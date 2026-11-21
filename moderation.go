package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/eventstore"
	"fiatjaf.com/nostr/khatru"
	"fiatjaf.com/nostr/nip11"
	"fiatjaf.com/nostr/nip86"
)

// where the admin's decisions are kept, next to the event database
const moderationStatePath = "admin.json"

// how many events one purge query pulls before deleting them
const purgeBatchSize = 500

var (
	errBanTombstone    = errors.New("deletion and vanish requests cannot be banned: they keep deleted events from coming back")
	errRefuseTombstone = errors.New("kinds 5 and 62 are always accepted: they keep deleted events from coming back")
)

// moderation holds what the admin decided: who and what this relay refuses, and
// the NIP-11 fields they edited. It is enforced whether or not the admin
// interface is enabled, so removing ADMIN_PUBKEYS never lifts a ban.
type moderation struct {
	path  string
	mu    sync.RWMutex
	state moderationState
}

type moderationState struct {
	bannedPubKeys   map[nostr.PubKey]string
	bannedEvents    map[nostr.ID]string
	blockedIPs      map[string]string
	disallowedKinds map[nostr.Kind]bool

	relayName        *string
	relayDescription *string
	relayIcon        *string
}

type moderationFile struct {
	BannedPubKeys    []nip86.PubKeyReason `json:"banned_pubkeys"`
	BannedEvents     []nip86.IDReason     `json:"banned_events"`
	BlockedIPs       []nip86.IPReason     `json:"blocked_ips"`
	DisallowedKinds  []nostr.Kind         `json:"disallowed_kinds"`
	RelayName        *string              `json:"relay_name,omitempty"`
	RelayDescription *string              `json:"relay_description,omitempty"`
	RelayIcon        *string              `json:"relay_icon,omitempty"`
}

func loadModeration(path string) (*moderation, error) {
	m := &moderation{path: path, state: moderationFile{}.state()}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	var file moderationFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	m.state = file.state()
	return m, nil
}

// attachModeration enforces the admin's decisions. Must run after the hooks it
// wraps are set: limitConnections replaces RejectConnection.
func attachModeration(relay *khatru.Relay, path string) (*moderation, error) {
	m, err := loadModeration(path)
	if err != nil {
		return nil, err
	}

	prevReject := relay.RejectConnection
	relay.RejectConnection = func(r *http.Request) bool {
		return m.ipBlocked(clientIP(r)) || (prevReject != nil && prevReject(r))
	}

	refuseBlockedIPs := func(next func(context.Context, nostr.Filter) (bool, string)) func(context.Context, nostr.Filter) (bool, string) {
		return func(ctx context.Context, filter nostr.Filter) (reject bool, msg string) {
			if m.ipBlocked(clientIP(khatru.GetRequest(ctx))) {
				return true, "blocked: your IP address is blocked from this relay"
			}
			if next != nil {
				return next(ctx, filter)
			}
			return false, ""
		}
	}
	relay.OnRequest = refuseBlockedIPs(relay.OnRequest)
	relay.OnCount = refuseBlockedIPs(relay.OnCount)

	prevOnEvent := relay.OnEvent
	relay.OnEvent = func(ctx context.Context, event nostr.Event) (reject bool, msg string) {
		if prevOnEvent != nil {
			if reject, msg := prevOnEvent(ctx, event); reject {
				return reject, msg
			}
		}
		return m.rejectEvent(ctx, event)
	}

	prevInfo := relay.OverwriteRelayInformation
	relay.OverwriteRelayInformation = func(ctx context.Context, r *http.Request, info nip11.RelayInformationDocument) nip11.RelayInformationDocument {
		if prevInfo != nil {
			info = prevInfo(ctx, r, info)
		}
		return m.applyRelayInfo(info)
	}

	return m, nil
}

func (m *moderation) rejectEvent(ctx context.Context, event nostr.Event) (reject bool, msg string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := &m.state

	if s.ipBlocked(clientIP(khatru.GetRequest(ctx))) {
		return true, "blocked: your IP address is blocked from this relay"
	}
	// whoever sends them, users can always take their data back
	if isTombstone(event.Kind) {
		return false, ""
	}
	if _, ok := s.bannedEvents[event.ID]; ok {
		return true, "blocked: this event is banned from this relay"
	}
	if _, ok := s.bannedPubKeys[event.PubKey]; ok {
		return true, "blocked: this pubkey is banned from this relay"
	}
	// a gift wrap is signed by a throw-away key, the connection is what names its sender
	if event.Kind == nostr.KindGiftWrap {
		for _, pk := range khatru.GetAllAuthed(ctx) {
			if _, ok := s.bannedPubKeys[pk]; ok {
				return true, "blocked: this pubkey is banned from this relay"
			}
		}
	}
	if s.disallowedKinds[event.Kind] {
		return true, fmt.Sprintf("blocked: kind %d is not accepted on this relay", event.Kind)
	}
	return false, ""
}

func (m *moderation) ipBlocked(ip string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state.ipBlocked(ip)
}

func (s *moderationState) ipBlocked(ip string) bool {
	if ip == "" || len(s.blockedIPs) == 0 {
		return false
	}
	_, ok := s.blockedIPs[normalizeIP(ip)]
	return ok
}

func (m *moderation) applyRelayInfo(info nip11.RelayInformationDocument) nip11.RelayInformationDocument {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.state.relayName != nil {
		info.Name = *m.state.relayName
	}
	if m.state.relayDescription != nil {
		info.Description = *m.state.relayDescription
	}
	if m.state.relayIcon != nil {
		info.Icon = *m.state.relayIcon
	}
	return info
}

// update applies change to a copy and keeps it only once it is on disk, so a
// failed write never leaves a decision that would vanish on restart.
func (m *moderation) update(change func(s *moderationState) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	next := m.state.clone()
	if err := change(&next); err != nil {
		return err
	}
	if err := writeJSONAtomic(m.path, next.file()); err != nil {
		return err
	}
	m.state = next
	return nil
}

func (m *moderation) snapshot() moderationFile {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state.file()
}

func (m *moderation) banPubKey(store eventstore.Store, pk nostr.PubKey, reason string) error {
	err := m.update(func(s *moderationState) error {
		s.bannedPubKeys[pk] = reason
		return nil
	})
	if err != nil {
		return err
	}
	return purgeAuthor(store, pk)
}

func (m *moderation) unbanPubKey(pk nostr.PubKey) error {
	return m.update(func(s *moderationState) error {
		delete(s.bannedPubKeys, pk)
		return nil
	})
}

func (m *moderation) banEvent(store eventstore.Store, id nostr.ID, reason string) error {
	for event := range store.QueryEvents(nostr.Filter{IDs: []nostr.ID{id}}, 1) {
		if isTombstone(event.Kind) {
			return errBanTombstone
		}
	}
	err := m.update(func(s *moderationState) error {
		s.bannedEvents[id] = reason
		return nil
	})
	if err != nil {
		return err
	}
	return store.DeleteEvent(id)
}

func (m *moderation) unbanEvent(id nostr.ID) error {
	return m.update(func(s *moderationState) error {
		delete(s.bannedEvents, id)
		return nil
	})
}

func (m *moderation) blockIP(ip net.IP, reason string) error {
	return m.update(func(s *moderationState) error {
		s.blockedIPs[ip.String()] = reason
		return nil
	})
}

func (m *moderation) unblockIP(ip net.IP) error {
	return m.update(func(s *moderationState) error {
		delete(s.blockedIPs, ip.String())
		return nil
	})
}

func (m *moderation) disallowKind(kind nostr.Kind) error {
	if isTombstone(kind) {
		return errRefuseTombstone
	}
	return m.update(func(s *moderationState) error {
		s.disallowedKinds[kind] = true
		return nil
	})
}

func (m *moderation) allowKind(kind nostr.Kind) error {
	return m.update(func(s *moderationState) error {
		delete(s.disallowedKinds, kind)
		return nil
	})
}

func (m *moderation) setRelayName(name string) error {
	return m.update(func(s *moderationState) error {
		s.relayName = &name
		return nil
	})
}

func (m *moderation) setRelayDescription(description string) error {
	return m.update(func(s *moderationState) error {
		s.relayDescription = &description
		return nil
	})
}

func (m *moderation) setRelayIcon(icon string) error {
	return m.update(func(s *moderationState) error {
		s.relayIcon = &icon
		return nil
	})
}

// isTombstone tells the events that make a deletion final. Moderation never
// removes or refuses them.
func isTombstone(kind nostr.Kind) bool {
	return kind == nostr.KindDeletion || kind == kindVanish
}

// purgeAuthor deletes everything a pubkey published, its tombstones aside.
func purgeAuthor(store eventstore.Store, author nostr.PubKey) error {
	filter := nostr.Filter{Authors: []nostr.PubKey{author}}
	for {
		// The iterator must be drained before deleting: lmdb holds a read
		// transaction for the whole range while DeleteEvent needs a write one.
		var ids []nostr.ID
		seen := 0
		oldest := nostr.Timestamp(0)
		for event := range store.QueryEvents(filter, purgeBatchSize) {
			seen++
			oldest = event.CreatedAt
			if !isTombstone(event.Kind) {
				ids = append(ids, event.ID)
			}
		}

		if len(ids) == 0 {
			// a page of tombstones only: step past it, Until 0 would mean no bound
			if seen < purgeBatchSize || oldest <= 1 {
				return nil
			}
			filter.Until = oldest - 1
			continue
		}

		for _, id := range ids {
			if err := store.DeleteEvent(id); err != nil {
				return err
			}
		}
	}
}

func normalizeIP(raw string) string {
	if ip := net.ParseIP(strings.TrimSpace(raw)); ip != nil {
		return ip.String()
	}
	return raw
}

func (f moderationFile) state() moderationState {
	s := moderationState{
		bannedPubKeys:    make(map[nostr.PubKey]string, len(f.BannedPubKeys)),
		bannedEvents:     make(map[nostr.ID]string, len(f.BannedEvents)),
		blockedIPs:       make(map[string]string, len(f.BlockedIPs)),
		disallowedKinds:  make(map[nostr.Kind]bool, len(f.DisallowedKinds)),
		relayName:        f.RelayName,
		relayDescription: f.RelayDescription,
		relayIcon:        f.RelayIcon,
	}
	for _, entry := range f.BannedPubKeys {
		s.bannedPubKeys[entry.PubKey] = entry.Reason
	}
	for _, entry := range f.BannedEvents {
		s.bannedEvents[entry.ID] = entry.Reason
	}
	for _, entry := range f.BlockedIPs {
		s.blockedIPs[normalizeIP(entry.IP)] = entry.Reason
	}
	for _, kind := range f.DisallowedKinds {
		s.disallowedKinds[kind] = true
	}
	return s
}

func (s moderationState) file() moderationFile {
	f := moderationFile{
		BannedPubKeys:    make([]nip86.PubKeyReason, 0, len(s.bannedPubKeys)),
		BannedEvents:     make([]nip86.IDReason, 0, len(s.bannedEvents)),
		BlockedIPs:       make([]nip86.IPReason, 0, len(s.blockedIPs)),
		DisallowedKinds:  slices.Sorted(maps.Keys(s.disallowedKinds)),
		RelayName:        s.relayName,
		RelayDescription: s.relayDescription,
		RelayIcon:        s.relayIcon,
	}
	if f.DisallowedKinds == nil {
		f.DisallowedKinds = []nostr.Kind{}
	}
	for pk, reason := range s.bannedPubKeys {
		f.BannedPubKeys = append(f.BannedPubKeys, nip86.PubKeyReason{PubKey: pk, Reason: reason})
	}
	slices.SortFunc(f.BannedPubKeys, func(a, b nip86.PubKeyReason) int { return strings.Compare(a.PubKey.Hex(), b.PubKey.Hex()) })
	for id, reason := range s.bannedEvents {
		f.BannedEvents = append(f.BannedEvents, nip86.IDReason{ID: id, Reason: reason})
	}
	slices.SortFunc(f.BannedEvents, func(a, b nip86.IDReason) int { return strings.Compare(a.ID.Hex(), b.ID.Hex()) })
	for ip, reason := range s.blockedIPs {
		f.BlockedIPs = append(f.BlockedIPs, nip86.IPReason{IP: ip, Reason: reason})
	}
	slices.SortFunc(f.BlockedIPs, func(a, b nip86.IPReason) int { return strings.Compare(a.IP, b.IP) })
	return f
}

func (s moderationState) clone() moderationState {
	s.bannedPubKeys = maps.Clone(s.bannedPubKeys)
	s.bannedEvents = maps.Clone(s.bannedEvents)
	s.blockedIPs = maps.Clone(s.blockedIPs)
	s.disallowedKinds = maps.Clone(s.disallowedKinds)
	return s
}

func writeJSONAtomic(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
