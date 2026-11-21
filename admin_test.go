package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/eventstore"
	"fiatjaf.com/nostr/eventstore/lmdb"
	"fiatjaf.com/nostr/eventstore/slicestore"
	"fiatjaf.com/nostr/khatru"
)

func newModerationTestRelay(t *testing.T) (*khatru.Relay, *slicestore.SliceStore, *moderation) {
	t.Helper()
	store := &slicestore.SliceStore{}
	if err := store.Init(); err != nil {
		t.Fatalf("store init: %v", err)
	}
	relay, _, m := wireRelayWithModeration(t, store, []string{testRelayURL})
	return relay, store, m
}

func isStored(store eventstore.Store, id nostr.ID) bool {
	return len(collect(store.QueryEvents(nostr.Filter{IDs: []nostr.ID{id}}, 1))) > 0
}

func mustSucceed(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func wantRejected(t *testing.T, relay *khatru.Relay, ctx context.Context, event nostr.Event, wantMsg string) {
	t.Helper()
	reject, msg := relay.OnEvent(ctx, event)
	if !reject || msg != wantMsg {
		t.Errorf("OnEvent(kind %d) = %v %q, want rejected with %q", event.Kind, reject, msg, wantMsg)
	}
}

func wantAccepted(t *testing.T, relay *khatru.Relay, ctx context.Context, event nostr.Event) {
	t.Helper()
	if reject, msg := relay.OnEvent(ctx, event); reject {
		t.Errorf("OnEvent(kind %d) rejected: %q", event.Kind, msg)
	}
}

func TestBannedPubKeyIsPurgedAndRefused(t *testing.T) {
	relay, store, m := newModerationTestRelay(t)
	sk := nostr.Generate()
	pk := nostr.GetPublicKey(sk)

	note := sign(t, sk, 1, nil)
	profile := sign(t, sk, 0, nil)
	deletion := sign(t, sk, nostr.KindDeletion, nostr.Tags{{"e", note.ID.Hex()}})
	other := sign(t, nostr.Generate(), 1, nil)
	save(t, store, note, profile, deletion, other)

	mustSucceed(t, m.banPubKey(store, pk, "spam"))

	if isStored(store, note.ID) || isStored(store, profile.ID) {
		t.Error("the banned pubkey's events are still stored")
	}
	if !isStored(store, deletion.ID) {
		t.Error("the banned pubkey's deletion request was purged")
	}
	if !isStored(store, other.ID) {
		t.Error("another pubkey's event was purged")
	}

	ctx := context.Background()
	wantRejected(t, relay, ctx, sign(t, sk, 1, nostr.Tags{{"t", "after"}}), "blocked: this pubkey is banned from this relay")
	wantAccepted(t, relay, ctx, sign(t, sk, nostr.KindDeletion, nostr.Tags{{"e", other.ID.Hex()}}))
	wantAccepted(t, relay, ctx, sign(t, sk, kindVanish, nostr.Tags{{"relay", vanishAllRelays}}))

	mustSucceed(t, m.unbanPubKey(pk))
	wantAccepted(t, relay, ctx, sign(t, sk, 1, nostr.Tags{{"t", "unbanned"}}))
}

// A full page of tombstones must not stop the purge before the events under it.
func TestPurgeAuthorStepsPastTombstones(t *testing.T) {
	memory := &slicestore.SliceStore{}
	disk := &lmdb.LMDBBackend{Path: t.TempDir()}
	for name, store := range map[string]eventstore.Store{"slicestore": memory, "lmdb": disk} {
		t.Run(name, func(t *testing.T) {
			mustSucceed(t, store.Init())
			t.Cleanup(store.Close)
			sk := nostr.Generate()
			base := nostr.Now() - 10_000

			var notes []nostr.Event
			for i := range 3 {
				notes = append(notes, signAt(t, sk, 1, nil, base+nostr.Timestamp(i)))
			}
			for i := range purgeBatchSize + 1 {
				notes = append(notes, signAt(t, sk, nostr.KindDeletion, nil, base+1000+nostr.Timestamp(i)))
			}
			for _, evt := range notes {
				mustSucceed(t, store.SaveEvent(evt))
			}

			mustSucceed(t, purgeAuthor(store, nostr.GetPublicKey(sk)))

			for _, evt := range notes {
				if got, want := isStored(store, evt.ID), evt.Kind == nostr.KindDeletion; got != want {
					t.Errorf("kind %d at %d stored = %v, want %v", evt.Kind, evt.CreatedAt, got, want)
				}
			}
			// what the stats method reports
			if n, err := store.CountEvents(nostr.Filter{}); err != nil || n != purgeBatchSize+1 {
				t.Errorf("CountEvents = %d, %v, want %d", n, err, purgeBatchSize+1)
			}
		})
	}
}

func TestBannedEventIsDeletedAndRefused(t *testing.T) {
	relay, store, m := newModerationTestRelay(t)
	note := sign(t, nostr.Generate(), 1, nil)
	save(t, store, note)

	mustSucceed(t, m.banEvent(store, note.ID, "illegal"))
	if isStored(store, note.ID) {
		t.Error("the banned event is still stored")
	}
	wantRejected(t, relay, context.Background(), note, "blocked: this event is banned from this relay")

	mustSucceed(t, m.unbanEvent(note.ID))
	wantAccepted(t, relay, context.Background(), note)
}

func TestTombstonesCannotBeBannedOrRefused(t *testing.T) {
	_, store, m := newModerationTestRelay(t)
	deletion := sign(t, nostr.Generate(), nostr.KindDeletion, nil)
	save(t, store, deletion)

	if err := m.banEvent(store, deletion.ID, ""); !errors.Is(err, errBanTombstone) {
		t.Errorf("banning a deletion request: %v, want errBanTombstone", err)
	}
	if !isStored(store, deletion.ID) {
		t.Error("the deletion request was deleted")
	}
	for _, kind := range []nostr.Kind{nostr.KindDeletion, kindVanish} {
		if err := m.disallowKind(kind); !errors.Is(err, errRefuseTombstone) {
			t.Errorf("refusing kind %d: %v, want errRefuseTombstone", kind, err)
		}
	}
}

func TestBannedPubKeyCannotSendGiftWraps(t *testing.T) {
	relay, store, m := newModerationTestRelay(t)
	banned := nostr.GetPublicKey(nostr.Generate())
	mustSucceed(t, m.banPubKey(store, banned, ""))

	wrap := sign(t, nostr.Generate(), nostr.KindGiftWrap, nostr.Tags{{"p", nostr.GetPublicKey(nostr.Generate()).Hex()}})
	wantRejected(t, relay, khatru.ForceSetAuthed(context.Background(), banned), wrap, "blocked: this pubkey is banned from this relay")
	wantAccepted(t, relay, khatru.ForceSetAuthed(context.Background(), nostr.GetPublicKey(nostr.Generate())), wrap)
}

func TestDisallowedKindIsRefused(t *testing.T) {
	relay, _, m := newModerationTestRelay(t)
	sk := nostr.Generate()

	mustSucceed(t, m.disallowKind(1984))
	wantRejected(t, relay, context.Background(), sign(t, sk, 1984, nil), "blocked: kind 1984 is not accepted on this relay")
	wantAccepted(t, relay, context.Background(), sign(t, sk, 1, nil))

	mustSucceed(t, m.allowKind(1984))
	wantAccepted(t, relay, context.Background(), sign(t, sk, 1984, nil))
}

func TestBlockedIPIsCutOff(t *testing.T) {
	relay, _, m := newModerationTestRelay(t)
	server := httptest.NewServer(relay)
	t.Cleanup(server.Close)
	relayURL := "ws://" + strings.TrimPrefix(server.URL, "http://")
	const ip = "203.0.113.9"

	open := dialRelayFrom(t, relayURL, ip)
	open.readUntil("AUTH")
	mustSucceed(t, m.blockIP(net.ParseIP(ip), "flood"))

	if ok := open.publish(sign(t, nostr.Generate(), 1, nil)); ok.OK || !strings.HasPrefix(ok.Reason, "blocked:") {
		t.Errorf("publish from a blocked IP: %+v", ok)
	}
	if closed, _ := open.fetch("sub", nostr.Filter{Kinds: []nostr.Kind{1}}); closed == nil || !strings.HasPrefix(closed.Reason, "blocked:") {
		t.Errorf("request from a blocked IP: %+v", closed)
	}
	// khatru answers a refused COUNT with a NOTICE, then a count of zero
	open.send(&nostr.CountEnvelope{SubscriptionID: "count", Filter: nostr.Filter{Kinds: []nostr.Kind{1}}})
	got := open.readUntil("COUNT")
	if notice, ok := got[0].(*nostr.NoticeEnvelope); !ok || !strings.HasPrefix(string(*notice), "blocked:") {
		t.Errorf("count from a blocked IP: %s", labels(got))
	}

	conn, resp, err := dialFrom(relayURL, ip)
	if err == nil {
		conn.Close()
		t.Fatal("a blocked IP opened a new connection")
	}
	if resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("new connection from a blocked IP: %v", err)
	}

	dialRelayFrom(t, relayURL, "203.0.113.10").readUntil("AUTH")
}

func TestModerationSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), moderationStatePath)
	m, err := loadModeration(path)
	mustSucceed(t, err)
	store := &slicestore.SliceStore{}
	mustSucceed(t, store.Init())

	mustSucceed(t, m.banPubKey(store, nostr.GetPublicKey(nostr.Generate()), "spam"))
	mustSucceed(t, m.banEvent(store, sign(t, nostr.Generate(), 1, nil).ID, "illegal"))
	mustSucceed(t, m.blockIP(net.ParseIP("2001:db8::1"), "flood"))
	mustSucceed(t, m.disallowKind(1984))
	mustSucceed(t, m.setRelayName("Renamed"))

	restarted, err := loadModeration(path)
	mustSucceed(t, err)
	if got, want := restarted.snapshot(), m.snapshot(); !reflect.DeepEqual(got, want) {
		t.Errorf("after restart:\n got %+v\nwant %+v", got, want)
	}
}

func TestModerationKeepsNothingItCouldNotSave(t *testing.T) {
	m, err := loadModeration(filepath.Join(t.TempDir(), "missing", moderationStatePath))
	mustSucceed(t, err)

	if err := m.disallowKind(1984); err == nil {
		t.Fatal("saving into a missing directory succeeded")
	}
	if kinds := m.snapshot().DisallowedKinds; len(kinds) != 0 {
		t.Errorf("an unsaved decision is enforced: %v", kinds)
	}
}

// NIP-86 over HTTP

type managementServer struct {
	url   string
	relay *khatru.Relay
	store *slicestore.SliceStore
	admin nostr.SecretKey
}

func startManagementServer(t *testing.T) managementServer {
	t.Helper()
	relay, store, m := newModerationTestRelay(t)
	admin := nostr.Generate()
	attachAdmin(relay, store, m, []nostr.PubKey{nostr.GetPublicKey(admin)})
	server := httptest.NewServer(relay)
	t.Cleanup(server.Close)
	return managementServer{url: server.URL, relay: relay, store: store, admin: admin}
}

type managementReply struct {
	Result json.RawMessage `json:"result"`
	Error  string          `json:"error"`
}

func (s managementServer) call(t *testing.T, sk nostr.SecretKey, method string, params []any, edit func(*nostr.Event)) managementReply {
	t.Helper()
	body, err := json.Marshal(map[string]any{"method": method, "params": params})
	mustSucceed(t, err)
	hash := sha256.Sum256(body)

	auth := nostr.Event{
		Kind:      nostr.KindHTTPAuth,
		CreatedAt: nostr.Now(),
		Tags: nostr.Tags{
			{"u", s.url + "/"},
			{"method", "POST"},
			{"payload", nostr.HexEncodeToString(hash[:])},
		},
	}
	if edit != nil {
		edit(&auth)
	}
	mustSucceed(t, auth.Sign(sk))
	authJSON, err := json.Marshal(auth)
	mustSucceed(t, err)

	req, err := http.NewRequest(http.MethodPost, s.url+"/", bytes.NewReader(body))
	mustSucceed(t, err)
	req.Header.Set("Content-Type", "application/nostr+json+rpc")
	req.Header.Set("Authorization", "Nostr "+base64.StdEncoding.EncodeToString(authJSON))
	resp, err := http.DefaultClient.Do(req)
	mustSucceed(t, err)
	defer resp.Body.Close()

	var reply managementReply
	mustSucceed(t, json.NewDecoder(resp.Body).Decode(&reply))
	return reply
}

func TestManagementAPIRefusesNonAdmins(t *testing.T) {
	s := startManagementServer(t)
	target := nostr.GetPublicKey(nostr.Generate())

	reply := s.call(t, nostr.Generate(), "banpubkey", []any{target.Hex(), "x"}, nil)
	if !strings.Contains(reply.Error, "not an admin") {
		t.Errorf("non-admin call: %+v", reply)
	}
	reply = s.call(t, s.admin, "listbannedpubkeys", nil, nil)
	if reply.Error != "" || string(reply.Result) != "[]" {
		t.Errorf("a non-admin call banned someone: %+v", reply)
	}
}

func TestManagementAPIRequiresNIP98(t *testing.T) {
	s := startManagementServer(t)
	cases := map[string]func(*nostr.Event){
		"another kind":        func(e *nostr.Event) { e.Kind = 1 },
		"no method tag":       func(e *nostr.Event) { e.Tags = nostr.Tags{e.Tags[0], e.Tags[2]} },
		"another method":      func(e *nostr.Event) { e.Tags[1] = nostr.Tag{"method", "GET"} },
		"dated in the future": func(e *nostr.Event) { e.CreatedAt += 2 * httpAuthClockSkew },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			reply := s.call(t, s.admin, "stats", nil, edit)
			if !strings.HasPrefix(reply.Error, "unauthorized:") {
				t.Errorf("reply: %+v", reply)
			}
		})
	}
}

func TestManagementAPIModeratesTheRelay(t *testing.T) {
	s := startManagementServer(t)
	sk := nostr.Generate()
	note := sign(t, sk, 1, nil)
	save(t, s.store, note)

	if reply := s.call(t, s.admin, "banpubkey", []any{nostr.GetPublicKey(sk).Hex(), "spam"}, nil); reply.Error != "" {
		t.Fatalf("banpubkey: %s", reply.Error)
	}
	if isStored(s.store, note.ID) {
		t.Error("banpubkey left the pubkey's events")
	}

	var banned []struct{ PubKey, Reason string }
	mustSucceed(t, json.Unmarshal(s.call(t, s.admin, "listbannedpubkeys", nil, nil).Result, &banned))
	if len(banned) != 1 || banned[0].PubKey != nostr.GetPublicKey(sk).Hex() || banned[0].Reason != "spam" {
		t.Errorf("listbannedpubkeys: %+v", banned)
	}

	var stats struct {
		Result struct{ Events, Connections int }
	}
	mustSucceed(t, json.Unmarshal(s.call(t, s.admin, "stats", nil, nil).Result, &stats))
	if stats.Result.Events != 0 {
		t.Errorf("stats counts %d events, want 0", stats.Result.Events)
	}
}

func TestManagementAPIRenamesTheRelay(t *testing.T) {
	s := startManagementServer(t)
	if reply := s.call(t, s.admin, "changerelayname", []any{"Renamed"}, nil); reply.Error != "" {
		t.Fatalf("changerelayname: %s", reply.Error)
	}
	info := fetchRelayInfo(t, s.relay)
	if info["name"] != "Renamed" {
		t.Errorf("NIP-11 name = %v", info["name"])
	}
	if !slices.Contains(supportedNIPs(t, info), 86) {
		t.Error("NIP-86 is not advertised")
	}
}

func TestAdminPageIsServed(t *testing.T) {
	s := startManagementServer(t)

	resp, err := http.Get(s.url + "/admin")
	mustSucceed(t, err)
	defer resp.Body.Close()
	page, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK || !bytes.Contains(page, []byte("Sign in with extension")) {
		t.Fatalf("GET /admin: %d\n%s", resp.StatusCode, page)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("Content-Security-Policy = %q", csp)
	}

	for _, asset := range []string{"/admin/admin.js", "/admin/admin.css"} {
		resp, err := http.Get(s.url + asset)
		mustSucceed(t, err)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s: %d", asset, resp.StatusCode)
		}
	}
}

func TestAdminPageAbsentWithoutAdmins(t *testing.T) {
	relay, _, _ := newModerationTestRelay(t)
	server := httptest.NewServer(relay)
	t.Cleanup(server.Close)

	resp, err := http.Get(server.URL + "/admin/")
	mustSucceed(t, err)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /admin/ without ADMIN_PUBKEYS: %d, want 404", resp.StatusCode)
	}
}
