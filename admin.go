package main

import (
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/eventstore"
	"fiatjaf.com/nostr/khatru"
	"fiatjaf.com/nostr/nip86"
)

//go:embed admin
var adminFiles embed.FS

// NIP-98: "The created_at timestamp MUST be within a reasonable time window"
const httpAuthClockSkew = 60

var startedAt = time.Now()

func adminPubKeysFromEnv() []nostr.PubKey {
	var admins []nostr.PubKey
	for _, raw := range splitCommaSeparated(os.Getenv("ADMIN_PUBKEYS")) {
		pk, err := parsePubKey(raw)
		if err != nil {
			log.Printf("ignoring invalid ADMIN_PUBKEYS entry %q: %v", raw, err)
			continue
		}
		admins = append(admins, pk)
	}
	return admins
}

// attachAdmin serves the NIP-86 management API to these pubkeys only, and the
// web interface that drives it on /admin/.
func attachAdmin(relay *khatru.Relay, store eventstore.Store, m *moderation, admins []nostr.PubKey) {
	relay.Info.AddSupportedNIP("86")

	api := &relay.ManagementAPI
	api.OnAPICall = func(ctx context.Context, _ nip86.MethodParams) (reject bool, msg string) {
		caller, _ := khatru.GetAuthed(ctx)
		if !slices.Contains(admins, caller) {
			return true, "unauthorized: this pubkey is not an admin of this relay"
		}
		if _, err := checkHTTPAuth(khatru.GetRequest(ctx)); err != nil {
			return true, "unauthorized: " + err.Error()
		}
		return false, ""
	}

	api.BanPubKey = func(_ context.Context, pk nostr.PubKey, reason string) error {
		return m.banPubKey(store, pk, reason)
	}
	api.UnbanPubKey = func(_ context.Context, pk nostr.PubKey, _ string) error {
		return m.unbanPubKey(pk)
	}
	api.ListBannedPubKeys = func(context.Context) ([]nip86.PubKeyReason, error) {
		return m.snapshot().BannedPubKeys, nil
	}

	api.BanEvent = func(_ context.Context, id nostr.ID, reason string) error {
		return m.banEvent(store, id, reason)
	}
	// NIP-86: allowevent "Should automatically remove the event from the ban list."
	api.AllowEvent = func(_ context.Context, id nostr.ID, _ string) error {
		return m.unbanEvent(id)
	}
	api.ListBannedEvents = func(context.Context) ([]nip86.IDReason, error) {
		return m.snapshot().BannedEvents, nil
	}

	api.BlockIP = func(_ context.Context, ip net.IP, reason string) error {
		return m.blockIP(ip, reason)
	}
	api.UnblockIP = func(_ context.Context, ip net.IP, _ string) error {
		return m.unblockIP(ip)
	}
	api.ListBlockedIPs = func(context.Context) ([]nip86.IPReason, error) {
		return m.snapshot().BlockedIPs, nil
	}

	api.DisallowKind = func(_ context.Context, kind nostr.Kind) error {
		return m.disallowKind(kind)
	}
	api.AllowKind = func(_ context.Context, kind nostr.Kind) error {
		return m.allowKind(kind)
	}
	api.ListDisallowedKinds = func(context.Context) ([]nostr.Kind, error) {
		return m.snapshot().DisallowedKinds, nil
	}

	api.ChangeRelayName = func(_ context.Context, name string) error {
		return m.setRelayName(name)
	}
	api.ChangeRelayDescription = func(_ context.Context, description string) error {
		return m.setRelayDescription(description)
	}
	api.ChangeRelayIcon = func(_ context.Context, icon string) error {
		return m.setRelayIcon(icon)
	}

	// khatru wraps this in its own response, so it reaches the client as result.result
	api.Stats = func(context.Context) (nip86.Response, error) {
		events, err := store.CountEvents(nostr.Filter{})
		if err != nil {
			return nip86.Response{}, err
		}
		connections, subscriptions := relay.Stats()
		return nip86.Response{Result: map[string]any{
			"events":        events,
			"connections":   connections,
			"subscriptions": subscriptions,
			"started_at":    startedAt.Unix(),
			"version":       version(),
		}}, nil
	}

	ui, err := fs.Sub(adminFiles, "admin")
	if err != nil {
		panic(err)
	}
	relay.Router().Handle("GET /admin/", withAdminHeaders(http.StripPrefix("/admin/", http.FileServerFS(ui))))
	relay.Router().Handle("POST /admin/backup", serveBackup(store, m, admins))

	log.Printf("admin interface enabled on /admin/ for %d pubkey(s)", len(admins))
}

// checkHTTPAuth covers the NIP-98 rules khatru leaves out: it checks the
// signature, the u and payload tags and that the event is not too old.
func checkHTTPAuth(r *http.Request) (nostr.Event, error) {
	var evt nostr.Event
	if r == nil {
		return evt, errors.New("missing request")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(r.Header.Get("Authorization"), "Nostr "))
	if err != nil {
		return evt, errors.New("invalid base64 auth")
	}
	if err := json.Unmarshal(raw, &evt); err != nil {
		return evt, errors.New("invalid auth event json")
	}
	if evt.Kind != nostr.KindHTTPAuth {
		return evt, errors.New("the auth event must be a kind 27235")
	}
	if method := evt.Tags.Find("method"); method == nil || method[1] != http.MethodPost {
		return evt, errors.New(`the auth event must carry a "method" tag of POST`)
	}
	if evt.CreatedAt > nostr.Now()+httpAuthClockSkew {
		return evt, errors.New("the auth event is dated in the future")
	}
	return evt, nil
}

// checkAdminHTTPAuth is the whole NIP-98 check, for the routes khatru does not
// serve itself.
func checkAdminHTTPAuth(r *http.Request, admins []nostr.PubKey) error {
	evt, err := checkHTTPAuth(r)
	if err != nil {
		return err
	}
	if !evt.VerifySignature() {
		return errors.New("invalid auth event signature")
	}
	if evt.CreatedAt < nostr.Now()-httpAuthClockSkew {
		return errors.New("auth event is too old")
	}
	if !isRequestURL(evt.Tags.Find("u"), r) {
		return errors.New(`the "u" tag must be the URL of this request`)
	}
	if !slices.Contains(admins, evt.PubKey) {
		return errors.New("this pubkey is not an admin of this relay")
	}
	return nil
}

// isRequestURL leaves the scheme out: behind the TLS proxy the relay cannot see it.
func isRequestURL(tag nostr.Tag, r *http.Request) bool {
	if tag == nil {
		return false
	}
	u, err := url.Parse(tag[1])
	if err != nil {
		return false
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	return strings.EqualFold(u.Host, host) && u.Path == r.URL.Path && u.RawQuery == r.URL.RawQuery
}

func withAdminHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// NIP-07 extensions inject their provider script from their own scheme
		h.Set("Content-Security-Policy", "default-src 'self'; "+
			"script-src 'self' chrome-extension: moz-extension: safari-web-extension:; "+
			"img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-cache")
		next.ServeHTTP(w, r)
	})
}
