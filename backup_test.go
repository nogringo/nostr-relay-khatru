package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/eventstore"
	"fiatjaf.com/nostr/eventstore/lmdb"
	"fiatjaf.com/nostr/eventstore/slicestore"
)

func (s managementServer) backup(t *testing.T, sk nostr.SecretKey, edit func(*nostr.Event)) *http.Response {
	t.Helper()
	url := s.url + "/admin/backup"
	req, err := http.NewRequest(http.MethodPost, url, nil)
	mustSucceed(t, err)
	req.Header.Set("Authorization", httpAuth(t, sk, url, nil, edit))
	resp, err := http.DefaultClient.Do(req)
	mustSucceed(t, err)
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// backupByForm posts the auth the way the console does, in a form field.
func (s managementServer) backupByForm(t *testing.T, sk nostr.SecretKey, edit func(*nostr.Event)) *http.Response {
	t.Helper()
	url := s.url + "/admin/backup"
	resp, err := http.PostForm(url, neturl.Values{"authorization": {httpAuth(t, sk, url, nil, edit)}})
	mustSucceed(t, err)
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func readZipEntry(t *testing.T, archive *zip.Reader, name string) []byte {
	t.Helper()
	file, err := archive.Open(name)
	mustSucceed(t, err)
	defer file.Close()
	raw, err := io.ReadAll(file)
	mustSucceed(t, err)
	return raw
}

func TestBackupHoldsEveryEventAndTheModerationState(t *testing.T) {
	s := startManagementServer(t)
	recipient := nostr.GetPublicKey(nostr.Generate())
	events := []nostr.Event{
		sign(t, nostr.Generate(), 1, nil),
		sign(t, nostr.Generate(), 0, nil),
		sign(t, nostr.Generate(), nostr.KindGiftWrap, nostr.Tags{{"p", recipient.Hex()}}),
		sign(t, nostr.Generate(), nostr.KindDeletion, nostr.Tags{{"k", "1059"}}),
	}
	save(t, s.store, events...)
	if reply := s.call(t, s.admin, "disallowkind", []any{1984}, nil); reply.Error != "" {
		t.Fatalf("disallowkind: %s", reply.Error)
	}
	if reply := s.call(t, s.admin, "changerelayname", []any{"Backed up"}, nil); reply.Error != "" {
		t.Fatalf("changerelayname: %s", reply.Error)
	}

	resp := s.backup(t, s.admin, nil)
	body, err := io.ReadAll(resp.Body)
	mustSucceed(t, err)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /admin/backup: %d %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Content-Disposition"); !strings.HasPrefix(got, `attachment; filename="nostr-relay-backup-`) {
		t.Errorf("Content-Disposition = %q", got)
	}
	archive, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	mustSucceed(t, err)

	var got []nostr.ID
	lines := bufio.NewScanner(bytes.NewReader(readZipEntry(t, archive, backupEventsFile)))
	for lines.Scan() {
		var event nostr.Event
		mustSucceed(t, json.Unmarshal(lines.Bytes(), &event))
		if !event.VerifySignature() {
			t.Errorf("event %s does not verify", event.ID)
		}
		got = append(got, event.ID)
	}
	if len(got) != len(events) {
		t.Errorf("the backup holds %d events, want %d", len(got), len(events))
	}
	for _, event := range events {
		if !hasID(got, event.ID) {
			t.Errorf("kind %d is missing from the backup", event.Kind)
		}
	}

	// restoring is putting the file back next to the database
	path := filepath.Join(t.TempDir(), moderationStatePath)
	mustSucceed(t, os.WriteFile(path, readZipEntry(t, archive, moderationStatePath), 0o600))
	restored, err := loadModeration(path)
	mustSucceed(t, err)
	if got, want := restored.snapshot(), s.moderation.snapshot(); !reflect.DeepEqual(got, want) {
		t.Errorf("restored admin.json:\n got %+v\nwant %+v", got, want)
	}
}

func TestBackupAcceptsTheAuthInAFormField(t *testing.T) {
	s := startManagementServer(t)
	event := sign(t, nostr.Generate(), 1, nil)
	save(t, s.store, event)

	resp := s.backupByForm(t, s.admin, nil)
	body, err := io.ReadAll(resp.Body)
	mustSucceed(t, err)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /admin/backup: %d %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Content-Disposition"); !strings.HasPrefix(got, "attachment;") {
		t.Errorf("Content-Disposition = %q, the browser would not save it as a download", got)
	}
	archive, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	mustSucceed(t, err)
	if got, want := strings.TrimSpace(string(readZipEntry(t, archive, backupEventsFile))), event.String(); got != want {
		t.Errorf("events.jsonl = %s, want %s", got, want)
	}
}

func TestBackupRequiresAnAdminSignature(t *testing.T) {
	s := startManagementServer(t)
	save(t, s.store, sign(t, nostr.Generate(), 1, nil))

	cases := map[string]struct {
		sk   nostr.SecretKey
		edit func(*nostr.Event)
	}{
		"another key":    {nostr.Generate(), nil},
		"a NIP-86 auth":  {s.admin, func(e *nostr.Event) { e.Tags[0] = nostr.Tag{"u", s.url + "/"} }},
		"another host":   {s.admin, func(e *nostr.Event) { e.Tags[0] = nostr.Tag{"u", "https://elsewhere.example/admin/backup"} }},
		"no u tag":       {s.admin, func(e *nostr.Event) { e.Tags = e.Tags[1:] }},
		"too old":        {s.admin, func(e *nostr.Event) { e.CreatedAt -= 2 * httpAuthClockSkew }},
		"another kind":   {s.admin, func(e *nostr.Event) { e.Kind = 1 }},
		"another method": {s.admin, func(e *nostr.Event) { e.Tags[1] = nostr.Tag{"method", "GET"} }},
	}
	senders := map[string]func(*testing.T, nostr.SecretKey, func(*nostr.Event)) *http.Response{
		"header": s.backup,
		"form":   s.backupByForm,
	}
	for via, send := range senders {
		for name, c := range cases {
			t.Run(via+"/"+name, func(t *testing.T) {
				resp := send(t, c.sk, c.edit)
				body, _ := io.ReadAll(resp.Body)
				if resp.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(string(body), "unauthorized:") {
					t.Errorf("POST /admin/backup: %d %s", resp.StatusCode, body)
				}
			})
		}
	}

	t.Run("oversized form", func(t *testing.T) {
		url := s.url + "/admin/backup"
		auth := httpAuth(t, s.admin, url, nil, nil)
		resp, err := http.PostForm(url, neturl.Values{"authorization": {auth}, "padding": {strings.Repeat("x", maxBackupFormSize)}})
		mustSucceed(t, err)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("POST /admin/backup: %d", resp.StatusCode)
		}
	})

	t.Run("no signature", func(t *testing.T) {
		resp, err := http.Post(s.url+"/admin/backup", "", nil)
		mustSucceed(t, err)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("POST /admin/backup: %d", resp.StatusCode)
		}
	})
}

// Pages must step past seconds holding more events than a page, and reach the
// events at created_at 0, which Until cannot name.
func TestEachStoredEventPagesPastTies(t *testing.T) {
	memory := &slicestore.SliceStore{}
	disk := &lmdb.LMDBBackend{Path: t.TempDir()}
	for name, store := range map[string]eventstore.Store{"slicestore": memory, "lmdb": disk} {
		t.Run(name, func(t *testing.T) {
			mustSucceed(t, store.Init())
			t.Cleanup(store.Close)
			sk := nostr.Generate()
			base := nostr.Now()

			want := make(map[nostr.ID]bool)
			for at, count := range map[nostr.Timestamp]int{base + 1: 2, base: 7, 5: 1, 1: 2, 0: 3} {
				for range count {
					event := signAt(t, sk, 1, nostr.Tags{{"n", nostr.Generate().Hex()}}, at)
					mustSucceed(t, store.SaveEvent(event))
					want[event.ID] = true
				}
			}

			seen := make(map[nostr.ID]int)
			last := nostr.Timestamp(base + 1)
			mustSucceed(t, eachStoredEvent(store, 3, func(event nostr.Event) error {
				seen[event.ID]++
				if event.CreatedAt > last {
					t.Errorf("an event at %d came after one at %d", event.CreatedAt, last)
				}
				last = event.CreatedAt
				return nil
			}))

			if len(seen) != len(want) {
				t.Errorf("got %d distinct events, want %d", len(seen), len(want))
			}
			for id, n := range seen {
				if !want[id] || n != 1 {
					t.Errorf("event %s seen %d times, stored %v", id, n, want[id])
				}
			}
		})
	}
}
