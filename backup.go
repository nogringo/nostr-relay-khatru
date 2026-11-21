package main

import (
	"archive/zip"
	"bufio"
	"cmp"
	"encoding/json"
	"io"
	"log"
	"maps"
	"net/http"
	"slices"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/eventstore"
)

// how many events one backup query pulls before writing them out
const backupPageSize = 1000

const backupEventsFile = "events.jsonl"

// a signed auth event is about 1 kB once form encoded
const maxBackupFormSize = 16 << 10

// serveBackup streams a zip of every stored event and of the moderation state,
// whose admin.json restores as is next to the database.
func serveBackup(store eventstore.Store, m *moderation, admins []nostr.PubKey) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("Authorization")
		if authorization == "" {
			// the console posts a form so the browser streams the zip to disk
			r.Body = http.MaxBytesReader(w, r.Body, maxBackupFormSize)
			authorization = r.PostFormValue("authorization")
		}
		if err := checkAdminHTTPAuth(r, authorization, admins); err != nil {
			http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}
		now := time.Now().UTC()
		h := w.Header()
		h.Set("Content-Type", "application/zip")
		h.Set("Content-Disposition", `attachment; filename="nostr-relay-backup-`+now.Format("20060102-150405")+`.zip"`)
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		if err := writeBackup(w, store, m, now); err != nil {
			log.Printf("backup interrupted: %v", err)
		}
	})
}

func writeBackup(w io.Writer, store eventstore.Store, m *moderation, now time.Time) error {
	archive := zip.NewWriter(w)
	entry := func(name string) (io.Writer, error) {
		return archive.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: now})
	}

	settings, err := entry(moderationStatePath)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(m.snapshot(), "", "  ")
	if err != nil {
		return err
	}
	if _, err := settings.Write(raw); err != nil {
		return err
	}

	file, err := entry(backupEventsFile)
	if err != nil {
		return err
	}
	lines := bufio.NewWriter(file)
	err = eachStoredEvent(store, backupPageSize, func(event nostr.Event) error {
		_, err := lines.WriteString(event.String() + "\n")
		return err
	})
	if err != nil {
		return err
	}
	if err := lines.Flush(); err != nil {
		return err
	}
	return archive.Close()
}

// eachStoredEvent calls fn on every stored event, newest first, one page at a
// time: a single query over the whole store would make lmdb decode all of it.
func eachStoredEvent(store eventstore.Store, pageSize int, fn func(nostr.Event) error) error {
	limit := pageSize
	until := nostr.Timestamp(0)
	// the events already written that a query bounded by until returns again
	written := make(map[nostr.ID]nostr.Timestamp)
	for {
		// collected first so the read transaction does not wait on the client
		page := slices.Collect(store.QueryEvents(nostr.Filter{Until: until}, limit))
		for _, event := range page {
			if _, ok := written[event.ID]; ok {
				continue
			}
			if err := fn(event); err != nil {
				return err
			}
			written[event.ID] = event.CreatedAt
		}
		if len(page) < limit {
			return nil
		}

		oldest := slices.MinFunc(page, func(a, b nostr.Event) int { return cmp.Compare(a.CreatedAt, b.CreatedAt) }).CreatedAt
		// Until 0 means no bound, so the events at 0 are reached with Until 1
		next := max(oldest, 1)
		if next == until {
			// a full page within one second: the only way past it is a bigger one
			limit *= 2
			continue
		}
		until, limit = next, pageSize
		maps.DeleteFunc(written, func(_ nostr.ID, at nostr.Timestamp) bool { return at > until })
	}
}
