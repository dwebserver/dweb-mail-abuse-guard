package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/dwebserver/dweb-mail-abuse-guard/internal/event"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/policy"
	bolt "go.etcd.io/bbolt"
)

func openTestStore(t *testing.T) *Bolt {
	t.Helper()
	database, err := Open(filepath.Join(t.TempDir(), "state.db"), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

func TestEventsAndPruning(t *testing.T) {
	database := openTestStore(t)
	base := time.Now().UTC().Add(-2 * time.Hour)
	invalid := event.Event{}
	if err := database.AppendEvent(invalid); err == nil {
		t.Fatal("invalid event accepted")
	}
	for index := 0; index < 3; index++ {
		item := event.Event{Time: base.Add(time.Duration(index) * time.Hour), Kind: event.Submission, Mailbox: "a@example.com", RecipientCount: index + 1, Source: "exim"}
		if err := database.AppendEvent(item); err != nil {
			t.Fatal(err)
		}
	}
	recent, err := database.RecentEvents(base.Add(30 * time.Minute))
	if err != nil || len(recent) != 2 {
		t.Fatalf("recent=%d err=%v", len(recent), err)
	}
	if err := database.PruneEvents(base.Add(90 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	recent, err = database.RecentEvents(base)
	if err != nil || len(recent) != 1 {
		t.Fatalf("after prune=%d err=%v", len(recent), err)
	}
}

func TestIncidentLifecycleAndEscalation(t *testing.T) {
	database := openTestStore(t)
	now := time.Now().UTC()
	warning := Incident{ID: "one", Mailbox: "a@example.com", Status: IncidentAudit, Decision: policy.Decision{Severity: policy.Warning}, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}
	created, ok, err := database.CreateIncident(warning)
	if err != nil || !ok || created.ID != "one" {
		t.Fatal(created, ok, err)
	}
	duplicate := warning
	duplicate.ID = "two"
	duplicate.CreatedAt = now.Add(time.Minute)
	created, ok, err = database.CreateIncident(duplicate)
	if err != nil || ok || created.ID != "one" {
		t.Fatal(created, ok, err)
	}

	escalated := duplicate
	escalated.ID = "three"
	escalated.Decision.Severity = policy.Contain
	created, ok, err = database.CreateIncident(escalated)
	if err != nil || !ok || created.ID != "three" {
		t.Fatal(created, ok, err)
	}
	if err := database.UpdateIncidentStatus("three", IncidentContained, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := database.UpdateIncidentStatus("missing", IncidentReleased, now); err == nil {
		t.Fatal("missing incident updated")
	}
	if err := database.UpdateIncidentStatus("three", IncidentReleased, now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}

	afterRelease := escalated
	afterRelease.ID = "four"
	afterRelease.CreatedAt = now.Add(4 * time.Minute)
	if _, ok, err := database.CreateIncident(afterRelease); err != nil || !ok {
		t.Fatal(ok, err)
	}
	incidents, err := database.Incidents()
	if err != nil || len(incidents) != 3 {
		t.Fatalf("incidents=%d err=%v", len(incidents), err)
	}

	if _, ok, err := database.CreateIncident(Incident{}); err == nil || ok {
		t.Fatal("invalid incident accepted")
	}
}

func TestCursor(t *testing.T) {
	database := openTestStore(t)
	if _, found, err := database.GetCursor("missing"); err != nil || found {
		t.Fatal(found, err)
	}
	if err := database.PutCursor(Cursor{}); err == nil {
		t.Fatal("invalid cursor accepted")
	}
	want := Cursor{Path: "/var/log/mail", Offset: 42, PrefixHash: "abc", UpdatedAt: time.Now().UTC()}
	if err := database.PutCursor(want); err != nil {
		t.Fatal(err)
	}
	got, found, err := database.GetCursor(want.Path)
	if err != nil || !found || got.Offset != want.Offset || got.PrefixHash != want.PrefixHash {
		t.Fatal(got, found, err)
	}
}

func TestOpenReadOnlyAndHelpers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	database, err := Open(path, false)
	if err != nil {
		t.Fatal(err)
	}
	_ = database.Close()
	readOnly, err := Open(path, true)
	if err != nil {
		t.Fatal(err)
	}
	_ = readOnly.Close()
	if IsNotFound(nil) {
		t.Fatal("nil is not not-found")
	}
	if severityRank(policy.Contain) != 2 || severityRank(policy.Warning) != 1 || severityRank(policy.None) != 0 {
		t.Fatal("severity ranks")
	}
	if _, err := Open(t.TempDir(), false); err == nil {
		t.Fatal("directory opened as database")
	}
}

func TestCorruptRecordsAreReported(t *testing.T) {
	database := openTestStore(t)
	if err := database.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(eventsBucket).Put(eventKey(time.Now(), 1), []byte("{")); err != nil {
			return err
		}
		if err := tx.Bucket(incidentsBucket).Put([]byte("bad"), []byte("{")); err != nil {
			return err
		}
		return tx.Bucket(cursorsBucket).Put([]byte("bad"), []byte("{"))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.RecentEvents(time.Now().Add(-time.Minute)); err == nil {
		t.Fatal("corrupt event hidden")
	}
	if _, err := database.Incidents(); err == nil {
		t.Fatal("corrupt incident hidden")
	}
	if _, _, err := database.GetCursor("bad"); err == nil {
		t.Fatal("corrupt cursor hidden")
	}
}
