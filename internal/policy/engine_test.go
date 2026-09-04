package policy

import (
	"testing"
	"time"

	"github.com/dwebserver/dweb-mail-abuse-guard/internal/config"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/event"
)

type policies struct{ value config.Policy }

func (p policies) PolicyFor(string) config.Policy { return p.value }

func testPolicy() config.Policy {
	return config.Policy{WarnRecipients5m: 3, ContainRecipients10m: 8, ContainRecipients5mWithIPs: 5, ContainSourceIPs1h: 2, ContainAuthFailures5m: 3, ProviderRejectMinRecipients5m: 2}
}

func submission(at time.Time, id, ip string, recipients int) event.Event {
	return event.Event{Time: at, Kind: event.Submission, Mailbox: "user@example.com", SourceIP: ip, MessageID: id, RecipientCount: recipients, Source: "exim"}
}

func TestEngineThresholds(t *testing.T) {
	base := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	engine := NewEngine(policies{testPolicy()}, nil)
	if got := engine.Evaluate(submission(base, "a", "192.0.2.1", 1)); got.Severity != None {
		t.Fatal(got)
	}
	if got := engine.Evaluate(submission(base.Add(time.Minute), "b", "192.0.2.1", 2)); got.Severity != Warning {
		t.Fatal(got)
	}
	got := engine.Evaluate(submission(base.Add(2*time.Minute), "c", "192.0.2.2", 2))
	if got.Severity != Contain || got.Stats.SourceIPs1h != 2 || got.Stats.Recipients5m != 5 {
		t.Fatal(got)
	}

	engine = NewEngine(policies{testPolicy()}, nil)
	if got := engine.Evaluate(submission(base, "a", "192.0.2.1", 8)); got.Severity != Contain {
		t.Fatal(got)
	}
}

func TestProviderCorrelationAndFailures(t *testing.T) {
	base := time.Now().UTC()
	engine := NewEngine(policies{testPolicy()}, nil)
	if got := engine.Evaluate(event.Event{Time: base, Kind: event.ProviderRejection, MessageID: "unknown", Source: "exim"}); got.Severity != None || got.Mailbox != "" {
		t.Fatal(got)
	}
	engine.Evaluate(submission(base, "known", "192.0.2.1", 2))
	got := engine.Evaluate(event.Event{Time: base.Add(time.Second), Kind: event.ProviderRejection, MessageID: "known", Source: "exim"})
	if got.Severity != Contain || got.Mailbox != "user@example.com" {
		t.Fatal(got)
	}

	engine = NewEngine(policies{testPolicy()}, nil)
	for index := 0; index < 3; index++ {
		got = engine.Evaluate(event.Event{Time: base.Add(time.Duration(index) * time.Second), Kind: event.AuthFailure, Mailbox: "user@example.com", Source: "dovecot"})
	}
	if got.Severity != Warning || got.Stats.AuthFailures5m != 3 {
		t.Fatal(got)
	}
}

func TestSeedPruningAndFutureEvents(t *testing.T) {
	now := time.Now().UTC()
	seed := []event.Event{
		submission(now.Add(-2*time.Hour), "old", "192.0.2.1", 100),
		submission(now.Add(-time.Minute), "recent", "192.0.2.2", 1),
		submission(now.Add(time.Hour), "future", "192.0.2.3", 100),
	}
	engine := NewEngine(policies{testPolicy()}, seed)
	got := engine.Evaluate(submission(now, "now", "192.0.2.4", 1))
	if got.Stats.Recipients5m != 2 || got.Stats.SourceIPs1h != 2 {
		t.Fatal(got)
	}
	if got := engine.Evaluate(event.Event{Time: now, Kind: event.AuthSuccess, Source: "dovecot"}); got.Severity != None {
		t.Fatal(got)
	}
}
