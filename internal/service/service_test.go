package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/dwebserver/dweb-mail-abuse-guard/internal/config"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/event"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/policy"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/store"
)

type fakeState struct {
	events                          []event.Event
	incidents                       []store.Incident
	statuses                        []store.IncidentStatus
	appendErr, createErr, updateErr error
	created                         bool
}

func (s *fakeState) AppendEvent(item event.Event) error {
	s.events = append(s.events, item)
	return s.appendErr
}
func (s *fakeState) CreateIncident(item store.Incident) (store.Incident, bool, error) {
	s.incidents = append(s.incidents, item)
	return item, s.created, s.createErr
}
func (s *fakeState) UpdateIncidentStatus(_ string, status store.IncidentStatus, _ time.Time) error {
	s.statuses = append(s.statuses, status)
	return s.updateErr
}

type fakeActions struct {
	err   error
	calls int
}

func (a *fakeActions) Contain(context.Context, string, string) error { a.calls++; return a.err }

type fakeNotifier struct {
	err   error
	calls int
	last  store.Incident
}

func (n *fakeNotifier) Send(_ context.Context, item store.Incident) error {
	n.calls++
	n.last = item
	return n.err
}

func serviceConfig(mode config.Mode) config.Config {
	profile := config.Policy{WarnRecipients5m: 1, ContainRecipients10m: 2, ContainRecipients5mWithIPs: 2, ContainSourceIPs1h: 2, ContainAuthFailures5m: 2, ProviderRejectMinRecipients5m: 1, IncidentCooldown: time.Hour}
	return config.Config{Mode: mode, DefaultProfile: "p", Profiles: map[string]config.Policy{"p": profile}, Notification: config.Notification{Timeout: time.Second}}
}
func logless() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
func testEvent(recipients int) event.Event {
	return event.Event{Time: time.Now().UTC(), Kind: event.Submission, Mailbox: "a@example.com", SourceIP: "192.0.2.1", RecipientCount: recipients, Source: "exim"}
}

func TestAuditAndEnforcement(t *testing.T) {
	for _, mode := range []config.Mode{config.Audit, config.Enforce} {
		cfg := serviceConfig(mode)
		state := &fakeState{created: true}
		actions := &fakeActions{}
		notifier := &fakeNotifier{}
		svc := New(cfg, policy.NewEngine(cfg, nil), state, actions, notifier, logless())
		svc.newID = func(time.Time) (string, error) { return "incident", nil }
		decision, err := svc.Handle(context.Background(), testEvent(2))
		if err != nil || decision.Severity != policy.Contain || len(state.incidents) != 1 || notifier.calls != 1 {
			t.Fatal(mode, decision, err, state, notifier.calls)
		}
		if mode == config.Audit && (actions.calls != 0 || state.incidents[0].Status != store.IncidentAudit) {
			t.Fatal("audit enforced")
		}
		if mode == config.Enforce && (actions.calls != 1 || len(state.statuses) != 1 || state.statuses[0] != store.IncidentContained || notifier.last.Status != store.IncidentContained) {
			t.Fatal(actions, state, notifier.last)
		}
	}
}

func TestNoDecisionDuplicateAndWarning(t *testing.T) {
	cfg := serviceConfig(config.Enforce)
	state := &fakeState{created: true}
	actions := &fakeActions{}
	notifier := &fakeNotifier{}
	svc := New(cfg, policy.NewEngine(cfg, nil), state, actions, notifier, logless())
	svc.newID = func(time.Time) (string, error) { return "id", nil }
	decision, err := svc.Handle(context.Background(), testEvent(0))
	if err != nil || decision.Severity != policy.None || len(state.incidents) != 0 {
		t.Fatal(decision, err)
	}
	decision, err = svc.Handle(context.Background(), testEvent(1))
	if err != nil || decision.Severity != policy.Warning || actions.calls != 0 {
		t.Fatal(decision, err, actions.calls)
	}
	state.created = false
	_, err = svc.Handle(context.Background(), testEvent(2))
	if err != nil || notifier.calls != 1 {
		t.Fatal(err, notifier.calls)
	}
}

func TestServiceFailures(t *testing.T) {
	cfg := serviceConfig(config.Enforce)
	tests := []struct {
		name       string
		state      *fakeState
		actions    *fakeActions
		iderr      error
		wantStatus store.IncidentStatus
	}{
		{"append", &fakeState{appendErr: errors.New("append")}, &fakeActions{}, nil, ""},
		{"id", &fakeState{}, &fakeActions{}, errors.New("id"), ""},
		{"create", &fakeState{createErr: errors.New("create")}, &fakeActions{}, nil, ""},
		{"action", &fakeState{created: true}, &fakeActions{err: errors.New("action")}, nil, store.IncidentFailed},
		{"update", &fakeState{created: true, updateErr: errors.New("update")}, &fakeActions{}, nil, store.IncidentContained},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			svc := New(cfg, policy.NewEngine(cfg, nil), test.state, test.actions, &fakeNotifier{}, logless())
			svc.newID = func(time.Time) (string, error) { return "id", test.iderr }
			_, err := svc.Handle(context.Background(), testEvent(2))
			if err == nil {
				t.Fatal("expected error")
			}
			if test.wantStatus != "" && (len(test.state.statuses) == 0 || test.state.statuses[0] != test.wantStatus) {
				t.Fatal(test.state.statuses)
			}
		})
	}

	state := &fakeState{created: true}
	svc := New(cfg, policy.NewEngine(cfg, nil), state, nil, nil, nil)
	svc.newID = func(time.Time) (string, error) { return "id", nil }
	if _, err := svc.Handle(context.Background(), testEvent(2)); err == nil {
		t.Fatal("missing action accepted")
	}

	state = &fakeState{created: true}
	notifier := &fakeNotifier{err: errors.New("notify")}
	svc = New(serviceConfig(config.Audit), policy.NewEngine(serviceConfig(config.Audit), nil), state, nil, notifier, logless())
	svc.newID = func(time.Time) (string, error) { return "id", nil }
	if _, err := svc.Handle(context.Background(), testEvent(2)); err != nil {
		t.Fatal("notification errors should not stop detection", err)
	}
}
