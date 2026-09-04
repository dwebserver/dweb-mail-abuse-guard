package report

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dwebserver/dweb-mail-abuse-guard/internal/config"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/event"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/policy"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/store"
)

type fakeState struct {
	events                                []event.Event
	incidents                             []store.Incident
	eventsErr, incidentsErr, heartbeatErr error
	heartbeats                            int
}

func (s *fakeState) RecentEvents(time.Time) ([]event.Event, error) { return s.events, s.eventsErr }
func (s *fakeState) Incidents() ([]store.Incident, error)          { return s.incidents, s.incidentsErr }
func (s *fakeState) Heartbeat(time.Time) error                     { s.heartbeats++; return s.heartbeatErr }

type fakeMailer struct {
	mu            sync.Mutex
	subject, body string
	err           error
	calls         int
	cancel        context.CancelFunc
	called        chan struct{}
}

func (m *fakeMailer) SendMessage(_ context.Context, subject, body string) error {
	m.mu.Lock()
	m.calls++
	m.subject, m.body = subject, body
	err, cancel, called := m.err, m.cancel, m.called
	m.mu.Unlock()
	if called != nil {
		called <- struct{}{}
	}
	if cancel != nil && err == nil {
		cancel()
	}
	return err
}
func (m *fakeMailer) setSuccess(cancel context.CancelFunc) {
	m.mu.Lock()
	m.err = nil
	m.cancel = cancel
	m.mu.Unlock()
}
func (m *fakeMailer) callCount() int { m.mu.Lock(); defer m.mu.Unlock(); return m.calls }

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestSendDailyReports(t *testing.T) {
	now := time.Now().UTC()
	state := &fakeState{events: []event.Event{{Time: now, Kind: event.Submission}, {Time: now, Kind: event.AuthFailure}}}
	mailer := &fakeMailer{}
	reporter := New(state, mailer, config.Audit, "mail.example.com", "1.2.3", now.Add(-time.Hour), 7, 0, time.Second, quietLogger())
	if err := reporter.Send(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"Daily health report", "No suspicious email activity", "authenticated submissions: 1", "authentication failures: 1", "Service status: running"} {
		if !strings.Contains(mailer.subject+mailer.body, text) {
			t.Errorf("missing %q", text)
		}
	}
	state.incidents = []store.Incident{{CreatedAt: now, Status: store.IncidentFailed, Decision: policy.Decision{Severity: policy.Contain}}}
	if err := reporter.Send(context.Background()); err != nil || !strings.Contains(mailer.body, "Suspicious activity was detected") || !strings.Contains(mailer.body, "failed containment actions: 1") {
		t.Fatal(err, mailer.body)
	}
}

func TestSendReportStateErrors(t *testing.T) {
	reporter := New(&fakeState{eventsErr: errors.New("events")}, &fakeMailer{}, config.Audit, "host", "v", time.Now(), 0, 0, time.Second, nil)
	if err := reporter.Send(context.Background()); err == nil {
		t.Fatal("event error hidden")
	}
	reporter.state = &fakeState{incidentsErr: errors.New("incidents")}
	if err := reporter.Send(context.Background()); err == nil {
		t.Fatal("incident error hidden")
	}
}

func TestRunHeartbeatAndReport(t *testing.T) {
	state := &fakeState{heartbeatErr: errors.New("db")}
	reporter := New(state, &fakeMailer{}, config.Audit, "host", "v", time.Now(), 0, 0, time.Second, quietLogger())
	reporter.heartbeatEvery = time.Millisecond
	reporter.nextReport = func(now time.Time, _, _ int) time.Time { return now.Add(time.Hour) }
	if err := reporter.Run(context.Background()); err == nil || state.heartbeats == 0 {
		t.Fatal(err, state.heartbeats)
	}

	ctx, cancel := context.WithCancel(context.Background())
	mailer := &fakeMailer{cancel: cancel}
	reporter = New(&fakeState{}, mailer, config.Audit, "host", "v", time.Now(), 0, 0, time.Second, quietLogger())
	reporter.heartbeatEvery = time.Hour
	reporter.nextReport = func(now time.Time, _, _ int) time.Time { return now.Add(time.Millisecond) }
	if err := reporter.Run(ctx); err != nil || mailer.callCount() != 1 {
		t.Fatal(err, mailer.callCount())
	}
}

func TestRunRetriesFailedReport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	mailer := &fakeMailer{err: errors.New("mail"), called: make(chan struct{}, 1)}
	reporter := New(&fakeState{}, mailer, config.Audit, "host", "v", time.Now(), 0, 0, time.Second, quietLogger())
	reporter.heartbeatEvery = time.Hour
	reporter.retryEvery = time.Millisecond
	reporter.nextReport = func(now time.Time, _, _ int) time.Time { return now.Add(time.Millisecond) }
	go func() { <-mailer.called; mailer.setSuccess(cancel) }()
	if err := reporter.Run(ctx); err != nil || mailer.callCount() < 2 {
		t.Fatal(err, mailer.callCount())
	}
}

func TestNextDailyAndSanitize(t *testing.T) {
	now := time.Date(2026, 9, 4, 6, 0, 0, 0, time.FixedZone("SAST", 7200))
	next := NextDaily(now, 7, 30)
	if !next.Equal(time.Date(2026, 9, 4, 7, 30, 0, 0, time.UTC)) {
		t.Fatal(next)
	}
	next = NextDaily(time.Date(2026, 9, 4, 8, 0, 0, 0, time.UTC), 7, 30)
	if next.Day() != 5 {
		t.Fatal(next)
	}
	if sanitizeSubject("a\r\nb") != "a  b" {
		t.Fatal("subject")
	}
}
