package control

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dwebserver/dweb-mail-abuse-guard/internal/config"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/policy"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/store"
)

type fakeState struct {
	incidents          []store.Incident
	listErr, updateErr error
	statuses           []store.IncidentStatus
}

func (s *fakeState) Incidents() ([]store.Incident, error) {
	return append([]store.Incident(nil), s.incidents...), s.listErr
}
func (s *fakeState) UpdateIncidentStatus(_ string, status store.IncidentStatus, _ time.Time) error {
	s.statuses = append(s.statuses, status)
	return s.updateErr
}

type fakeReleaser struct {
	err   error
	calls int
}
type fakeReporter struct {
	err   error
	calls int
}

func (r *fakeReporter) Send(context.Context) error { r.calls++; return r.err }

func (r *fakeReleaser) Release(context.Context, string, string) error { r.calls++; return r.err }

func incident(id string, status store.IncidentStatus, at time.Time) store.Incident {
	return store.Incident{ID: id, Mailbox: "a@example.com", Status: status, Decision: policy.Decision{Severity: policy.Contain}, CreatedAt: at, UpdatedAt: at}
}

func TestStatusHandler(t *testing.T) {
	now := time.Now()
	state := &fakeState{incidents: []store.Incident{incident("old", store.IncidentAudit, now.Add(-time.Hour)), incident("new", store.IncidentAudit, now)}}
	request := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	recorder := httptest.NewRecorder()
	NewServer(config.Audit, state, nil).Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"mode":"audit"`) || strings.Index(recorder.Body.String(), "new") > strings.Index(recorder.Body.String(), "old") {
		t.Fatal(recorder.Code, recorder.Body.String())
	}
	state.listErr = errors.New("db")
	recorder = httptest.NewRecorder()
	NewServer(config.Audit, state, nil).Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatal(recorder.Code)
	}
}

func TestReleaseHandler(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name     string
		state    *fakeState
		releaser Releaser
		id       string
		code     int
	}{
		{"missing", &fakeState{}, &fakeReleaser{}, "none", http.StatusNotFound},
		{"audit", &fakeState{incidents: []store.Incident{incident("id", store.IncidentAudit, now)}}, &fakeReleaser{}, "id", http.StatusConflict},
		{"already", &fakeState{incidents: []store.Incident{incident("id", store.IncidentReleased, now)}}, &fakeReleaser{}, "id", http.StatusOK},
		{"no helper", &fakeState{incidents: []store.Incident{incident("id", store.IncidentContained, now)}}, nil, "id", http.StatusServiceUnavailable},
		{"helper failure", &fakeState{incidents: []store.Incident{incident("id", store.IncidentContained, now)}}, &fakeReleaser{err: errors.New("no")}, "id", http.StatusBadGateway},
		{"update failure", &fakeState{incidents: []store.Incident{incident("id", store.IncidentContained, now)}, updateErr: errors.New("no")}, &fakeReleaser{}, "id", http.StatusInternalServerError},
		{"success", &fakeState{incidents: []store.Incident{incident("id", store.IncidentContained, now)}}, &fakeReleaser{}, "id", http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/incidents/"+test.id+"/release", nil)
			recorder := httptest.NewRecorder()
			NewServer(config.Enforce, test.state, test.releaser).Handler().ServeHTTP(recorder, request)
			if recorder.Code != test.code {
				t.Fatal(recorder.Code, recorder.Body.String())
			}
		})
	}
	state := &fakeState{listErr: errors.New("db")}
	request := httptest.NewRequest(http.MethodPost, "/v1/incidents/id/release", nil)
	recorder := httptest.NewRecorder()
	NewServer(config.Enforce, state, &fakeReleaser{}).Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatal(recorder.Code)
	}
}

func TestUnixServerAndClient(t *testing.T) {
	temporary, err := os.CreateTemp("", "mag-control-")
	if err != nil {
		t.Fatal(err)
	}
	path := temporary.Name()
	_ = temporary.Close()
	_ = os.Remove(path)
	t.Cleanup(func() { _ = os.Remove(path) })
	state := &fakeState{incidents: []store.Incident{incident("id", store.IncidentContained, time.Now())}}
	releaser := &fakeReleaser{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	server := NewServer(config.Enforce, state, releaser)
	reporter := &fakeReporter{}
	server.SetReporter(reporter)
	go func() { done <- server.Serve(ctx, path) }()
	for deadline := time.Now().Add(2 * time.Second); ; {
		if _, err := os.Stat(path); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("socket not created")
		}
		time.Sleep(10 * time.Millisecond)
	}
	client := NewClient(path, time.Second)
	status, err := client.Status(context.Background())
	if err != nil || status.Mode != config.Enforce || len(status.Incidents) != 1 {
		t.Fatal(status, err)
	}
	result, err := client.Release(context.Background(), "id")
	if err != nil || result.Status != store.IncidentReleased || releaser.calls != 1 {
		t.Fatal(result, err, releaser.calls)
	}
	if _, err := client.Release(context.Background(), "missing"); err == nil {
		t.Fatal("HTTP error hidden")
	}
	if err := client.Report(context.Background()); err != nil || reporter.calls != 1 {
		t.Fatal(err, reporter.calls)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestReportHandler(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/v1/report", nil)
	server := NewServer(config.Audit, &fakeState{}, nil)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatal(recorder.Code)
	}
	reporter := &fakeReporter{err: errors.New("mail")}
	server.SetReporter(reporter)
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadGateway {
		t.Fatal(recorder.Code)
	}
	reporter.err = nil
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || reporter.calls != 2 {
		t.Fatal(recorder.Code, reporter.calls)
	}
}

func TestServePathValidation(t *testing.T) {
	server := NewServer(config.Audit, &fakeState{}, nil)
	if err := server.Serve(context.Background(), "relative.sock"); err == nil {
		t.Fatal("relative path accepted")
	}
	path := filepath.Join(t.TempDir(), "control.sock")
	if err := os.WriteFile(path, []byte("not socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := server.Serve(context.Background(), path); err == nil {
		t.Fatal("regular file replaced")
	}
}
