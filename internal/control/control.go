// Package control exposes a small local API over a permission-protected Unix
// socket. The daemon remains the sole owner of the Bolt database.
package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dwebserver/dweb-mail-abuse-guard/internal/config"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/store"
)

const maxErrorBody = 64 * 1024

type State interface {
	Incidents() ([]store.Incident, error)
	UpdateIncidentStatus(string, store.IncidentStatus, time.Time) error
}

type Releaser interface {
	Release(context.Context, string, string) error
}

type Reporter interface {
	Send(context.Context) error
}

type Status struct {
	Mode      config.Mode      `json:"mode"`
	Incidents []store.Incident `json:"incidents"`
}

type Server struct {
	mode     config.Mode
	state    State
	releaser Releaser
	reporter Reporter
}

func NewServer(mode config.Mode, state State, releaser Releaser) *Server {
	return &Server{mode: mode, state: state, releaser: releaser}
}

func (s *Server) SetReporter(reporter Reporter) {
	s.reporter = reporter
}

// Serve listens until cancellation. It removes only a stale socket at the
// exact configured path and refuses to replace any other filesystem object.
func (s *Server) Serve(ctx context.Context, path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("control socket path must be absolute")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing to replace non-socket control path")
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove stale control socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect control socket: %w", err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("listen on control socket: %w", err)
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(path)
	}()
	if err := os.Chmod(path, 0o660); err != nil {
		return fmt.Errorf("set control socket permissions: %w", err)
	}

	httpServer := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()
	err = httpServer.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", s.status)
	mux.HandleFunc("POST /v1/incidents/{id}/release", s.release)
	mux.HandleFunc("POST /v1/report", s.report)
	return mux
}

func (s *Server) report(writer http.ResponseWriter, request *http.Request) {
	if s.reporter == nil {
		http.Error(writer, "email reporting is not configured", http.StatusServiceUnavailable)
		return
	}
	if err := s.reporter.Send(request.Context()); err != nil {
		http.Error(writer, "send health report failed", http.StatusBadGateway)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "sent"})
}

func (s *Server) status(writer http.ResponseWriter, _ *http.Request) {
	incidents, err := s.state.Incidents()
	if err != nil {
		http.Error(writer, "read incident state", http.StatusInternalServerError)
		return
	}
	sort.Slice(incidents, func(i, j int) bool { return incidents[i].CreatedAt.After(incidents[j].CreatedAt) })
	writeJSON(writer, http.StatusOK, Status{Mode: s.mode, Incidents: incidents})
}

func (s *Server) release(writer http.ResponseWriter, request *http.Request) {
	id := request.PathValue("id")
	incidents, err := s.state.Incidents()
	if err != nil {
		http.Error(writer, "read incident state", http.StatusInternalServerError)
		return
	}
	var selected *store.Incident
	for index := range incidents {
		if incidents[index].ID == id {
			selected = &incidents[index]
			break
		}
	}
	if selected == nil {
		http.Error(writer, "incident not found", http.StatusNotFound)
		return
	}
	if selected.Status == store.IncidentReleased {
		writeJSON(writer, http.StatusOK, selected)
		return
	}
	if selected.Status != store.IncidentContained {
		http.Error(writer, "incident is not contained", http.StatusConflict)
		return
	}
	if s.releaser == nil {
		http.Error(writer, "release helper is unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := s.releaser.Release(request.Context(), selected.Mailbox, selected.ID); err != nil {
		http.Error(writer, "mailbox release failed", http.StatusBadGateway)
		return
	}
	now := time.Now().UTC()
	if err := s.state.UpdateIncidentStatus(selected.ID, store.IncidentReleased, now); err != nil {
		http.Error(writer, "record release failed", http.StatusInternalServerError)
		return
	}
	selected.Status = store.IncidentReleased
	selected.UpdatedAt = now
	writeJSON(writer, http.StatusOK, selected)
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

type Client struct {
	httpClient *http.Client
}

func NewClient(socketPath string, timeout time.Duration) *Client {
	dialer := net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
	return &Client{httpClient: &http.Client{Transport: transport, Timeout: timeout}}
}

func (c *Client) Status(ctx context.Context) (Status, error) {
	var result Status
	if err := c.request(ctx, http.MethodGet, "/v1/status", &result); err != nil {
		return Status{}, err
	}
	return result, nil
}

func (c *Client) Release(ctx context.Context, id string) (store.Incident, error) {
	var result store.Incident
	path := "/v1/incidents/" + url.PathEscape(id) + "/release"
	if err := c.request(ctx, http.MethodPost, path, &result); err != nil {
		return store.Incident{}, err
	}
	return result, nil
}

func (c *Client) Report(ctx context.Context) error {
	var result map[string]string
	return c.request(ctx, http.MethodPost, "/v1/report", &result)
}

func (c *Client) request(ctx context.Context, method, path string, destination any) error {
	request, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, nil)
	if err != nil {
		return err
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("control request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, maxErrorBody))
		return fmt.Errorf("control request returned HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxErrorBody)).Decode(destination); err != nil {
		return fmt.Errorf("decode control response: %w", err)
	}
	return nil
}
