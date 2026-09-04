package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dwebserver/dweb-mail-abuse-guard/internal/config"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/control"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/policy"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/store"
)

type noRelease struct{}

func (noRelease) Release(context.Context, string, string) error { return nil }

func controlFixture(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	statePath := filepath.Join(directory, "state.db")
	socketPath := filepath.Join(directory, "control.sock")
	content := fmt.Sprintf(`mode: audit
state_path: %q
control_socket: %q
default_profile: p
sources: [{kind: exim, path: %q}]
profiles:
  p:
    warn_recipients_5m: 1
    contain_recipients_10m: 2
    contain_recipients_5m_with_ips: 2
    contain_source_ips_1h: 2
    contain_auth_failures_5m: 2
    provider_reject_min_recipients_5m: 1
accounts: {}
actions: {helper_path: %q}
notification: {}
`, statePath, socketPath, filepath.Join(directory, "mail.log"), filepath.Join(directory, "helper"))
	configPath := filepath.Join(directory, "config.yml")
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(statePath, false)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	_, _, err = database.CreateIncident(store.Incident{ID: "audit-id", Mailbox: "a@example.com", Status: store.IncidentAudit, Decision: policy.Decision{Severity: policy.Warning}, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- control.NewServer(config.Audit, database, noRelease{}).Serve(ctx, socketPath) }()
	for deadline := time.Now().Add(2 * time.Second); ; {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("control socket not created")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() { cancel(); _ = <-done; _ = database.Close() })
	return configPath
}

func TestControlStatusAndErrors(t *testing.T) {
	configPath := controlFixture(t)
	output, err := os.CreateTemp(t.TempDir(), "status")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	if err := status([]string{"--config", configPath}, output); err != nil {
		t.Fatal(err)
	}
	if info, err := output.Stat(); err != nil || info.Size() == 0 {
		t.Fatal(info, err)
	}
	if err := run(nil); err == nil {
		t.Fatal("empty command accepted")
	}
	if err := run([]string{"unknown"}); err == nil {
		t.Fatal("unknown command accepted")
	}
	if err := release([]string{"--config", configPath}); err == nil {
		t.Fatal("missing incident accepted")
	}
	if err := release([]string{"--config", configPath, "--incident", "missing"}); err == nil {
		t.Fatal("missing record accepted")
	}
	if err := release([]string{"--config", configPath, "--incident", "audit-id"}); err == nil {
		t.Fatal("audit incident released")
	}
}
