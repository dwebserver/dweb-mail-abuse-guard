package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func commandConfig(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	content := fmt.Sprintf(`mode: audit
state_path: %q
default_profile: p
sources:
  - kind: exim
    path: %q
profiles:
  p:
    warn_recipients_5m: 1
    contain_recipients_10m: 2
    contain_recipients_5m_with_ips: 2
    contain_source_ips_1h: 2
    contain_auth_failures_5m: 2
    provider_reject_min_recipients_5m: 1
    incident_cooldown: 1h
accounts: {}
actions:
  helper_path: %q
notification: {}
`, filepath.Join(directory, "state.db"), filepath.Join(directory, "mail.log"), filepath.Join(directory, "helper"))
	path := filepath.Join(directory, "config.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCommandRoutingAndValidation(t *testing.T) {
	if err := run([]string{"unknown"}); err == nil {
		t.Fatal("unknown command accepted")
	}
	if err := validateConfig([]string{"--config", filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Fatal("missing config accepted")
	}
	path := commandConfig(t)
	if err := validateConfig([]string{"--config", path}); err != nil {
		t.Fatal(err)
	}
	if _, err := parserFor("exim"); err != nil {
		t.Fatal(err)
	}
	if _, err := parserFor("dovecot"); err != nil {
		t.Fatal(err)
	}
	if _, err := parserFor("bad"); err == nil {
		t.Fatal("unknown parser accepted")
	}
}

func TestReplay(t *testing.T) {
	configPath := commandConfig(t)
	logPath := filepath.Join(t.TempDir(), "mail.log")
	line := "2026-09-03 10:38:12 ABC123 <= user@example.com H=(desk) [192.0.2.1]:123 P=esmtpsa A=plain:user@example.com for x@example.net\n"
	if err := os.WriteFile(logPath, []byte("unrelated\n"+line), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replay([]string{"--config", configPath, "--path", logPath, "--kind", "exim"}); err != nil {
		t.Fatal(err)
	}
	if err := replay([]string{"--config", configPath}); err == nil {
		t.Fatal("missing path accepted")
	}
	if err := replay([]string{"--config", configPath, "--path", filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Fatal("missing log accepted")
	}
}
