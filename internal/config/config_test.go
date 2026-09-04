package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func validConfig(t *testing.T, extra string) string {
	t.Helper()
	directory := t.TempDir()
	content := fmt.Sprintf(`
mode: audit
state_path: %q
poll_interval: 250ms
retention: 2h
default_profile: standard
sources:
  - kind: exim
    path: %q
profiles:
  standard:
    warn_recipients_5m: 20
    contain_recipients_10m: 100
    contain_recipients_5m_with_ips: 50
    contain_source_ips_1h: 3
    contain_auth_failures_5m: 20
    provider_reject_min_recipients_5m: 10
    incident_cooldown: 30m
accounts:
  VIP@Example.com: standard
actions:
  helper_path: %q
  helper_args: ["-n", "/helper"]
  timeout: 4s
notification:
  timeout: 3s
%s`, filepath.Join(directory, "state.db"), filepath.Join(directory, "mail.log"), filepath.Join(directory, "sudo"), extra)
	path := filepath.Join(directory, "config.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadAndPolicyFor(t *testing.T) {
	path := validConfig(t, "")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PollInterval != 250*time.Millisecond || cfg.Retention != 2*time.Hour || cfg.Actions.Timeout != 4*time.Second || cfg.Notification.Timeout != 3*time.Second {
		t.Fatalf("durations not decoded: %#v", cfg)
	}
	if cfg.PolicyFor("vip@example.com").IncidentCooldown != 30*time.Minute || cfg.PolicyFor("other@example.com").WarnRecipients5m != 20 {
		t.Fatal("profile lookup failed")
	}
	if _, ok := cfg.Accounts["vip@example.com"]; !ok {
		t.Fatal("account key was not normalized")
	}
}

func TestLoadFailures(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing configuration should fail")
	}
	path := validConfig(t, "unknown_field: true")
	if _, err := Load(path); err == nil {
		t.Fatal("unknown field should fail")
	}
	bad := []func(*Config){
		func(c *Config) { c.Mode = "bad" },
		func(c *Config) { c.StatePath = "relative" },
		func(c *Config) { c.ControlSocket = "relative" },
		func(c *Config) { c.PollText = "bad" },
		func(c *Config) { c.RetentionText = "30m" },
		func(c *Config) { c.Sources = nil },
		func(c *Config) { c.Sources[0].Kind = "postfix" },
		func(c *Config) { c.Sources[0].Path = "relative" },
		func(c *Config) { c.DefaultProfile = "missing" },
		func(c *Config) { c.Profiles["standard"] = Policy{} },
		func(c *Config) { c.Accounts = map[string]string{"bad": "standard"} },
		func(c *Config) { c.Accounts = map[string]string{"a@example.com": "missing"} },
		func(c *Config) {
			c.Accounts = map[string]string{"A@example.com": "standard", "a@example.com": "standard"}
		},
		func(c *Config) { c.Actions.TimeoutText = "zero" },
		func(c *Config) { c.Mode = Enforce; c.Actions.HelperPath = "relative" },
		func(c *Config) { c.Notification.TimeoutText = "0s" },
		func(c *Config) { c.Notification.WebhookURLFile = "relative" },
	}
	base, err := Load(validConfig(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	for index, mutate := range bad {
		cfg := base
		cfg.Sources = append([]Source(nil), base.Sources...)
		cfg.Profiles = make(map[string]Policy)
		for name, profile := range base.Profiles {
			cfg.Profiles[name] = profile
		}
		cfg.Accounts = make(map[string]string)
		for name, profile := range base.Accounts {
			cfg.Accounts[name] = profile
		}
		mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("case %d should fail", index)
		}
	}
}

func TestValidatePolicyRelationships(t *testing.T) {
	base, err := Load(validConfig(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	profile := base.Profiles["standard"]
	profile.ContainRecipients10m = 1
	base.Profiles["standard"] = profile
	if err := base.Validate(); err == nil {
		t.Fatal("low contain threshold should fail")
	}

	base, _ = Load(validConfig(t, ""))
	profile = base.Profiles["standard"]
	profile.IncidentCooldownText = "bad"
	base.Profiles["standard"] = profile
	if err := base.Validate(); err == nil {
		t.Fatal("bad cooldown should fail")
	}
}

func TestEmailNotificationValidation(t *testing.T) {
	base, err := Load(validConfig(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	base.Notification.EmailTo = "Fabrice@Example.com"
	base.Notification.EmailFrom = "guard@example.com"
	base.Notification.SendmailPath = filepath.Join(t.TempDir(), "sendmail")
	base.Notification.DailyReportAt = "07:30"
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	if base.Notification.EmailTo != "fabrice@example.com" || base.Notification.DailyHour != 7 || base.Notification.DailyMinute != 30 {
		t.Fatal(base.Notification)
	}

	mutations := []func(*Notification){
		func(n *Notification) { n.EmailTo = "bad" },
		func(n *Notification) { n.EmailFrom = "bad" },
		func(n *Notification) { n.SendmailPath = "relative" },
		func(n *Notification) { n.DailyReportAt = "25:00" },
	}
	for index, mutate := range mutations {
		candidate := base
		candidate.Notification = base.Notification
		mutate(&candidate.Notification)
		if err := candidate.Validate(); err == nil {
			t.Errorf("case %d should fail", index)
		}
	}
}
