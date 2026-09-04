// Package config loads and validates the operator configuration.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dwebserver/dweb-mail-abuse-guard/internal/identity"
	"gopkg.in/yaml.v3"
)

// Mode determines whether decisions are recorded or enforced.
type Mode string

const (
	Audit   Mode = "audit"
	Enforce Mode = "enforce"
)

type Source struct {
	Kind       string `yaml:"kind"`
	Path       string `yaml:"path"`
	StartAtEnd bool   `yaml:"start_at_end"`
}

// Policy describes rolling-window thresholds for one mailbox class.
type Policy struct {
	WarnRecipients5m              int           `yaml:"warn_recipients_5m"`
	ContainRecipients10m          int           `yaml:"contain_recipients_10m"`
	ContainRecipients5mWithIPs    int           `yaml:"contain_recipients_5m_with_ips"`
	ContainSourceIPs1h            int           `yaml:"contain_source_ips_1h"`
	ContainAuthFailures5m         int           `yaml:"contain_auth_failures_5m"`
	ProviderRejectMinRecipients5m int           `yaml:"provider_reject_min_recipients_5m"`
	IncidentCooldown              time.Duration `yaml:"-"`
	IncidentCooldownText          string        `yaml:"incident_cooldown"`
}

type Actions struct {
	HelperPath  string        `yaml:"helper_path"`
	HelperArgs  []string      `yaml:"helper_args"`
	Timeout     time.Duration `yaml:"-"`
	TimeoutText string        `yaml:"timeout"`
}

type Notification struct {
	WebhookURLFile string        `yaml:"webhook_url_file"`
	Timeout        time.Duration `yaml:"-"`
	TimeoutText    string        `yaml:"timeout"`
}

// Config is the complete daemon configuration.
type Config struct {
	Mode           Mode              `yaml:"mode"`
	StatePath      string            `yaml:"state_path"`
	ControlSocket  string            `yaml:"control_socket"`
	PollInterval   time.Duration     `yaml:"-"`
	PollText       string            `yaml:"poll_interval"`
	Retention      time.Duration     `yaml:"-"`
	RetentionText  string            `yaml:"retention"`
	DefaultProfile string            `yaml:"default_profile"`
	Sources        []Source          `yaml:"sources"`
	Profiles       map[string]Policy `yaml:"profiles"`
	Accounts       map[string]string `yaml:"accounts"`
	Actions        Actions           `yaml:"actions"`
	Notification   Notification      `yaml:"notification"`
}

// Load reads a YAML document and rejects unknown fields.
func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open configuration: %w", err)
	}
	defer file.Close()

	var cfg Config
	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode configuration: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate applies secure defaults and checks relationships between settings.
func (c *Config) Validate() error {
	if c.Mode != Audit && c.Mode != Enforce {
		return fmt.Errorf("mode must be audit or enforce")
	}
	if !filepath.IsAbs(c.StatePath) {
		return fmt.Errorf("state_path must be absolute")
	}
	if c.ControlSocket == "" {
		c.ControlSocket = filepath.Join(filepath.Dir(c.StatePath), "control.sock")
	}
	if !filepath.IsAbs(c.ControlSocket) {
		return fmt.Errorf("control_socket must be absolute")
	}
	var err error
	if c.PollInterval, err = durationOrDefault(c.PollText, 500*time.Millisecond); err != nil {
		return fmt.Errorf("poll_interval: %w", err)
	}
	if c.Retention, err = durationOrDefault(c.RetentionText, 24*time.Hour); err != nil {
		return fmt.Errorf("retention: %w", err)
	}
	if c.Retention < time.Hour {
		return fmt.Errorf("retention must be at least one hour")
	}
	if len(c.Sources) == 0 {
		return fmt.Errorf("at least one log source is required")
	}
	for index, source := range c.Sources {
		if source.Kind != "exim" && source.Kind != "dovecot" {
			return fmt.Errorf("sources[%d].kind must be exim or dovecot", index)
		}
		if !filepath.IsAbs(source.Path) {
			return fmt.Errorf("sources[%d].path must be absolute", index)
		}
	}
	if c.DefaultProfile == "" || c.Profiles[c.DefaultProfile].WarnRecipients5m == 0 {
		return fmt.Errorf("default_profile must reference a configured profile")
	}
	for name, policy := range c.Profiles {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("profile name cannot be empty")
		}
		if err := validatePolicy(name, &policy); err != nil {
			return err
		}
		c.Profiles[name] = policy
	}
	normalizedAccounts := make(map[string]string, len(c.Accounts))
	for mailbox, profile := range c.Accounts {
		normalized, err := identity.NormalizeMailbox(mailbox)
		if err != nil {
			return fmt.Errorf("accounts contains invalid mailbox %q", mailbox)
		}
		if _, ok := c.Profiles[profile]; !ok {
			return fmt.Errorf("account %q references unknown profile %q", mailbox, profile)
		}
		if _, duplicate := normalizedAccounts[normalized]; duplicate {
			return fmt.Errorf("accounts contains duplicate mailbox %q", normalized)
		}
		normalizedAccounts[normalized] = profile
	}
	c.Accounts = normalizedAccounts
	if c.Actions.Timeout, err = durationOrDefault(c.Actions.TimeoutText, 20*time.Second); err != nil {
		return fmt.Errorf("actions.timeout: %w", err)
	}
	if c.Mode == Enforce && !filepath.IsAbs(c.Actions.HelperPath) {
		return fmt.Errorf("actions.helper_path must be absolute in enforce mode")
	}
	if c.Notification.Timeout, err = durationOrDefault(c.Notification.TimeoutText, 10*time.Second); err != nil {
		return fmt.Errorf("notification.timeout: %w", err)
	}
	if c.Notification.WebhookURLFile != "" && !filepath.IsAbs(c.Notification.WebhookURLFile) {
		return fmt.Errorf("notification.webhook_url_file must be absolute")
	}
	return nil
}

func validatePolicy(name string, policy *Policy) error {
	values := []int{
		policy.WarnRecipients5m,
		policy.ContainRecipients10m,
		policy.ContainRecipients5mWithIPs,
		policy.ContainSourceIPs1h,
		policy.ContainAuthFailures5m,
		policy.ProviderRejectMinRecipients5m,
	}
	for _, value := range values {
		if value <= 0 {
			return fmt.Errorf("profile %q thresholds must be positive", name)
		}
	}
	if policy.ContainRecipients10m < policy.WarnRecipients5m {
		return fmt.Errorf("profile %q contain threshold must not be below warning threshold", name)
	}
	duration, err := durationOrDefault(policy.IncidentCooldownText, time.Hour)
	if err != nil {
		return fmt.Errorf("profile %q incident_cooldown: %w", name, err)
	}
	policy.IncidentCooldown = duration
	return nil
}

func durationOrDefault(value string, fallback time.Duration) (time.Duration, error) {
	if strings.TrimSpace(value) == "" {
		return fallback, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("must be a positive Go duration")
	}
	return duration, nil
}

// PolicyFor returns the configured policy for a normalized mailbox.
func (c Config) PolicyFor(mailbox string) Policy {
	profile := c.DefaultProfile
	if override, ok := c.Accounts[strings.ToLower(mailbox)]; ok {
		profile = override
	}
	return c.Profiles[profile]
}
