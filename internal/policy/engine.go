// Package policy correlates mail events into explainable abuse decisions.
package policy

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dwebserver/dweb-mail-abuse-guard/internal/config"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/event"
)

// Severity is the action level produced by policy evaluation.
type Severity string

const (
	None    Severity = "none"
	Warning Severity = "warning"
	Contain Severity = "contain"
)

// Stats are rolling values captured at decision time.
type Stats struct {
	Recipients5m       int `json:"recipients_5m"`
	Recipients10m      int `json:"recipients_10m"`
	SourceIPs1h        int `json:"source_ips_1h"`
	AuthFailures5m     int `json:"auth_failures_5m"`
	ProviderRejects10m int `json:"provider_rejects_10m"`
}

// Decision is intentionally explainable: operators can see the exact signals
// that caused a warning or containment request.
type Decision struct {
	Time     time.Time `json:"time"`
	Mailbox  string    `json:"mailbox"`
	Severity Severity  `json:"severity"`
	Signals  []string  `json:"signals,omitempty"`
	Stats    Stats     `json:"stats"`
}

// PolicyProvider resolves mailbox-specific profiles.
type PolicyProvider interface {
	PolicyFor(mailbox string) config.Policy
}

// Engine maintains only the one-hour working set needed by current rules.
// Durable storage remains responsible for incident history and restart replay.
type Engine struct {
	mu            sync.Mutex
	policies      PolicyProvider
	events        map[string][]event.Event
	messageOwners map[string]messageOwner
}

type messageOwner struct {
	mailbox string
	seenAt  time.Time
}

func NewEngine(policies PolicyProvider, seed []event.Event) *Engine {
	engine := &Engine{
		policies:      policies,
		events:        make(map[string][]event.Event),
		messageOwners: make(map[string]messageOwner),
	}
	for _, item := range seed {
		engine.add(item)
	}
	return engine
}

// Evaluate updates the working set and returns a decision for a mailbox event.
// Provider rejections are associated with the authenticated owner of the Exim
// message ID; unmatched rejections are ignored rather than guessed.
func (e *Engine) Evaluate(item event.Event) Decision {
	e.mu.Lock()
	defer e.mu.Unlock()

	if item.Kind == event.ProviderRejection && item.Mailbox == "" {
		owner, ok := e.messageOwners[item.MessageID]
		if !ok {
			return Decision{Time: item.Time, Severity: None}
		}
		item.Mailbox = owner.mailbox
	}
	if item.Mailbox == "" {
		return Decision{Time: item.Time, Severity: None}
	}

	e.add(item)
	e.prune(item.Time)
	stats := summarize(e.events[item.Mailbox], item.Time)
	configured := e.policies.PolicyFor(item.Mailbox)

	decision := Decision{
		Time:     item.Time,
		Mailbox:  item.Mailbox,
		Severity: None,
		Stats:    stats,
	}

	if stats.Recipients10m >= configured.ContainRecipients10m {
		decision.Severity = Contain
		decision.Signals = append(decision.Signals, "hard recipient ceiling exceeded")
	}
	if stats.Recipients5m >= configured.ContainRecipients5mWithIPs && stats.SourceIPs1h >= configured.ContainSourceIPs1h {
		decision.Severity = Contain
		decision.Signals = append(decision.Signals, "recipient burst from multiple source IPs")
	}
	if stats.ProviderRejects10m > 0 && stats.Recipients5m >= configured.ProviderRejectMinRecipients5m {
		decision.Severity = Contain
		decision.Signals = append(decision.Signals, "provider abuse rejection during abnormal volume")
	}
	if decision.Severity != Contain {
		if stats.Recipients5m >= configured.WarnRecipients5m {
			decision.Severity = Warning
			decision.Signals = append(decision.Signals, "recipient warning threshold exceeded")
		}
		if stats.AuthFailures5m >= configured.ContainAuthFailures5m {
			decision.Severity = Warning
			decision.Signals = append(decision.Signals, "authentication failure threshold exceeded")
		}
	}
	sort.Strings(decision.Signals)
	return decision
}

func (e *Engine) add(item event.Event) {
	mailbox := strings.ToLower(item.Mailbox)
	if mailbox != "" {
		item.Mailbox = mailbox
		e.events[mailbox] = append(e.events[mailbox], item)
	}
	if item.Kind == event.Submission && item.MessageID != "" {
		e.messageOwners[item.MessageID] = messageOwner{mailbox: mailbox, seenAt: item.Time}
	}
}

func (e *Engine) prune(now time.Time) {
	cutoff := now.Add(-time.Hour)
	for mailbox, items := range e.events {
		kept := items[:0]
		for _, item := range items {
			if !item.Time.Before(cutoff) {
				kept = append(kept, item)
			}
		}
		if len(kept) == 0 {
			delete(e.events, mailbox)
		} else {
			e.events[mailbox] = kept
		}
	}
	for id, owner := range e.messageOwners {
		if owner.seenAt.Before(cutoff) {
			delete(e.messageOwners, id)
		}
	}
}

func summarize(items []event.Event, now time.Time) Stats {
	var stats Stats
	sourceIPs := make(map[string]struct{})
	fiveMinutesAgo := now.Add(-5 * time.Minute)
	tenMinutesAgo := now.Add(-10 * time.Minute)
	oneHourAgo := now.Add(-time.Hour)
	for _, item := range items {
		if item.Time.After(now) || item.Time.Before(oneHourAgo) {
			continue
		}
		if item.Kind == event.Submission && item.SourceIP != "" {
			sourceIPs[item.SourceIP] = struct{}{}
		}
		if !item.Time.Before(fiveMinutesAgo) {
			switch item.Kind {
			case event.Submission:
				stats.Recipients5m += item.RecipientCount
			case event.AuthFailure:
				stats.AuthFailures5m++
			}
		}
		if !item.Time.Before(tenMinutesAgo) {
			switch item.Kind {
			case event.Submission:
				stats.Recipients10m += item.RecipientCount
			case event.ProviderRejection:
				stats.ProviderRejects10m++
			}
		}
	}
	stats.SourceIPs1h = len(sourceIPs)
	return stats
}
