// Package event defines the normalized security events consumed by policy.
package event

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/dwebserver/dweb-mail-abuse-guard/internal/identity"
)

// Kind describes an observable mail-system event.
type Kind string

const (
	Submission        Kind = "submission"
	AuthSuccess       Kind = "auth_success"
	AuthFailure       Kind = "auth_failure"
	ProviderRejection Kind = "provider_rejection"
)

// Event contains only the metadata required for abuse detection. Message
// bodies, passwords, and recipient addresses are intentionally excluded.
type Event struct {
	Time           time.Time `json:"time"`
	Kind           Kind      `json:"kind"`
	Mailbox        string    `json:"mailbox,omitempty"`
	SourceIP       string    `json:"source_ip,omitempty"`
	MessageID      string    `json:"message_id,omitempty"`
	EnvelopeSender string    `json:"envelope_sender,omitempty"`
	RecipientCount int       `json:"recipient_count,omitempty"`
	Code           string    `json:"code,omitempty"`
	Source         string    `json:"source"`
}

// Validate rejects malformed events before they enter persistent state.
func (e Event) Validate() error {
	if e.Time.IsZero() {
		return fmt.Errorf("event time is required")
	}
	switch e.Kind {
	case Submission, AuthSuccess, AuthFailure:
		if _, err := identity.NormalizeMailbox(e.Mailbox); err != nil {
			return fmt.Errorf("invalid mailbox: %w", err)
		}
	case ProviderRejection:
		if e.Mailbox == "" && strings.TrimSpace(e.MessageID) == "" {
			return fmt.Errorf("provider rejection requires a mailbox or message ID")
		}
		if e.Mailbox != "" {
			if _, err := identity.NormalizeMailbox(e.Mailbox); err != nil {
				return fmt.Errorf("invalid mailbox: %w", err)
			}
		}
	default:
		return fmt.Errorf("unsupported event kind %q", e.Kind)
	}
	if e.SourceIP != "" && net.ParseIP(e.SourceIP) == nil {
		return fmt.Errorf("invalid source IP")
	}
	if e.RecipientCount < 0 {
		return fmt.Errorf("recipient count cannot be negative")
	}
	if strings.TrimSpace(e.Source) == "" {
		return fmt.Errorf("event source is required")
	}
	return nil
}
