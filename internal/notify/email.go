package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/dwebserver/dweb-mail-abuse-guard/internal/store"
)

const maxSendmailOutput = 64 * 1024

type messageRunner interface {
	Run(context.Context, string, []string, []byte) ([]byte, error)
}

type execMessageRunner struct{}

func (execMessageRunner) Run(ctx context.Context, path string, arguments []string, input []byte) ([]byte, error) {
	command := exec.CommandContext(ctx, path, arguments...)
	command.Stdin = bytes.NewReader(input)
	var output boundedBuffer
	command.Stdout = &output
	command.Stderr = &output
	err := command.Run()
	if err != nil {
		return output.Bytes(), fmt.Errorf("run local mail transport: %w", err)
	}
	return output.Bytes(), nil
}

type boundedBuffer struct {
	value bytes.Buffer
	over  bool
}

func (b *boundedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	remaining := maxSendmailOutput - b.value.Len()
	if remaining <= 0 {
		b.over = true
		return original, nil
	}
	if len(value) > remaining {
		value = value[:remaining]
		b.over = true
	}
	_, _ = b.value.Write(value)
	return original, nil
}

func (b *boundedBuffer) Bytes() []byte {
	if !b.over {
		return b.value.Bytes()
	}
	return append(append([]byte(nil), b.value.Bytes()...), []byte("\n[output truncated]\n")...)
}

// Email delivers plain-text operational mail through the host's local
// sendmail-compatible transport. Addresses are validated during config load.
type Email struct {
	runner   messageRunner
	path     string
	to       string
	from     string
	hostname string
}

func NewEmail(path, to, from, hostname string) *Email {
	return &Email{runner: execMessageRunner{}, path: path, to: to, from: from, hostname: hostname}
}

func (e *Email) Send(ctx context.Context, incident store.Incident) error {
	subject := fmt.Sprintf("[DWEB Mail Guard] %s incident for %s", strings.ToUpper(string(incident.Decision.Severity)), incident.Mailbox)
	body := fmt.Sprintf(`DWEB Mail Abuse Guard detected suspicious authenticated email activity.

Server: %s
Incident: %s
Mailbox: %s
Time: %s
Mode status: %s
Severity: %s
Signals: %s

Observed counters:
- recipients in 5 minutes: %d
- recipients in 10 minutes: %d
- source IPs in 1 hour: %d
- authentication failures in 5 minutes: %d
- provider abuse rejections in 10 minutes: %d

Review the incident immediately with:
dweb-mail-abuse-guardctl status
`, e.hostname, incident.ID, incident.Mailbox, incident.Decision.Time.UTC().Format(time.RFC3339), incident.Status, incident.Decision.Severity, strings.Join(incident.Decision.Signals, ", "), incident.Decision.Stats.Recipients5m, incident.Decision.Stats.Recipients10m, incident.Decision.Stats.SourceIPs1h, incident.Decision.Stats.AuthFailures5m, incident.Decision.Stats.ProviderRejects10m)
	return e.SendMessage(ctx, subject, body)
}

func (e *Email) SendMessage(ctx context.Context, subject, body string) error {
	subject = strings.NewReplacer("\r", " ", "\n", " ").Replace(subject)
	identifier, err := randomMessageID()
	if err != nil {
		return err
	}
	message := fmt.Sprintf("From: DWEB Mail Abuse Guard <%s>\r\nTo: <%s>\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%s@%s>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\nAuto-Submitted: auto-generated\r\n\r\n%s\r\n", e.from, e.to, subject, time.Now().UTC().Format(time.RFC1123Z), identifier, e.hostname, normalizeBody(body))
	output, err := e.runner.Run(ctx, e.path, []string{"-i", "-t"}, []byte(message))
	if err != nil {
		return fmt.Errorf("send operational email: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func randomMessageID() (string, error) {
	value := make([]byte, 12)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate email message ID: %w", err)
	}
	return "dweb-mag-" + hex.EncodeToString(value), nil
}

func normalizeBody(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	return strings.ReplaceAll(value, "\n", "\r\n")
}

// Multi sends an incident to every configured channel and reports all errors.
type Multi []Sender

func (m Multi) Send(ctx context.Context, incident store.Incident) error {
	var failures []error
	for _, sender := range m {
		if sender == nil {
			continue
		}
		if err := sender.Send(ctx, incident); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}
