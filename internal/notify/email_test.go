package notify

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dwebserver/dweb-mail-abuse-guard/internal/policy"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/store"
)

type fakeMessageRunner struct {
	path      string
	arguments []string
	input     []byte
	output    []byte
	err       error
}

func (r *fakeMessageRunner) Run(_ context.Context, path string, arguments []string, input []byte) ([]byte, error) {
	r.path = path
	r.arguments = append([]string(nil), arguments...)
	r.input = append([]byte(nil), input...)
	return r.output, r.err
}

func TestEmailIncidentAndMessage(t *testing.T) {
	runner := &fakeMessageRunner{}
	email := NewEmail("/sendmail", "admin@example.com", "guard@example.com", "mail.example.com")
	email.runner = runner
	incident := store.Incident{ID: "mag-id", Mailbox: "user@example.com", Status: store.IncidentAudit, Decision: policy.Decision{Time: time.Now(), Severity: policy.Contain, Signals: []string{"provider rejection"}, Stats: policy.Stats{Recipients5m: 10, Recipients10m: 12, SourceIPs1h: 6, AuthFailures5m: 2, ProviderRejects10m: 1}}}
	if err := email.Send(context.Background(), incident); err != nil {
		t.Fatal(err)
	}
	message := string(runner.input)
	for _, expected := range []string{"To: <admin@example.com>", "CONTAIN incident for user@example.com", "provider rejection", "recipients in 5 minutes: 10", "Auto-Submitted: auto-generated"} {
		if !strings.Contains(message, expected) {
			t.Errorf("missing %q in %s", expected, message)
		}
	}
	if runner.path != "/sendmail" || len(runner.arguments) != 2 || runner.arguments[0] != "-i" {
		t.Fatal(runner)
	}
	if err := email.SendMessage(context.Background(), "bad\r\nInjected: header", "line1\nline2"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(runner.input), "\r\nInjected: header\r\n") || !strings.Contains(string(runner.input), "line1\r\nline2") {
		t.Fatal(string(runner.input))
	}
}

func TestEmailFailuresAndMulti(t *testing.T) {
	runner := &fakeMessageRunner{output: []byte("transport said no"), err: errors.New("exit")}
	email := NewEmail("/sendmail", "a@example.com", "b@example.com", "host")
	email.runner = runner
	if err := email.SendMessage(context.Background(), "subject", "body"); err == nil || !strings.Contains(err.Error(), "transport said no") {
		t.Fatal(err)
	}
	good := &fakeSender{}
	bad := &fakeSender{err: errors.New("bad")}
	if err := (Multi{nil, good, bad}).Send(context.Background(), store.Incident{}); err == nil || good.calls != 1 || bad.calls != 1 {
		t.Fatal(err, good, bad)
	}
}

type fakeSender struct {
	calls int
	err   error
}

func (s *fakeSender) Send(context.Context, store.Incident) error { s.calls++; return s.err }

func TestBoundedBufferAndHelpers(t *testing.T) {
	var buffer boundedBuffer
	input := bytes.Repeat([]byte("x"), maxSendmailOutput+5)
	written, err := buffer.Write(input)
	if err != nil || written != len(input) || !bytes.Contains(buffer.Bytes(), []byte("truncated")) {
		t.Fatal(written, err)
	}
	if written, err := buffer.Write([]byte("more")); err != nil || written != 4 {
		t.Fatal(written, err)
	}
	if id, err := randomMessageID(); err != nil || !strings.HasPrefix(id, "dweb-mag-") {
		t.Fatal(id, err)
	}
	if normalizeBody("a\rb\r\nc\nd") != "a\r\nb\r\nc\r\nd" {
		t.Fatal("body normalization")
	}
}

func TestExecMessageRunnerFailure(t *testing.T) {
	if _, err := (execMessageRunner{}).Run(context.Background(), "definitely-not-a-command", nil, nil); err == nil {
		t.Fatal("missing command accepted")
	}
}
