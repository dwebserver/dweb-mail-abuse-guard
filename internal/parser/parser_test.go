package parser

import (
	"testing"
	"time"

	"github.com/dwebserver/dweb-mail-abuse-guard/internal/event"
)

func TestEximSubmission(t *testing.T) {
	t.Parallel()
	line := "2026-09-03 10:38:12 1xExample-000001 <= sender@example.com H=(DESKTOP) [192.0.2.10]:62496 P=esmtpsa X=TLS A=dovecot_login:sender@example.com S=1234 for one@example.com two@example.net"
	got, ok, err := (Exim{}).Parse(line, time.Time{})
	if err != nil || !ok {
		t.Fatalf("Parse() = %#v, %v, %v", got, ok, err)
	}
	if got.Kind != event.Submission || got.Mailbox != "sender@example.com" || got.SourceIP != "192.0.2.10" || got.RecipientCount != 2 || got.MessageID != "1xExample-000001" {
		t.Fatalf("unexpected event: %#v", got)
	}
}

func TestEximCases(t *testing.T) {
	t.Parallel()
	parser := Exim{}
	tests := []struct {
		line string
		ok   bool
		err  bool
		kind event.Kind
	}{
		{"short", false, false, ""},
		{"not-a-date but long enough", false, false, ""},
		{"2026-09-03 10:38:12 id <= a@example.com H=x P=local", false, false, ""},
		{"2026-09-03 10:38:12 id <= a@example.com P=esmtpa X=none", true, true, ""},
		{"2026-09-03 10:38:12 id <= a@example.com H=[192.0.2.1]:25 P=esmtpa A=plain:bad for x@example.com", true, true, ""},
		{"2026-09-03 10:38:12 ABC123 ** x@gmail.com SMTP error from remote mail server: 550 5.7.1 unsolicited email JFE050003", true, false, event.ProviderRejection},
		{"2026-09-03 10:38:12", false, false, ""},
	}
	for index, test := range tests {
		got, ok, err := parser.Parse(test.line, time.Time{})
		if ok != test.ok || (err != nil) != test.err || (test.kind != "" && got.Kind != test.kind) {
			t.Errorf("case %d = %#v, %v, %v", index, got, ok, err)
		}
	}
}

func TestEximHelpers(t *testing.T) {
	t.Parallel()
	if countRecipients("anything without marker") != 0 || countRecipients("x for a@example.com invalid") != 1 {
		t.Fatal("recipient counting failed")
	}
	if !isProviderAbuseRejection("SMTP error from remote mail server: low reputation") || isProviderAbuseRejection("ordinary message") {
		t.Fatal("provider rejection classification failed")
	}
	if value, err := parsePositiveInt("4"); err != nil || value != 4 {
		t.Fatal("integer parsing failed")
	}
	if _, err := parsePositiveInt("-1"); err == nil {
		t.Fatal("negative integer should fail")
	}
}

func TestDovecot(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.January, 1, 0, 0, 10, 0, time.Local)
	tests := []struct {
		line string
		ok   bool
		err  bool
		kind event.Kind
	}{
		{"Jan  1 00:00:01 host dovecot: imap-login: Login: user=<User@Example.com>, method=PLAIN, rip=192.0.2.8, lip=192.0.2.1", true, false, event.AuthSuccess},
		{"Dec 31 23:59:59 host dovecot: pop3-login: Disconnected: Connection closed (auth failed, 1 attempts): user=<user@example.com>, rip=2001:db8::1, lip=192.0.2.1", true, false, event.AuthFailure},
		{"Jan  1 00:00:01 host postfix: hello", false, false, ""},
		{"Jan  1 00:00:01 host dovecot: imap-login: Auth failed", true, true, ""},
		{"bad timestamp__ host dovecot: imap-login: Login: user=<a@example.com>", true, true, ""},
	}
	for index, test := range tests {
		got, ok, err := (Dovecot{}).Parse(test.line, now)
		if ok != test.ok || (err != nil) != test.err || (test.kind != "" && got.Kind != test.kind) {
			t.Errorf("case %d = %#v, %v, %v", index, got, ok, err)
		}
		if index == 1 && got.Time.Year() != 2025 {
			t.Errorf("year rollover = %v", got.Time)
		}
	}
}
