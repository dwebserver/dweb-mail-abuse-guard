package parser

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/dwebserver/dweb-mail-abuse-guard/internal/event"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/identity"
)

var (
	dovecotUserPattern = regexp.MustCompile(`user=<([^>]+)>`)
	dovecotIPPattern   = regexp.MustCompile(`(?:^|, )rip=([^, ]+)`)
)

// Dovecot parses traditional syslog output from Dovecot login services.
type Dovecot struct{}

func (Dovecot) Parse(line string, now time.Time) (event.Event, bool, error) {
	kind, relevant := dovecotKind(line)
	if !relevant {
		return event.Event{}, false, nil
	}
	userMatch := dovecotUserPattern.FindStringSubmatch(line)
	if len(userMatch) != 2 {
		return event.Event{}, true, fmt.Errorf("Dovecot event is missing user identity")
	}
	mailbox, err := identity.NormalizeMailbox(userMatch[1])
	if err != nil {
		return event.Event{}, true, fmt.Errorf("Dovecot user identity: %w", err)
	}
	when, err := parseSyslogTime(line, now)
	if err != nil {
		return event.Event{}, true, err
	}
	sourceIP := ""
	if match := dovecotIPPattern.FindStringSubmatch(line); len(match) == 2 && net.ParseIP(match[1]) != nil {
		sourceIP = match[1]
	}
	parsed := event.Event{
		Time:     when,
		Kind:     kind,
		Mailbox:  mailbox,
		SourceIP: sourceIP,
		Source:   "dovecot",
	}
	return parsed, true, parsed.Validate()
}

func dovecotKind(line string) (event.Kind, bool) {
	lower := strings.ToLower(line)
	if !strings.Contains(lower, "dovecot") || !strings.Contains(lower, "-login:") {
		return "", false
	}
	if strings.Contains(lower, "auth failed") {
		return event.AuthFailure, true
	}
	if strings.Contains(line, "-login: Login:") {
		return event.AuthSuccess, true
	}
	return "", false
}

func parseSyslogTime(line string, now time.Time) (time.Time, error) {
	if len(line) < 15 {
		return time.Time{}, fmt.Errorf("syslog timestamp is incomplete")
	}
	stamp := strings.Join(strings.Fields(line[:15]), " ")
	parsed, err := time.ParseInLocation("Jan 2 15:04:05", stamp, now.Location())
	if err != nil {
		return time.Time{}, fmt.Errorf("parse syslog timestamp: %w", err)
	}
	parsed = parsed.AddDate(now.Year(), 0, 0)
	if parsed.After(now.Add(24 * time.Hour)) {
		parsed = parsed.AddDate(-1, 0, 0)
	}
	return parsed, nil
}
