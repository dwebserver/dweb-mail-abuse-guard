package parser

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dwebserver/dweb-mail-abuse-guard/internal/event"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/identity"
)

var (
	eximAuthPattern = regexp.MustCompile(`(?:^| )A=[^: ]+:([^ ]+)`)
	eximIPPattern   = regexp.MustCompile(`\[([0-9A-Fa-f:.]+)\]:[0-9]+`)
	eximCodePattern = regexp.MustCompile(`\b([45][0-9]{2} [245]\.[0-9]\.[0-9]{1,3})\b`)
)

// Exim parses cPanel-style Exim mainlog records.
type Exim struct{}

func (Exim) Parse(line string, _ time.Time) (event.Event, bool, error) {
	if len(line) < 20 {
		return event.Event{}, false, nil
	}
	when, err := time.ParseInLocation("2006-01-02 15:04:05", line[:19], time.UTC)
	if err != nil {
		return event.Event{}, false, nil
	}

	if strings.Contains(line, " <= ") && isAuthenticatedSMTP(line) {
		return parseEximSubmission(line, when)
	}
	if isProviderAbuseRejection(line) {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			return event.Event{}, true, fmt.Errorf("provider rejection is missing a message ID")
		}
		code := "provider-abuse"
		if match := eximCodePattern.FindStringSubmatch(line); len(match) == 2 {
			code = match[1]
		}
		return event.Event{
			Time:      when,
			Kind:      event.ProviderRejection,
			MessageID: fields[2],
			Code:      code,
			Source:    "exim",
		}, true, nil
	}
	return event.Event{}, false, nil
}

func isAuthenticatedSMTP(line string) bool {
	return strings.Contains(line, " P=esmtpa ") || strings.Contains(line, " P=esmtpsa ")
}

func parseEximSubmission(line string, when time.Time) (event.Event, bool, error) {
	fields := strings.Fields(line)
	if len(fields) < 6 {
		return event.Event{}, true, fmt.Errorf("submission line is incomplete")
	}
	auth := eximAuthPattern.FindStringSubmatch(line)
	if len(auth) != 2 {
		return event.Event{}, true, fmt.Errorf("submission line is missing authenticated identity")
	}
	mailbox, err := identity.NormalizeMailbox(auth[1])
	if err != nil {
		return event.Event{}, true, fmt.Errorf("authenticated identity: %w", err)
	}

	sourceIP := ""
	if match := eximIPPattern.FindStringSubmatch(line); len(match) == 2 && net.ParseIP(match[1]) != nil {
		sourceIP = match[1]
	}
	recipients := countRecipients(line)
	sender := fields[4]
	if normalized, normalizeErr := identity.NormalizeMailbox(sender); normalizeErr == nil {
		sender = normalized
	}

	parsed := event.Event{
		Time:           when,
		Kind:           event.Submission,
		Mailbox:        mailbox,
		SourceIP:       sourceIP,
		MessageID:      fields[2],
		EnvelopeSender: sender,
		RecipientCount: recipients,
		Source:         "exim",
	}
	return parsed, true, parsed.Validate()
}

func countRecipients(line string) int {
	index := strings.LastIndex(line, " for ")
	if index < 0 {
		return 0
	}
	count := 0
	for _, candidate := range strings.Fields(line[index+5:]) {
		candidate = strings.Trim(candidate, "<>,;")
		if _, err := identity.NormalizeMailbox(candidate); err == nil {
			count++
		}
	}
	return count
}

func isProviderAbuseRejection(line string) bool {
	lower := strings.ToLower(line)
	if !strings.Contains(lower, "smtp error from remote mail server") {
		return false
	}
	indicators := []string{
		"unsolicited email",
		"probability of spam",
		"low reputation",
		"jfe050003",
		"message is likely suspicious",
	}
	for _, indicator := range indicators {
		if strings.Contains(lower, indicator) {
			return true
		}
	}
	return false
}

// parsePositiveInt is kept local to the parser package for future Exim fields.
func parsePositiveInt(value string) (int, error) {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return 0, fmt.Errorf("invalid non-negative integer")
	}
	return parsed, nil
}
