// Package identity validates identities that cross the privilege boundary.
package identity

import (
	"fmt"
	"strings"
	"unicode"
)

const maxMailboxLength = 254

// NormalizeMailbox returns a canonical mailbox identity suitable for policy
// keys and privileged actions. It deliberately accepts a conservative subset
// of RFC 5322 because cPanel mailbox names do not need comments, display names,
// quoted local parts, or internationalized domains.
func NormalizeMailbox(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxMailboxLength {
		return "", fmt.Errorf("mailbox length is invalid")
	}
	if strings.ContainsAny(value, "\r\n\x00") {
		return "", fmt.Errorf("mailbox contains a control character")
	}

	local, domain, found := strings.Cut(value, "@")
	if !found || local == "" || domain == "" || strings.Contains(domain, "@") {
		return "", fmt.Errorf("mailbox must contain one @ separator")
	}
	if len(local) > 64 || !validLocalPart(local) || !validDomain(domain) {
		return "", fmt.Errorf("mailbox syntax is invalid")
	}
	return strings.ToLower(local + "@" + domain), nil
}

func validLocalPart(local string) bool {
	if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return false
	}
	const specials = "!#$%&'*+-/=?^_`{|}~."
	for _, r := range local {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune(specials, r) {
			continue
		}
		return false
	}
	return true
}

func validDomain(domain string) bool {
	if len(domain) > 253 || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

// Domain returns the canonical domain part of a validated mailbox.
func Domain(mailbox string) (string, error) {
	normalized, err := NormalizeMailbox(mailbox)
	if err != nil {
		return "", err
	}
	_, domain, _ := strings.Cut(normalized, "@")
	return domain, nil
}
