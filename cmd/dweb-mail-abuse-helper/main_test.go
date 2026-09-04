package main

import "testing"

func TestRejectsInvalidInvocation(t *testing.T) {
	for _, arguments := range [][]string{
		nil,
		{"unknown"},
		{"contain", "--mailbox", "bad", "--incident", "bad"},
		{"contain", "--mailbox", "a@example.com", "--incident", "../../bad"},
		{"release", "--mailbox", "a@example.com", "--incident", "mag-20260904t103045z-1234567890abcdef", "extra"},
	} {
		if err := run(arguments); err == nil {
			t.Errorf("accepted %#v", arguments)
		}
	}
}
