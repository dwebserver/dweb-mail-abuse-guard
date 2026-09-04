package event

import (
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	t.Parallel()
	valid := Event{Time: time.Now(), Kind: Submission, Mailbox: "a@example.com", SourceIP: "192.0.2.1", RecipientCount: 1, Source: "exim"}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	tests := []Event{
		{},
		{Time: time.Now(), Kind: Kind("unknown"), Source: "x"},
		{Time: time.Now(), Kind: AuthSuccess, Mailbox: "bad", Source: "x"},
		{Time: time.Now(), Kind: ProviderRejection, Source: "x"},
		{Time: time.Now(), Kind: ProviderRejection, Mailbox: "bad", Source: "x"},
		{Time: time.Now(), Kind: ProviderRejection, MessageID: "id", SourceIP: "bad", Source: "x"},
		{Time: time.Now(), Kind: Submission, Mailbox: "a@example.com", RecipientCount: -1, Source: "x"},
		{Time: time.Now(), Kind: Submission, Mailbox: "a@example.com"},
	}
	for index, item := range tests {
		if err := item.Validate(); err == nil {
			t.Errorf("case %d should fail", index)
		}
	}
	rejection := Event{Time: time.Now(), Kind: ProviderRejection, MessageID: "abc", Source: "exim"}
	if err := rejection.Validate(); err != nil {
		t.Fatal(err)
	}
}
