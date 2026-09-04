package identity

import "testing"

func TestNormalizeMailbox(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  string
		ok    bool
	}{
		{" User.Name+tag@Example.COM ", "user.name+tag@example.com", true},
		{"x@example.com", "x@example.com", true},
		{"", "", false}, {"missing-at.example.com", "", false},
		{"a@@example.com", "", false}, {".a@example.com", "", false},
		{"a..b@example.com", "", false}, {"a@-example.com", "", false},
		{"a@example", "", false}, {"a@example.com\n--flag", "", false},
		{string(make([]byte, 255)), "", false},
	}
	for _, test := range tests {
		got, err := NormalizeMailbox(test.input)
		if (err == nil) != test.ok || got != test.want {
			t.Errorf("NormalizeMailbox(%q) = %q, %v", test.input, got, err)
		}
	}
}

func TestDomain(t *testing.T) {
	t.Parallel()
	got, err := Domain("User@Example.com")
	if err != nil || got != "example.com" {
		t.Fatalf("Domain() = %q, %v", got, err)
	}
	if _, err := Domain("invalid"); err == nil {
		t.Fatal("expected invalid mailbox error")
	}
}
