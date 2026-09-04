package notify

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dwebserver/dweb-mail-abuse-guard/internal/store"
)

func TestNewWebhookValidation(t *testing.T) {
	if _, err := NewWebhook(filepath.Join(t.TempDir(), "missing"), time.Second); err == nil {
		t.Fatal("missing URL file accepted")
	}
	for _, value := range []string{"http://example.com", "https://user:pass@example.com", "://bad", "https:///missing-host"} {
		path := filepath.Join(t.TempDir(), "url")
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewWebhook(path, time.Second); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
	path := filepath.Join(t.TempDir(), "url")
	_ = os.WriteFile(path, []byte("https://example.com/hook\n"), 0o600)
	got, err := NewWebhook(path, 2*time.Second)
	if err != nil || got.url != "https://example.com/hook" || got.client.Timeout != 2*time.Second {
		t.Fatal(got, err)
	}
}

func TestWebhookSend(t *testing.T) {
	var body string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value, _ := io.ReadAll(r.Body)
		body = string(value)
		if r.Header.Get("Content-Type") != "application/json" || !strings.HasPrefix(r.UserAgent(), "dweb-mail-abuse-guard") {
			t.Error("headers")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	hook := &Webhook{client: server.Client(), url: server.URL}
	incident := store.Incident{ID: "id", Mailbox: "a@example.com"}
	if err := hook.Send(context.Background(), incident); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, `"mailbox":"a@example.com"`) {
		t.Fatal(body)
	}
	if err := (Noop{}).Send(context.Background(), incident); err != nil {
		t.Fatal(err)
	}
}

func TestWebhookHTTPFailure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", http.StatusBadGateway) }))
	defer server.Close()
	hook := &Webhook{client: server.Client(), url: server.URL}
	if err := hook.Send(context.Background(), store.Incident{}); err == nil {
		t.Fatal("HTTP error hidden")
	}
	hook.url = "://bad"
	if err := hook.Send(context.Background(), store.Incident{}); err == nil {
		t.Fatal("request error hidden")
	}
}
