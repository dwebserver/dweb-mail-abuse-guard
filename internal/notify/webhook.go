// Package notify sends optional, non-blocking incident notifications.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/dwebserver/dweb-mail-abuse-guard/internal/store"
)

const maxResponseBody = 64 * 1024

type Sender interface {
	Send(ctx context.Context, incident store.Incident) error
}

type Noop struct{}

func (Noop) Send(context.Context, store.Incident) error { return nil }

type Webhook struct {
	client *http.Client
	url    string
}

// NewWebhook reads a URL from a root-managed file so secrets never appear in
// the world-readable service configuration or process arguments.
func NewWebhook(path string, timeout time.Duration) (*Webhook, error) {
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read webhook URL: %w", err)
	}
	rawURL := strings.TrimSpace(string(value))
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return nil, fmt.Errorf("webhook URL must be an HTTPS URL without embedded credentials")
	}
	return &Webhook{client: &http.Client{Timeout: timeout}, url: rawURL}, nil
}

func (w *Webhook) Send(ctx context.Context, incident store.Incident) error {
	payload, err := json.Marshal(incident)
	if err != nil {
		return fmt.Errorf("encode webhook payload: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create webhook request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "dweb-mail-abuse-guard")
	response, err := w.client.Do(request)
	if err != nil {
		return fmt.Errorf("send webhook: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBody))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", response.StatusCode)
	}
	return nil
}
