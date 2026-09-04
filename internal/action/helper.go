// Package action invokes the privileged helper without a shell.
package action

import (
	"context"
	"fmt"
	"time"

	"github.com/dwebserver/dweb-mail-abuse-guard/internal/platform"
)

type Helper struct {
	runner  platform.Runner
	path    string
	prefix  []string
	timeout time.Duration
}

func NewHelper(runner platform.Runner, path string, prefix []string, timeout time.Duration) *Helper {
	return &Helper{runner: runner, path: path, prefix: append([]string(nil), prefix...), timeout: timeout}
}

func (h *Helper) Contain(ctx context.Context, mailbox, incidentID string) error {
	callCtx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	arguments := append(append([]string(nil), h.prefix...), "contain", "--mailbox", mailbox, "--incident", incidentID)
	_, err := h.runner.Run(callCtx, h.path, arguments...)
	if err != nil {
		return fmt.Errorf("contain mailbox: %w", err)
	}
	return nil
}

func (h *Helper) Release(ctx context.Context, mailbox, incidentID string) error {
	callCtx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	arguments := append(append([]string(nil), h.prefix...), "release", "--mailbox", mailbox, "--incident", incidentID)
	_, err := h.runner.Run(callCtx, h.path, arguments...)
	if err != nil {
		return fmt.Errorf("release mailbox: %w", err)
	}
	return nil
}
