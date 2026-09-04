// Package cpanel implements mailbox-scoped cPanel containment actions.
package cpanel

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/dwebserver/dweb-mail-abuse-guard/internal/identity"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/platform"
)

var (
	ownerPattern   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$`)
	queueIDPattern = regexp.MustCompile(`^[A-Za-z0-9-]{6,64}$`)
	queueLine      = regexp.MustCompile(`(?m)^\s*\S+\s+\S+\s+([A-Za-z0-9-]+)\s+<([^>]*)>`)
)

type Paths struct {
	WhoOwns string
	UAPI    string
	Doveadm string
	Exim    string
}

func DefaultPaths() Paths {
	return Paths{
		WhoOwns: "/usr/local/cpanel/scripts/whoowns",
		UAPI:    "/usr/local/cpanel/bin/uapi",
		Doveadm: "/usr/bin/doveadm",
		Exim:    "/usr/sbin/exim",
	}
}

type Controller struct {
	runner platform.Runner
	paths  Paths
}

func New(runner platform.Runner, paths Paths) *Controller {
	return &Controller{runner: runner, paths: paths}
}

type Result struct {
	Mailbox        string   `json:"mailbox"`
	Owner          string   `json:"owner"`
	FrozenQueueIDs []string `json:"frozen_queue_ids,omitempty"`
}

// Contain disables new authenticated access and outgoing delivery, terminates
// mailbox sessions, and freezes queued messages with the exact envelope sender.
func (c *Controller) Contain(ctx context.Context, mailbox string) (Result, error) {
	mailbox, owner, err := c.resolve(ctx, mailbox)
	if err != nil {
		return Result{}, err
	}
	if err := c.uapi(ctx, owner, "suspend_login", mailbox); err != nil {
		return Result{}, err
	}
	if err := c.uapi(ctx, owner, "suspend_outgoing", mailbox); err != nil {
		return Result{}, err
	}
	if _, err := c.runner.Run(ctx, c.paths.Doveadm, "kick", mailbox); err != nil {
		return Result{}, fmt.Errorf("terminate Dovecot sessions: %w", err)
	}
	ids, err := c.freezeQueue(ctx, mailbox)
	if err != nil {
		return Result{}, err
	}
	return Result{Mailbox: mailbox, Owner: owner, FrozenQueueIDs: ids}, nil
}

// Release restores login and outgoing mail. Frozen messages remain frozen so
// an administrator can review them before any delivery is attempted.
func (c *Controller) Release(ctx context.Context, mailbox string) (Result, error) {
	mailbox, owner, err := c.resolve(ctx, mailbox)
	if err != nil {
		return Result{}, err
	}
	if err := c.uapi(ctx, owner, "unsuspend_outgoing", mailbox); err != nil {
		return Result{}, err
	}
	if err := c.uapi(ctx, owner, "unsuspend_login", mailbox); err != nil {
		return Result{}, err
	}
	return Result{Mailbox: mailbox, Owner: owner}, nil
}

func (c *Controller) resolve(ctx context.Context, mailbox string) (string, string, error) {
	mailbox, err := identity.NormalizeMailbox(mailbox)
	if err != nil {
		return "", "", err
	}
	domain, _ := identity.Domain(mailbox)
	output, err := c.runner.Run(ctx, c.paths.WhoOwns, domain)
	if err != nil {
		return "", "", fmt.Errorf("resolve cPanel owner: %w", err)
	}
	owner := strings.TrimSpace(string(output))
	if !ownerPattern.MatchString(owner) {
		return "", "", fmt.Errorf("cPanel returned an invalid owner")
	}
	if err := c.verifyMailbox(ctx, owner, mailbox); err != nil {
		return "", "", err
	}
	return mailbox, owner, nil
}

func (c *Controller) verifyMailbox(ctx context.Context, owner, mailbox string) error {
	output, err := c.runner.Run(ctx, c.paths.UAPI, "--user="+owner, "--output=json", "Email", "list_pops")
	if err != nil {
		return fmt.Errorf("list cPanel mailboxes: %w", err)
	}
	var response struct {
		Result struct {
			Status int `json:"status"`
			Data   []struct {
				Email string `json:"email"`
			} `json:"data"`
			Errors []string `json:"errors"`
		} `json:"result"`
	}
	if err := json.Unmarshal(output, &response); err != nil {
		return fmt.Errorf("decode cPanel mailbox list: %w", err)
	}
	if response.Result.Status != 1 {
		return fmt.Errorf("cPanel mailbox list failed: %s", strings.Join(response.Result.Errors, "; "))
	}
	for _, candidate := range response.Result.Data {
		if strings.EqualFold(candidate.Email, mailbox) {
			return nil
		}
	}
	return fmt.Errorf("mailbox is not owned by the resolved cPanel account")
}

func (c *Controller) uapi(ctx context.Context, owner, function, mailbox string) error {
	output, err := c.runner.Run(
		ctx,
		c.paths.UAPI,
		"--user="+owner,
		"--output=json",
		"Email",
		function,
		"email="+mailbox,
	)
	if err != nil {
		return fmt.Errorf("cPanel %s: %w", function, err)
	}
	var response struct {
		Result struct {
			Status int      `json:"status"`
			Errors []string `json:"errors"`
		} `json:"result"`
	}
	if err := json.Unmarshal(output, &response); err != nil {
		return fmt.Errorf("decode cPanel %s response: %w", function, err)
	}
	if response.Result.Status != 1 {
		return fmt.Errorf("cPanel %s failed: %s", function, strings.Join(response.Result.Errors, "; "))
	}
	return nil
}

func (c *Controller) freezeQueue(ctx context.Context, mailbox string) ([]string, error) {
	output, err := c.runner.Run(ctx, c.paths.Exim, "-bp")
	if err != nil {
		return nil, fmt.Errorf("list Exim queue: %w", err)
	}
	ids, err := queueIDsForSender(output, mailbox)
	if err != nil {
		return nil, err
	}
	for start := 0; start < len(ids); start += 100 {
		end := min(start+100, len(ids))
		arguments := append([]string{"-Mf"}, ids[start:end]...)
		if _, err := c.runner.Run(ctx, c.paths.Exim, arguments...); err != nil {
			return nil, fmt.Errorf("freeze Exim queue: %w", err)
		}
	}
	return ids, nil
}

func queueIDsForSender(output []byte, mailbox string) ([]string, error) {
	mailbox, err := identity.NormalizeMailbox(mailbox)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, match := range queueLine.FindAllSubmatch(output, -1) {
		id, sender := string(match[1]), string(match[2])
		if !strings.EqualFold(sender, mailbox) {
			continue
		}
		if !queueIDPattern.MatchString(id) {
			return nil, fmt.Errorf("Exim returned an invalid queue ID")
		}
		ids = append(ids, id)
	}
	return ids, nil
}
