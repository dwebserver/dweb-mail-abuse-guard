// Package report produces periodic health summaries and maintains the durable
// heartbeat used to detect an unclean service stop on the next startup.
package report

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/dwebserver/dweb-mail-abuse-guard/internal/config"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/event"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/policy"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/store"
)

const (
	heartbeatInterval = time.Minute
	reportRetry       = 15 * time.Minute
)

type State interface {
	RecentEvents(time.Time) ([]event.Event, error)
	Incidents() ([]store.Incident, error)
	Heartbeat(time.Time) error
}

type Mailer interface {
	SendMessage(context.Context, string, string) error
}

type Reporter struct {
	state          State
	mailer         Mailer
	mode           config.Mode
	hostname       string
	version        string
	startedAt      time.Time
	hour           int
	minute         int
	timeout        time.Duration
	logger         *slog.Logger
	heartbeatEvery time.Duration
	retryEvery     time.Duration
	nextReport     func(time.Time, int, int) time.Time
}

func New(state State, mailer Mailer, mode config.Mode, hostname, version string, startedAt time.Time, hour, minute int, timeout time.Duration, logger *slog.Logger) *Reporter {
	if logger == nil {
		logger = slog.Default()
	}
	return &Reporter{state: state, mailer: mailer, mode: mode, hostname: hostname, version: version, startedAt: startedAt, hour: hour, minute: minute, timeout: timeout, logger: logger, heartbeatEvery: heartbeatInterval, retryEvery: reportRetry, nextReport: NextDaily}
}

func (r *Reporter) Send(ctx context.Context) error {
	now := time.Now().UTC()
	since := now.Add(-24 * time.Hour)
	events, err := r.state.RecentEvents(since)
	if err != nil {
		return fmt.Errorf("read events for daily report: %w", err)
	}
	incidents, err := r.state.Incidents()
	if err != nil {
		return fmt.Errorf("read incidents for daily report: %w", err)
	}

	counts := make(map[event.Kind]int)
	for _, item := range events {
		counts[item.Kind]++
	}
	warnings, containments, failures := 0, 0, 0
	for _, item := range incidents {
		if item.CreatedAt.Before(since) || item.CreatedAt.After(now) {
			continue
		}
		switch item.Decision.Severity {
		case policy.Warning:
			warnings++
		case policy.Contain:
			containments++
		}
		if item.Status == store.IncidentFailed {
			failures++
		}
	}

	result := "No suspicious email activity was detected during the last 24 hours."
	if warnings+containments > 0 {
		result = fmt.Sprintf("Suspicious activity was detected: %d warning incident(s) and %d containment incident(s).", warnings, containments)
	}
	body := fmt.Sprintf(`DWEB Mail Abuse Guard daily health report

Server: %s
Version: %s
Mode: %s
Service status: running
Current process started: %s
Reporting period: %s to %s (UTC)

Result: %s

Events processed:
- authenticated submissions: %d
- authentication successes: %d
- authentication failures: %d
- provider abuse rejections: %d

Incidents:
- warnings: %d
- containment decisions: %d
- failed containment actions: %d

This message is generated automatically once per day to confirm that the monitoring service is operating.
`, r.hostname, r.version, r.mode, r.startedAt.UTC().Format(time.RFC3339), since.Format(time.RFC3339), now.Format(time.RFC3339), result, counts[event.Submission], counts[event.AuthSuccess], counts[event.AuthFailure], counts[event.ProviderRejection], warnings, containments, failures)
	return r.mailer.SendMessage(ctx, "[DWEB Mail Guard] Daily health report for "+sanitizeSubject(r.hostname), body)
}

// Run maintains a durable heartbeat and sends one report at the configured UTC
// time. Failed report delivery is retried without restarting the detector.
func (r *Reporter) Run(ctx context.Context) error {
	heartbeat := time.NewTicker(r.heartbeatEvery)
	defer heartbeat.Stop()
	next := r.nextReport(time.Now().UTC(), r.hour, r.minute)
	reportTimer := time.NewTimer(time.Until(next))
	defer reportTimer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-heartbeat.C:
			if err := r.state.Heartbeat(now.UTC()); err != nil {
				return fmt.Errorf("persist service heartbeat: %w", err)
			}
		case <-reportTimer.C:
			reportCtx, cancel := context.WithTimeout(ctx, r.timeout)
			err := r.Send(reportCtx)
			cancel()
			if err != nil {
				r.logger.Error("daily health report failed", "error", err)
				reportTimer.Reset(r.retryEvery)
				continue
			}
			r.logger.Info("daily health report sent")
			next = r.nextReport(time.Now().UTC(), r.hour, r.minute)
			reportTimer.Reset(time.Until(next))
		}
	}
}

func NextDaily(now time.Time, hour, minute int) time.Time {
	now = now.UTC()
	next := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, time.UTC)
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	return next
}

func sanitizeSubject(value string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(value)
}
