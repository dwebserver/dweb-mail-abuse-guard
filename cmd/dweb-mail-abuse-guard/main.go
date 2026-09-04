// dweb-mail-abuse-guard detects compromised mailboxes from local mail logs.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"github.com/dwebserver/dweb-mail-abuse-guard/internal/action"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/config"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/control"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/follow"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/notify"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/parser"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/platform"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/policy"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/report"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/service"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/store"
)

var version = "development"

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("dweb-mail-abuse-guard stopped", "error", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		arguments = []string{"run"}
	}
	switch arguments[0] {
	case "run":
		return runDaemon(arguments[1:])
	case "validate-config":
		return validateConfig(arguments[1:])
	case "replay":
		return replay(arguments[1:])
	case "version":
		fmt.Println(version)
		return nil
	default:
		return fmt.Errorf("unknown command %q", arguments[0])
	}
}

func validateConfig(arguments []string) error {
	flags := flag.NewFlagSet("validate-config", flag.ContinueOnError)
	path := flags.String("config", "/etc/dweb-mail-abuse-guard/config.yml", "configuration file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	_, err := config.Load(*path)
	if err == nil {
		fmt.Println("configuration is valid")
	}
	return err
}

func runDaemon(arguments []string) (resultErr error) {
	var operationalMailer *notify.Email
	var hostname string
	var panicDetail string
	defer func() {
		if recovered := recover(); recovered != nil {
			stack := string(debug.Stack())
			panicDetail = fmt.Sprintf("Panic: %v\n\nStack:\n%s", recovered, stack)
			resultErr = fmt.Errorf("unexpected panic: %v", recovered)
		}
		if resultErr != nil && operationalMailer != nil {
			detail := fmt.Sprintf("Error: %v", resultErr)
			subject := "[DWEB Mail Guard] Service failure"
			if panicDetail != "" {
				detail = panicDetail
				subject = "[DWEB Mail Guard] Service panic"
			}
			alertCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := operationalMailer.SendMessage(alertCtx, subject, fmt.Sprintf("The monitoring service on %s stopped because of a fatal error. Systemd is configured to restart it.\n\n%s\nTime: %s\n", hostname, detail, time.Now().UTC().Format(time.RFC3339))); err != nil {
				slog.Error("service failure email failed", "error", err)
			}
			cancel()
		}
	}()

	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	path := flags.String("config", "/etc/dweb-mail-abuse-guard/config.yml", "configuration file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	hostname, err = os.Hostname()
	if err != nil {
		return fmt.Errorf("read server hostname: %w", err)
	}
	if cfg.Notification.EmailTo != "" {
		operationalMailer = notify.NewEmail(cfg.Notification.SendmailPath, cfg.Notification.EmailTo, cfg.Notification.EmailFrom, hostname)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.StatePath), 0o750); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	database, err := store.Open(cfg.StatePath, false)
	if err != nil {
		return err
	}
	defer database.Close()
	seed, err := database.RecentEvents(time.Now().UTC().Add(-time.Hour))
	if err != nil {
		return err
	}
	startedAt := time.Now().UTC()
	previous, previousFound, err := database.BeginRun(startedAt)
	if err != nil {
		return err
	}
	engine := policy.NewEngine(cfg, seed)
	helper := action.NewHelper(platform.ExecRunner{}, cfg.Actions.HelperPath, cfg.Actions.HelperArgs, cfg.Actions.Timeout)
	channels := make(notify.Multi, 0, 2)
	if cfg.Notification.WebhookURLFile != "" {
		webhook, webhookErr := notify.NewWebhook(cfg.Notification.WebhookURLFile, cfg.Notification.Timeout)
		err = webhookErr
		if err != nil {
			return err
		}
		channels = append(channels, webhook)
	}
	if operationalMailer != nil {
		channels = append(channels, operationalMailer)
	}
	var sender notify.Sender = notify.Noop{}
	if len(channels) > 0 {
		sender = channels
	}
	handler := service.New(cfg, engine, database, helper, sender, slog.Default())
	controlServer := control.NewServer(cfg.Mode, database, helper)
	components := []func(context.Context) error{
		func(componentCtx context.Context) error { return followSources(componentCtx, cfg, database, handler) },
		func(componentCtx context.Context) error { return controlServer.Serve(componentCtx, cfg.ControlSocket) },
	}
	if operationalMailer != nil {
		reporter := report.New(database, operationalMailer, cfg.Mode, hostname, version, startedAt, cfg.Notification.DailyHour, cfg.Notification.DailyMinute, cfg.Notification.Timeout, slog.Default())
		controlServer.SetReporter(reporter)
		components = append(components, reporter.Run)
		if previousFound && !previous.CleanShutdown {
			alertCtx, cancel := context.WithTimeout(context.Background(), cfg.Notification.Timeout)
			err := operationalMailer.SendMessage(alertCtx, "[DWEB Mail Guard] Service recovered after an unclean stop", fmt.Sprintf("The monitoring service is running again on %s. Its previous run did not record a clean shutdown.\n\nPrevious start: %s\nLast recorded heartbeat: %s\nCurrent start: %s\n", hostname, previous.StartedAt.UTC().Format(time.RFC3339), previous.HeartbeatAt.UTC().Format(time.RFC3339), startedAt.Format(time.RFC3339)))
			cancel()
			if err != nil {
				slog.Error("unclean-stop recovery email failed", "error", err)
			}
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	slog.Info("mail abuse guard started", "version", version, "mode", cfg.Mode, "sources", len(cfg.Sources))
	resultErr = runComponents(ctx, components...)
	if resultErr != nil {
		return resultErr
	}
	if err := database.EndRun(time.Now().UTC()); err != nil {
		return fmt.Errorf("record clean service shutdown: %w", err)
	}
	return nil
}

func runComponents(ctx context.Context, components ...func(context.Context) error) error {
	if len(components) == 0 {
		return fmt.Errorf("at least one service component is required")
	}
	componentCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, len(components))
	for _, component := range components {
		component := component
		go func() { results <- component(componentCtx) }()
	}
	first := <-results
	cancel()
	for range len(components) - 1 {
		other := <-results
		if first == nil && other != nil {
			first = other
		}
	}
	return first
}

func followSources(ctx context.Context, cfg config.Config, database *store.Bolt, handler *service.Service) error {
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errorsChannel := make(chan error, len(cfg.Sources))
	var waitGroup sync.WaitGroup
	for _, source := range cfg.Sources {
		source := source
		lineParser, err := parserFor(source.Kind)
		if err != nil {
			return err
		}
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			err := follow.Run(childCtx, follow.Options{Path: source.Path, StartAtEnd: source.StartAtEnd, Poll: cfg.PollInterval}, database, func(line string) error {
				item, ok, parseErr := lineParser.Parse(line, time.Now())
				if parseErr != nil {
					slog.Warn("ignored malformed relevant log line", "source", source.Path, "error", parseErr)
					return nil
				}
				if !ok {
					return nil
				}
				_, handleErr := handler.Handle(childCtx, item)
				return handleErr
			})
			if err != nil {
				errorsChannel <- fmt.Errorf("follow %s: %w", source.Path, err)
			}
		}()
	}
	pruneTicker := time.NewTicker(time.Hour)
	defer pruneTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			cancel()
			waitGroup.Wait()
			return nil
		case err := <-errorsChannel:
			cancel()
			waitGroup.Wait()
			return err
		case now := <-pruneTicker.C:
			if err := database.PruneEvents(now.UTC().Add(-cfg.Retention)); err != nil {
				slog.Error("event retention failed", "error", err)
			}
		}
	}
}

type replayResult struct {
	Lines            int              `json:"lines"`
	Events           int              `json:"events"`
	Warnings         int              `json:"warnings"`
	Containments     int              `json:"containments"`
	FirstContainment *policy.Decision `json:"first_containment,omitempty"`
}

func replay(arguments []string) error {
	flags := flag.NewFlagSet("replay", flag.ContinueOnError)
	configPath := flags.String("config", "", "configuration file")
	kind := flags.String("kind", "exim", "log parser: exim or dovecot")
	path := flags.String("path", "", "log file to replay")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *configPath == "" || *path == "" {
		return errors.New("--config and --path are required")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	lineParser, err := parserFor(*kind)
	if err != nil {
		return err
	}
	input, err := os.Open(*path)
	if err != nil {
		return err
	}
	defer input.Close()
	engine := policy.NewEngine(cfg, nil)
	result := replayResult{}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		result.Lines++
		item, ok, parseErr := lineParser.Parse(scanner.Text(), time.Now())
		if parseErr != nil || !ok {
			continue
		}
		result.Events++
		decision := engine.Evaluate(item)
		switch decision.Severity {
		case policy.Warning:
			result.Warnings++
		case policy.Contain:
			result.Containments++
			if result.FirstContainment == nil {
				copyOfDecision := decision
				result.FirstContainment = &copyOfDecision
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func parserFor(kind string) (parser.LineParser, error) {
	switch kind {
	case "exim":
		return parser.Exim{}, nil
	case "dovecot":
		return parser.Dovecot{}, nil
	default:
		return nil, fmt.Errorf("unknown parser %q", kind)
	}
}
