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

func runDaemon(arguments []string) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	path := flags.String("config", "/etc/dweb-mail-abuse-guard/config.yml", "configuration file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
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
	engine := policy.NewEngine(cfg, seed)
	helper := action.NewHelper(platform.ExecRunner{}, cfg.Actions.HelperPath, cfg.Actions.HelperArgs, cfg.Actions.Timeout)
	var sender notify.Sender = notify.Noop{}
	if cfg.Notification.WebhookURLFile != "" {
		sender, err = notify.NewWebhook(cfg.Notification.WebhookURLFile, cfg.Notification.Timeout)
		if err != nil {
			return err
		}
	}
	handler := service.New(cfg, engine, database, helper, sender, slog.Default())
	controlServer := control.NewServer(cfg.Mode, database, helper)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	slog.Info("mail abuse guard started", "version", version, "mode", cfg.Mode, "sources", len(cfg.Sources))
	return runComponents(ctx,
		func(componentCtx context.Context) error { return followSources(componentCtx, cfg, database, handler) },
		func(componentCtx context.Context) error { return controlServer.Serve(componentCtx, cfg.ControlSocket) },
	)
}

func runComponents(ctx context.Context, components ...func(context.Context) error) error {
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
