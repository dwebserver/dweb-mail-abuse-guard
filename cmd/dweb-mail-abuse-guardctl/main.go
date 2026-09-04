// dweb-mail-abuse-guardctl provides local status and controlled release actions.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/dwebserver/dweb-mail-abuse-guard/internal/config"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/control"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "dweb-mail-abuse-guardctl:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("usage: dweb-mail-abuse-guardctl <status|release> [options]")
	}
	switch arguments[0] {
	case "status":
		return status(arguments[1:], os.Stdout)
	case "release":
		return release(arguments[1:])
	default:
		return fmt.Errorf("unknown command %q", arguments[0])
	}
}

func status(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	configPath := flags.String("config", "/etc/dweb-mail-abuse-guard/config.yml", "configuration file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	client := control.NewClient(cfg.ControlSocket, 5*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := client.Status(ctx)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(result)
}

func release(arguments []string) error {
	flags := flag.NewFlagSet("release", flag.ContinueOnError)
	configPath := flags.String("config", "/etc/dweb-mail-abuse-guard/config.yml", "configuration file")
	incidentID := flags.String("incident", "", "incident to release")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *incidentID == "" {
		return errors.New("--incident is required")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	client := control.NewClient(cfg.ControlSocket, cfg.Actions.Timeout)
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Actions.Timeout)
	defer cancel()
	result, err := client.Release(ctx, *incidentID)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
