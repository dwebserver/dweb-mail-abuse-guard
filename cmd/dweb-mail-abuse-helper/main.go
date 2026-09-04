// dweb-mail-abuse-helper is the narrow privileged boundary used by the daemon.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/dwebserver/dweb-mail-abuse-guard/internal/identity"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/incident"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/platform"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/platform/cpanel"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "dweb-mail-abuse-helper:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 || (arguments[0] != "contain" && arguments[0] != "release") {
		return errors.New("usage: dweb-mail-abuse-helper <contain|release> --mailbox ADDRESS --incident ID")
	}
	operation := arguments[0]
	flags := flag.NewFlagSet(operation, flag.ContinueOnError)
	mailbox := flags.String("mailbox", "", "mailbox to contain or release")
	incidentID := flags.String("incident", "", "validated incident identifier")
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional argument")
	}
	normalized, err := identity.NormalizeMailbox(*mailbox)
	if err != nil {
		return err
	}
	if !incident.ValidID(*incidentID) {
		return errors.New("invalid incident identifier")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	controller := cpanel.New(platform.ExecRunner{}, cpanel.DefaultPaths())
	var result cpanel.Result
	if operation == "contain" {
		result, err = controller.Contain(ctx, normalized)
	} else {
		result, err = controller.Release(ctx, normalized)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
