// Package parser converts mail-server logs into privacy-preserving events.
package parser

import (
	"time"

	"github.com/dwebserver/dweb-mail-abuse-guard/internal/event"
)

// LineParser parses one complete log line. Relevant but malformed lines return
// an error; unrelated lines return ok=false without an error.
type LineParser interface {
	Parse(line string, now time.Time) (parsed event.Event, ok bool, err error)
}
