// Package incident provides stable identifiers for operator-visible incidents.
package incident

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"time"
)

var validID = regexp.MustCompile(`^mag-[0-9]{8}t[0-9]{6}z-[a-f0-9]{16}$`)

// NewID returns a sortable identifier with enough randomness to avoid collisions.
func NewID(at time.Time) (string, error) {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate incident ID: %w", err)
	}
	return fmt.Sprintf("mag-%s-%s", at.UTC().Format("20060102t150405z"), hex.EncodeToString(random)), nil
}

func ValidID(value string) bool {
	return validID.MatchString(value)
}
