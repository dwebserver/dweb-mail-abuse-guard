package incident

import (
	"testing"
	"time"
)

func TestNewAndValidateID(t *testing.T) {
	id, err := NewID(time.Date(2026, 9, 4, 12, 30, 45, 0, time.FixedZone("SAST", 7200)))
	if err != nil {
		t.Fatal(err)
	}
	if !ValidID(id) || id[:20] != "mag-20260904t103045z" {
		t.Fatal(id)
	}
	for _, invalid := range []string{"", "../../etc/passwd", "mag-20260904t103045z-short", "MAG-20260904t103045z-1234567890abcdef"} {
		if ValidID(invalid) {
			t.Errorf("accepted %q", invalid)
		}
	}
}
