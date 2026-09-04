package follow

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dwebserver/dweb-mail-abuse-guard/internal/store"
)

type memoryCursors struct {
	values map[string]store.Cursor
	putErr error
	getErr error
}

func (m *memoryCursors) GetCursor(path string) (store.Cursor, bool, error) {
	if m.getErr != nil {
		return store.Cursor{}, false, m.getErr
	}
	value, ok := m.values[path]
	return value, ok, nil
}
func (m *memoryCursors) PutCursor(value store.Cursor) error {
	if m.putErr != nil {
		return m.putErr
	}
	m.values[value.Path] = value
	return nil
}

func TestRunReadsCompleteLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mail.log")
	if err := os.WriteFile(path, []byte("one\ntwo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cursors := &memoryCursors{values: map[string]store.Cursor{}}
	ctx, cancel := context.WithCancel(context.Background())
	var lines []string
	err := Run(ctx, Options{Path: path, Poll: time.Millisecond}, cursors, func(line string) error {
		lines = append(lines, line)
		if len(lines) == 2 {
			cancel()
		}
		return nil
	})
	if err != nil || len(lines) != 2 || lines[0] != "one" || cursors.values[path].Offset != 8 {
		t.Fatal(lines, cursors.values[path], err)
	}
}

func TestOpenAtCursorAndStartAtEnd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mail.log")
	_ = os.WriteFile(path, []byte("abcdef"), 0o600)
	cursors := &memoryCursors{values: map[string]store.Cursor{}}
	file, offset, prefix, err := openAtCursor(Options{Path: path, StartAtEnd: true}, cursors)
	if err != nil || offset != 6 || prefix == "" {
		t.Fatal(offset, prefix, err)
	}
	_ = file.Close()
	cursors.values[path] = store.Cursor{Path: path, Offset: 2, PrefixHash: prefix}
	file, offset, _, err = openAtCursor(Options{Path: path}, cursors)
	if err != nil || offset != 2 {
		t.Fatal(offset, err)
	}
	_ = file.Close()
	cursors.values[path] = store.Cursor{Path: path, Offset: 100, PrefixHash: prefix}
	file, offset, _, err = openAtCursor(Options{Path: path}, cursors)
	if err != nil || offset != 0 {
		t.Fatal(offset, err)
	}
	_ = file.Close()
}

func TestChangedAndValidation(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "mail.log")
	_ = os.WriteFile(path, []byte("abc"), 0o600)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	rotated, truncated, err := changed(file, path, 5)
	if err != nil || rotated || !truncated {
		t.Fatal(rotated, truncated, err)
	}
	_ = file.Close()
	if err := Run(context.Background(), Options{}, &memoryCursors{}, func(string) error { return nil }); err == nil {
		t.Fatal("invalid options accepted")
	}
	if _, _, _, err := openAtCursor(Options{Path: filepath.Join(directory, "missing")}, &memoryCursors{}); err == nil {
		t.Fatal("missing file accepted")
	}
	if _, _, _, err := openAtCursor(Options{Path: path}, &memoryCursors{getErr: os.ErrPermission}); err == nil {
		t.Fatal("cursor error hidden")
	}
}

func TestRunCallbackAndCursorErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mail.log")
	_ = os.WriteFile(path, []byte("one\n"), 0o600)
	want := os.ErrPermission
	if err := Run(context.Background(), Options{Path: path, Poll: time.Millisecond}, &memoryCursors{values: map[string]store.Cursor{}}, func(string) error { return want }); err != want {
		t.Fatal(err)
	}
	if err := Run(context.Background(), Options{Path: path, Poll: time.Millisecond}, &memoryCursors{values: map[string]store.Cursor{}, putErr: want}, func(string) error { return nil }); err == nil {
		t.Fatal("cursor error hidden")
	}
}

func TestRunRejectsOversizedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mail.log")
	if err := os.WriteFile(path, make([]byte, maxLineSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Run(context.Background(), Options{Path: path, Poll: time.Millisecond}, &memoryCursors{values: map[string]store.Cursor{}}, func(string) error { return nil })
	if err == nil {
		t.Fatal("oversized line accepted")
	}
}
