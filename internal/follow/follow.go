// Package follow reads append-only log files with durable cursors and rotation handling.
package follow

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/dwebserver/dweb-mail-abuse-guard/internal/store"
)

const (
	prefixSize  = 4096
	maxLineSize = 1024 * 1024
)

type CursorStore interface {
	GetCursor(path string) (store.Cursor, bool, error)
	PutCursor(cursor store.Cursor) error
}

type Options struct {
	Path       string
	StartAtEnd bool
	Poll       time.Duration
}

// Run follows one path until the context is cancelled or an unrecoverable
// read/state error occurs. A callback error stops the follower so no event is
// silently skipped.
func Run(ctx context.Context, options Options, cursors CursorStore, handle func(string) error) error {
	if options.Path == "" || options.Poll <= 0 {
		return fmt.Errorf("invalid follower options")
	}

	file, offset, prefix, err := openAtCursor(options, cursors)
	if err != nil {
		return err
	}
	defer file.Close()
	reader := bufio.NewReaderSize(file, 64*1024)

	for {
		line, readErr := reader.ReadString('\n')
		if len(line) > maxLineSize {
			return fmt.Errorf("log line exceeds %d bytes", maxLineSize)
		}
		if readErr == nil {
			offset += int64(len(line))
			line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
			if err := handle(line); err != nil {
				return err
			}
			if err := cursors.PutCursor(store.Cursor{
				Path:       options.Path,
				Offset:     offset,
				PrefixHash: prefix,
				UpdatedAt:  time.Now().UTC(),
			}); err != nil {
				return fmt.Errorf("save log cursor: %w", err)
			}
			continue
		}
		if !errors.Is(readErr, io.EOF) {
			return fmt.Errorf("read %s: %w", options.Path, readErr)
		}
		if len(line) > 0 {
			if _, err := file.Seek(-int64(len(line)), io.SeekCurrent); err != nil {
				return fmt.Errorf("rewind partial log line: %w", err)
			}
			reader.Reset(file)
		}

		rotated, truncated, err := changed(file, options.Path, offset)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if rotated || truncated {
			file.Close()
			file, prefix, err = openFresh(options.Path)
			if err != nil {
				return err
			}
			offset = 0
			reader.Reset(file)
		}
		if !wait(ctx, options.Poll) {
			return nil
		}
	}
}

func openAtCursor(options Options, cursors CursorStore) (*os.File, int64, string, error) {
	file, prefix, err := openFresh(options.Path)
	if err != nil {
		return nil, 0, "", err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, 0, "", err
	}
	cursor, found, err := cursors.GetCursor(options.Path)
	if err != nil {
		file.Close()
		return nil, 0, "", err
	}
	offset := int64(0)
	if found && cursor.PrefixHash == prefix && cursor.Offset <= info.Size() {
		offset = cursor.Offset
	} else if !found && options.StartAtEnd {
		offset = info.Size()
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		file.Close()
		return nil, 0, "", err
	}
	return file, offset, prefix, nil
}

func openFresh(path string) (*os.File, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, "", fmt.Errorf("open log %s: %w", path, err)
	}
	prefix, err := prefixHash(file)
	if err != nil {
		file.Close()
		return nil, "", err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		file.Close()
		return nil, "", err
	}
	return file, prefix, nil
}

func prefixHash(file *os.File) (string, error) {
	hash := sha256.New()
	if _, err := io.CopyN(hash, file, prefixSize); err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func changed(file *os.File, path string, offset int64) (rotated bool, truncated bool, err error) {
	openInfo, err := file.Stat()
	if err != nil {
		return false, false, err
	}
	pathInfo, err := os.Stat(path)
	if err != nil {
		return false, false, err
	}
	return !os.SameFile(openInfo, pathInfo), pathInfo.Size() < offset, nil
}

func wait(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
