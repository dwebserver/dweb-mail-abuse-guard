// Package platform contains narrowly scoped integrations with mail platforms.
package platform

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

const maxCommandOutput = 2 * 1024 * 1024

type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	var output limitedBuffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		return output.Bytes(), fmt.Errorf("run %s: %w", name, err)
	}
	return output.Bytes(), nil
}

type limitedBuffer struct {
	buffer bytes.Buffer
	over   bool
}

func (b *limitedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	remaining := maxCommandOutput - b.buffer.Len()
	if remaining <= 0 {
		b.over = true
		return original, nil
	}
	if len(value) > remaining {
		value = value[:remaining]
		b.over = true
	}
	_, _ = b.buffer.Write(value)
	return original, nil
}

func (b *limitedBuffer) Bytes() []byte {
	if !b.over {
		return b.buffer.Bytes()
	}
	copyOfOutput := append([]byte(nil), b.buffer.Bytes()...)
	return append(copyOfOutput, []byte("\n[output truncated]\n")...)
}
