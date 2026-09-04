package platform

import (
	"bytes"
	"context"
	"testing"
)

func TestLimitedBuffer(t *testing.T) {
	var buffer limitedBuffer
	input := bytes.Repeat([]byte("x"), maxCommandOutput+20)
	if written, err := buffer.Write(input); err != nil || written != len(input) {
		t.Fatal(written, err)
	}
	output := buffer.Bytes()
	if !bytes.HasSuffix(output, []byte("[output truncated]\n")) || len(output) <= maxCommandOutput {
		t.Fatal("missing truncation marker")
	}
	if written, err := buffer.Write([]byte("more")); err != nil || written != 4 {
		t.Fatal(written, err)
	}
}

func TestExecRunnerFailure(t *testing.T) {
	if output, err := (ExecRunner{}).Run(context.Background(), "definitely-not-a-real-dweb-command"); err == nil || len(output) != 0 {
		t.Fatal(string(output), err)
	}
}
