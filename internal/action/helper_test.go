package action

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type fakeRunner struct {
	name string
	args []string
	err  error
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.name, f.args = name, append([]string(nil), args...)
	return nil, f.err
}

func TestHelperArguments(t *testing.T) {
	runner := &fakeRunner{}
	helper := NewHelper(runner, "/usr/bin/sudo", []string{"-n", "/helper"}, time.Second)
	if err := helper.Contain(context.Background(), "user@example.com", "incident"); err != nil {
		t.Fatal(err)
	}
	want := []string{"-n", "/helper", "contain", "--mailbox", "user@example.com", "--incident", "incident"}
	if runner.name != "/usr/bin/sudo" || !reflect.DeepEqual(runner.args, want) {
		t.Fatal(runner.name, runner.args)
	}
	if err := helper.Release(context.Background(), "user@example.com", "incident"); err != nil {
		t.Fatal(err)
	}
	if runner.args[2] != "release" {
		t.Fatal(runner.args)
	}
}

func TestHelperErrorsAndTimeout(t *testing.T) {
	runner := &fakeRunner{err: errors.New("failed")}
	helper := NewHelper(runner, "/helper", nil, time.Millisecond)
	if err := helper.Contain(context.Background(), "a@example.com", "id"); err == nil {
		t.Fatal("contain error hidden")
	}
	if err := helper.Release(context.Background(), "a@example.com", "id"); err == nil {
		t.Fatal("release error hidden")
	}
}
