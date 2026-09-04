package cpanel

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type response struct {
	output string
	err    error
}
type call struct {
	name string
	args []string
}
type scriptedRunner struct {
	responses []response
	calls     []call
}

func (r *scriptedRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, call{name, append([]string(nil), args...)})
	if len(r.responses) == 0 {
		return nil, errors.New("unexpected call")
	}
	answer := r.responses[0]
	r.responses = r.responses[1:]
	return []byte(answer.output), answer.err
}

func successResponses(queue string) []response {
	return []response{
		{output: "owner\n"},
		{output: `{"result":{"status":1,"data":[{"email":"User@Example.com"}]}}`},
		{output: `{"result":{"status":1}}`},
		{output: `{"result":{"status":1}}`},
		{},
		{output: queue},
	}
}

func TestContainAndRelease(t *testing.T) {
	queue := " 1m  2K ABC123 <user@example.com>\n 2m 2K OTHER1 <other@example.com>\n"
	runner := &scriptedRunner{responses: successResponses(queue)}
	runner.responses = append(runner.responses, response{})
	controller := New(runner, Paths{"whoowns", "uapi", "doveadm", "exim"})
	result, err := controller.Contain(context.Background(), "USER@example.com")
	if err != nil || result.Owner != "owner" || !reflect.DeepEqual(result.FrozenQueueIDs, []string{"ABC123"}) {
		t.Fatal(result, err)
	}
	last := runner.calls[len(runner.calls)-1]
	if last.name != "exim" || !reflect.DeepEqual(last.args, []string{"-Mf", "ABC123"}) {
		t.Fatal(last)
	}

	runner = &scriptedRunner{responses: []response{{output: "owner"}, {output: `{"result":{"status":1,"data":[{"email":"user@example.com"}]}}`}, {output: `{"result":{"status":1}}`}, {output: `{"result":{"status":1}}`}}}
	controller = New(runner, Paths{"whoowns", "uapi", "doveadm", "exim"})
	result, err = controller.Release(context.Background(), "user@example.com")
	if err != nil || result.Mailbox != "user@example.com" {
		t.Fatal(result, err)
	}
	if runner.calls[2].args[3] != "unsuspend_outgoing" || runner.calls[3].args[3] != "unsuspend_login" {
		t.Fatal(runner.calls)
	}
}

func TestResolveFailures(t *testing.T) {
	tests := []struct {
		name    string
		mailbox string
		replies []response
	}{
		{"invalid mailbox", "bad", nil},
		{"whoowns failed", "a@example.com", []response{{err: errors.New("no")}}},
		{"bad owner", "a@example.com", []response{{output: "root;evil"}}},
		{"list failed", "a@example.com", []response{{output: "owner"}, {err: errors.New("no")}}},
		{"bad json", "a@example.com", []response{{output: "owner"}, {output: "{"}}},
		{"api failure", "a@example.com", []response{{output: "owner"}, {output: `{"result":{"status":0,"errors":["denied"]}}`}}},
		{"not owned", "a@example.com", []response{{output: "owner"}, {output: `{"result":{"status":1,"data":[]}}`}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &scriptedRunner{responses: test.replies}
			_, _, err := New(runner, Paths{"whoowns", "uapi", "doveadm", "exim"}).resolve(context.Background(), test.mailbox)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestActionFailures(t *testing.T) {
	base := []response{{output: "owner"}, {output: `{"result":{"status":1,"data":[{"email":"a@example.com"}]}}`}}
	tests := [][]response{
		append(append([]response{}, base...), response{err: errors.New("suspend login")}),
		append(append([]response{}, base...), response{output: `{"result":{"status":1}}`}, response{output: `{"result":{"status":0,"errors":["no"]}}`}),
		append(append([]response{}, base...), response{output: `{"result":{"status":1}}`}, response{output: `{"result":{"status":1}}`}, response{err: errors.New("kick")}),
		append(append([]response{}, base...), response{output: `{"result":{"status":1}}`}, response{output: `{"result":{"status":1}}`}, response{}, response{err: errors.New("queue")}),
	}
	for index, replies := range tests {
		runner := &scriptedRunner{responses: replies}
		_, err := New(runner, Paths{"whoowns", "uapi", "doveadm", "exim"}).Contain(context.Background(), "a@example.com")
		if err == nil {
			t.Errorf("case %d should fail", index)
		}
	}

	runner := &scriptedRunner{responses: append(append([]response{}, base...), response{output: "not-json"})}
	if _, err := New(runner, Paths{"whoowns", "uapi", "doveadm", "exim"}).Release(context.Background(), "a@example.com"); err == nil {
		t.Fatal("bad uapi JSON accepted")
	}
}

func TestQueueParsingAndChunking(t *testing.T) {
	ids, err := queueIDsForSender([]byte(" 1m 2K ABC123 <A@example.com>\n 1m 2K BCD234 <b@example.com>"), "a@example.com")
	if err != nil || !reflect.DeepEqual(ids, []string{"ABC123"}) {
		t.Fatal(ids, err)
	}
	if _, err := queueIDsForSender(nil, "bad"); err == nil {
		t.Fatal("invalid sender accepted")
	}

	var builder strings.Builder
	for index := 0; index < 205; index++ {
		fmt.Fprintf(&builder, " 1m 2K ID%06d <a@example.com>\n", index)
	}
	replies := successResponses(builder.String())
	replies[1].output = `{"result":{"status":1,"data":[{"email":"a@example.com"}]}}`
	replies = append(replies, response{}, response{}, response{})
	runner := &scriptedRunner{responses: replies}
	_, err = New(runner, Paths{"whoowns", "uapi", "doveadm", "exim"}).Contain(context.Background(), "a@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 9 {
		t.Fatalf("calls=%d", len(runner.calls))
	}
}

func TestDefaultPaths(t *testing.T) {
	paths := DefaultPaths()
	if paths.UAPI == "" || paths.Exim == "" {
		t.Fatal(paths)
	}
}
