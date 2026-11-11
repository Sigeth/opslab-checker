package checks

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
	"github.com/Sigeth/opslab-core-go/pkg/checkerio"
	"github.com/Sigeth/opslab-core-go/pkg/kubeexec"

	"github.com/Sigeth/opslab-checker/pkg/sdk"
)

// fakeMachine answers the commands the checks run.
type fakeMachine struct {
	files map[string]string // path -> "mode user group\ncontent"
	exit  int
	out   string
	err   error
	cmds  [][]string
}

func (f *fakeMachine) Exec(_ context.Context, req kubeexec.Request) (kubeexec.Result, error) {
	f.cmds = append(f.cmds, req.Command)
	if f.err != nil {
		return kubeexec.Result{}, f.err
	}
	switch {
	case req.Command[0] == "/bin/sh" && req.Command[2] == statScript:
		entry, ok := f.files[req.Command[4]]
		if !ok {
			return kubeexec.Result{Stdout: []byte("missing\n")}, nil
		}
		stat, _, _ := strings.Cut(entry, "\n")
		return kubeexec.Result{Stdout: []byte(stat + "\n")}, nil
	case req.Command[0] == "head":
		_, content, _ := strings.Cut(f.files[req.Command[4]], "\n")
		return kubeexec.Result{Stdout: []byte(content)}, nil
	default:
		return kubeexec.Result{ExitCode: f.exit, Stdout: []byte(f.out)}, nil
	}
}

var podTarget = checkerio.Target{Runtime: v1alpha1.RuntimePod, Namespace: "inst-x", Pod: "box", Container: "machine"}

func check(t *testing.T, m *fakeMachine, c v1alpha1.Check) sdk.Result {
	t.Helper()
	c.Machine = "box"
	env := &sdk.Env{Targets: &checkerio.Targets{Machines: map[string]checkerio.Target{"box": podTarget}}}
	res, err := (&Checker{Exec: m}).Check(context.Background(), env, v1alpha1.Task{ID: "t", Check: &c})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestFileChecks(t *testing.T) {
	m := &fakeMachine{files: map[string]string{
		"/home/ubuntu/.ssh/id_ed25519": "600 ubuntu ubuntu\n-----BEGIN KEY-----",
		"/home/ubuntu/.env":            "644 ubuntu ubuntu\nTOKEN=s3cr3t",
	}}
	no := false
	tests := []struct {
		name string
		file v1alpha1.FileCheck
		pass bool
		msg  string
	}{
		{"mode ok", v1alpha1.FileCheck{Path: "/home/ubuntu/.ssh/id_ed25519", Mode: "0600"}, true, ""},
		{"mode wrong", v1alpha1.FileCheck{Path: "/home/ubuntu/.env", Mode: "0600"}, false, "mode 0644, expected 0600"},
		{"owner", v1alpha1.FileCheck{Path: "/home/ubuntu/.env", Owner: "ubuntu:ubuntu"}, true, ""},
		{"owner wrong", v1alpha1.FileCheck{Path: "/home/ubuntu/.env", Owner: "root"}, false, "owned by ubuntu:ubuntu"},
		{"missing", v1alpha1.FileCheck{Path: "/nope"}, false, "does not exist"},
		{"absent as expected", v1alpha1.FileCheck{Path: "/nope", Exists: &no}, true, ""},
		{"still exists", v1alpha1.FileCheck{Path: "/home/ubuntu/.env", Exists: &no}, false, "still exists"},
		{"contains", v1alpha1.FileCheck{Path: "/home/ubuntu/.ssh/id_ed25519", Contains: "BEGIN"}, true, ""},
		{"not contains", v1alpha1.FileCheck{Path: "/home/ubuntu/.env", NotContains: "s3cr3t"}, false, "forbidden content"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := check(t, m, v1alpha1.Check{File: &tt.file})
			if res.Passed != tt.pass || !strings.Contains(res.Message, tt.msg) {
				t.Fatalf("got %+v", res)
			}
		})
	}
}

func TestShellChecks(t *testing.T) {
	one := int32(1)
	tests := []struct {
		name  string
		m     *fakeMachine
		shell v1alpha1.ShellCheck
		pass  bool
	}{
		{"exit 0", &fakeMachine{}, v1alpha1.ShellCheck{Run: "true"}, true},
		{"exit 1", &fakeMachine{exit: 1}, v1alpha1.ShellCheck{Run: "false"}, false},
		{"expected exit 1", &fakeMachine{exit: 1}, v1alpha1.ShellCheck{Run: "false", ExpectExit: &one}, true},
		{"output", &fakeMachine{out: "nginx running"}, v1alpha1.ShellCheck{Run: "ps", ExpectOutput: "nginx"}, true},
		{"output mismatch", &fakeMachine{out: "nothing"}, v1alpha1.ShellCheck{Run: "ps", ExpectOutput: "nginx"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if res := check(t, tt.m, v1alpha1.Check{Shell: &tt.shell}); res.Passed != tt.pass {
				t.Fatalf("got %+v", res)
			}
			if got := tt.m.cmds[0]; got[0] != "/bin/sh" || got[2] != tt.shell.Run {
				t.Fatalf("command = %q", got)
			}
		})
	}
}

func TestUnreachableMachineFails(t *testing.T) {
	m := &fakeMachine{err: errors.New("pods \"box\" not found")}
	res := check(t, m, v1alpha1.Check{Shell: &v1alpha1.ShellCheck{Run: "true"}})
	if res.Passed || !strings.Contains(res.Message, "cannot run commands on box") {
		t.Fatalf("got %+v", res)
	}
}
