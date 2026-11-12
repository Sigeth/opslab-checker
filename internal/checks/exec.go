package checks

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
	"github.com/Sigeth/opslab-core-go/pkg/checkerio"
	"github.com/Sigeth/opslab-core-go/pkg/kubeexec"

	"github.com/Sigeth/opslab-checker/pkg/sdk"
)

// maxFileSize bounds the content read by file checks.
const maxFileSize = 1 << 20

// run executes a command on a machine: in the container of pod machines (as
// the container user), over SSH on vm machines (as user, root when empty).
// When the machine cannot be reached (the student deleted it, broke sshd or
// the checker's access...), the task fails: a check never passes without
// evidence.
func (c *Checker) run(ctx context.Context, target checkerio.Target, machine, user string, cmd ...string) (kubeexec.Result, *sdk.Result, error) {
	if target.Runtime == v1alpha1.RuntimeVM {
		return c.runSSH(ctx, target, machine, user, cmd)
	}
	if target.Pod == "" {
		return kubeexec.Result{}, nil, fmt.Errorf("machine %s (%s): %w", machine, target.Runtime, ErrUnsupported)
	}
	if c.Exec == nil {
		return kubeexec.Result{}, nil, fmt.Errorf("machine %s: no Kubernetes access to run commands", machine)
	}
	res, err := c.Exec.Exec(ctx, kubeexec.Request{
		Namespace: target.Namespace,
		Pod:       target.Pod,
		Container: target.Container,
		Command:   cmd,
	})
	if err != nil {
		if ctx.Err() != nil {
			return res, nil, err
		}
		fail := sdk.Fail(fmt.Sprintf("cannot run commands on %s: %v", machine, err))
		return res, &fail, nil
	}
	return res, nil, nil
}

// shell runs a command on the machine. On pod machines it runs as the
// container user whatever the check's user is.
func (c *Checker) shell(ctx context.Context, target checkerio.Target, machine string, s *v1alpha1.ShellCheck) (sdk.Result, error) {
	var re *regexp.Regexp
	if s.ExpectOutput != "" {
		var err error
		if re, err = regexp.Compile(s.ExpectOutput); err != nil {
			return sdk.Result{}, err
		}
	}
	res, fail, err := c.run(ctx, target, machine, s.User, "/bin/sh", "-c", s.Run)
	if err != nil || fail != nil {
		return deref(fail), err
	}
	want := 0
	if s.ExpectExit != nil {
		want = int(*s.ExpectExit)
	}
	if res.ExitCode != want {
		return sdk.Fail(fmt.Sprintf("the command exited with %d, expected %d", res.ExitCode, want)), nil
	}
	if re != nil && !re.Match(res.Stdout) {
		return sdk.Fail(fmt.Sprintf("the output does not match %q", s.ExpectOutput)), nil
	}
	return sdk.Pass("the command succeeded"), nil
}

// statScript prints "<octal mode> <user> <group>" for an existing path, or
// "missing". It only needs a POSIX shell and stat (coreutils or busybox).
const statScript = `if [ -e "$1" ] || [ -L "$1" ]; then stat -c '%a %U %G' -- "$1"; else echo missing; fi`

// file asserts properties of a file on the machine.
func (c *Checker) file(ctx context.Context, target checkerio.Target, machine string, f *v1alpha1.FileCheck) (sdk.Result, error) {
	res, fail, err := c.run(ctx, target, machine, "root", "/bin/sh", "-c", statScript, "sh", f.Path)
	if err != nil || fail != nil {
		return deref(fail), err
	}
	if res.ExitCode != 0 {
		return sdk.Fail(fmt.Sprintf("cannot inspect %s: %s", f.Path, strings.TrimSpace(string(res.Stderr)))), nil
	}
	out := strings.Fields(string(res.Stdout))
	exists := len(out) == 3
	wantExists := f.Exists == nil || *f.Exists
	switch {
	case !wantExists && exists:
		return sdk.Fail(fmt.Sprintf("%s still exists", f.Path)), nil
	case !wantExists:
		return sdk.Pass(fmt.Sprintf("%s does not exist", f.Path)), nil
	case !exists:
		return sdk.Fail(fmt.Sprintf("%s does not exist", f.Path)), nil
	}

	if f.Mode != "" {
		want, err := strconv.ParseUint(f.Mode, 8, 32)
		if err != nil {
			return sdk.Result{}, fmt.Errorf("mode %q: %w", f.Mode, err)
		}
		got, err := strconv.ParseUint(out[0], 8, 32)
		if err != nil {
			return sdk.Fail(fmt.Sprintf("cannot read the mode of %s", f.Path)), nil
		}
		if got != want {
			return sdk.Fail(fmt.Sprintf("%s has mode %04o, expected %04o", f.Path, got, want)), nil
		}
	}
	if f.Owner != "" {
		user, group, hasGroup := strings.Cut(f.Owner, ":")
		if out[1] != user || (hasGroup && out[2] != group) {
			return sdk.Fail(fmt.Sprintf("%s is owned by %s:%s, expected %s", f.Path, out[1], out[2], f.Owner)), nil
		}
	}
	if f.Contains != "" || f.NotContains != "" {
		res, fail, err := c.run(ctx, target, machine, "root", "head", "-c", strconv.Itoa(maxFileSize), "--", f.Path)
		if err != nil || fail != nil {
			return deref(fail), err
		}
		if res.ExitCode != 0 {
			return sdk.Fail(fmt.Sprintf("cannot read %s", f.Path)), nil
		}
		for _, rule := range []struct {
			expr string
			want bool
			msg  string
		}{
			{f.Contains, true, "%s does not contain the expected content"},
			{f.NotContains, false, "%s still contains forbidden content"},
		} {
			if rule.expr == "" {
				continue
			}
			re, err := regexp.Compile(rule.expr)
			if err != nil {
				return sdk.Result{}, err
			}
			if re.Match(res.Stdout) != rule.want {
				return sdk.Fail(fmt.Sprintf(rule.msg, f.Path)), nil
			}
		}
	}
	return sdk.Pass(fmt.Sprintf("%s is as expected", f.Path)), nil
}

func deref(r *sdk.Result) sdk.Result {
	if r == nil {
		return sdk.Result{}
	}
	return *r
}
