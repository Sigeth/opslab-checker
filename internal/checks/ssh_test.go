package checks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
	"github.com/Sigeth/opslab-core-go/pkg/checkerio"
	"github.com/Sigeth/opslab-core-go/pkg/sshexec"

	"github.com/Sigeth/opslab-checker/pkg/sdk"
)

// fakeVM answers SSH commands like a machine where sudo works (or not).
type fakeVM struct {
	noSudo bool
	exit   int
	out    string
	err    error
	reqs   []sshexec.Request
}

func (f *fakeVM) Run(_ context.Context, req sshexec.Request) (sshexec.Result, error) {
	f.reqs = append(f.reqs, req)
	if f.err != nil {
		return sshexec.Result{}, f.err
	}
	if f.noSudo {
		return sshexec.Result{ExitCode: 1, Stderr: []byte("sudo: a password is required\n")}, nil
	}
	return sshexec.Result{ExitCode: f.exit, Stdout: []byte(f.out), Stderr: []byte(sudoMarker + "\nwarning\n")}, nil
}

func vmTarget(t *testing.T) checkerio.Target {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{"checker": "CHECKER KEY", "student": "STUDENT KEY", "known_hosts": "box.inst-x.svc ssh-ed25519 AAAA\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return checkerio.Target{
		Runtime: v1alpha1.RuntimeVM, Host: "box.inst-x.svc", SSHPort: 22, SSHUser: "opslab-checker",
		SSHPrivateKeyFile:     filepath.Join(dir, "checker"),
		StudentPrivateKeyFile: filepath.Join(dir, "student"),
		SSHKnownHostsFile:     filepath.Join(dir, "known_hosts"),
	}
}

func checkVM(t *testing.T, ch *Checker, c v1alpha1.Check) sdk.Result {
	t.Helper()
	c.Machine = "box"
	env := &sdk.Env{Targets: &checkerio.Targets{Machines: map[string]checkerio.Target{"box": vmTarget(t)}}}
	res, err := ch.Check(context.Background(), env, v1alpha1.Task{ID: "t", Check: &c})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestShellOverSSH(t *testing.T) {
	vm := &fakeVM{out: "PermitRootLogin no\n"}
	res := checkVM(t, &Checker{SSH: vm}, v1alpha1.Check{Shell: &v1alpha1.ShellCheck{Run: "sshd -T | grep -i permitrootlogin", User: "root", ExpectOutput: "(?i)permitrootlogin no"}})
	if !res.Passed {
		t.Fatalf("result = %+v", res)
	}
	req := vm.reqs[0]
	if req.Addr != "box.inst-x.svc:22" || req.User != "opslab-checker" || string(req.PrivateKey) != "CHECKER KEY" || !strings.HasPrefix(string(req.KnownHosts), "box.inst-x.svc ") {
		t.Fatalf("request = %+v", req)
	}
	want := `'sudo' '-n' '-u' 'root' '--' '/bin/sh' '-c' 'echo '\''` + sudoMarker + `'\'' >&2; exec "$@"' 'sh' '/bin/sh' '-c' 'sshd -T | grep -i permitrootlogin'`
	if req.Command != want {
		t.Fatalf("command =\n%s\nwant\n%s", req.Command, want)
	}
}

func TestRefusedSudoFailsClosed(t *testing.T) {
	// The command would "succeed" with exit 1, but sudo itself failed.
	expect := int32(1)
	res := checkVM(t, &Checker{SSH: &fakeVM{noSudo: true}}, v1alpha1.Check{Shell: &v1alpha1.ShellCheck{Run: "grep -q bad /etc/x", ExpectExit: &expect}})
	if res.Passed || !strings.Contains(res.Message, "cannot run commands as root") {
		t.Fatalf("result = %+v", res)
	}
}

func TestUnreachableVMFails(t *testing.T) {
	exists := false
	res := checkVM(t, &Checker{SSH: &fakeVM{err: errors.New("connection refused")}}, v1alpha1.Check{File: &v1alpha1.FileCheck{Path: "/root/.rhosts", Exists: &exists}})
	if res.Passed || !strings.Contains(res.Message, "cannot run commands on box") {
		t.Fatalf("result = %+v", res)
	}
}

func TestFileCheckOverSSHRunsAsRoot(t *testing.T) {
	vm := &fakeVM{out: "600 root root\n"}
	res := checkVM(t, &Checker{SSH: vm}, v1alpha1.Check{File: &v1alpha1.FileCheck{Path: "/etc/shadow", Mode: "0600"}})
	if !res.Passed || !strings.Contains(vm.reqs[0].Command, `'-u' 'root'`) {
		t.Fatalf("result = %+v, command %s", res, vm.reqs[0].Command)
	}
}

func TestSSHLogin(t *testing.T) {
	var got sshexec.Request
	login := func(allowed bool, err error) func(context.Context, sshexec.Request) (bool, error) {
		return func(_ context.Context, req sshexec.Request) (bool, error) {
			got = req
			return allowed, err
		}
	}
	denied := v1alpha1.SSHLoginCheck{User: "root", Expect: v1alpha1.ExpectDenied}
	for name, tc := range map[string]struct {
		check   v1alpha1.SSHLoginCheck
		allowed bool
		err     error
		pass    bool
		message string
	}{
		"denied as expected":      {denied, false, nil, true, "root cannot log in with the student's key"},
		"still allowed":           {denied, true, nil, false, "root can still log in"},
		"sshd stopped":            {denied, false, errors.New("connection refused"), false, "cannot reach the SSH server of box"},
		"allowed as expected":     {v1alpha1.SSHLoginCheck{User: "student", Expect: v1alpha1.ExpectAllowed}, true, nil, true, "student can log in"},
		"password refused":        {v1alpha1.SSHLoginCheck{User: "root", Method: v1alpha1.SSHLoginPassword, Password: "toor", Expect: v1alpha1.ExpectDenied}, false, nil, true, "with a password"},
		"expected but not denied": {v1alpha1.SSHLoginCheck{User: "student", Expect: v1alpha1.ExpectAllowed}, false, nil, false, "student cannot log in"},
	} {
		c := tc.check
		res := checkVM(t, &Checker{Login: login(tc.allowed, tc.err)}, v1alpha1.Check{SSHLogin: &c})
		if res.Passed != tc.pass || !strings.Contains(res.Message, tc.message) {
			t.Errorf("%s: result = %+v", name, res)
		}
		if got.Addr != "box.inst-x.svc:22" || got.User != c.User {
			t.Errorf("%s: request = %+v", name, got)
		}
		if c.Method == v1alpha1.SSHLoginPassword {
			if got.Password != c.Password || got.PrivateKey != nil {
				t.Errorf("%s: password login sent %+v", name, got)
			}
		} else if string(got.PrivateKey) != "STUDENT KEY" {
			t.Errorf("%s: key login must present the student's key", name)
		}
	}
}

func TestSSHLoginNeedsSSHTarget(t *testing.T) {
	c := v1alpha1.Check{Machine: "box", SSHLogin: &v1alpha1.SSHLoginCheck{User: "root", Expect: v1alpha1.ExpectDenied}}
	env := &sdk.Env{Targets: &checkerio.Targets{Machines: map[string]checkerio.Target{"box": podTarget}}}
	if _, err := (&Checker{}).Check(context.Background(), env, v1alpha1.Task{ID: "t", Check: &c}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v", err)
	}
}
