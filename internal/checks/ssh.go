package checks

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
	"github.com/Sigeth/opslab-core-go/pkg/checkerio"
	"github.com/Sigeth/opslab-core-go/pkg/kubeexec"
	"github.com/Sigeth/opslab-core-go/pkg/sshexec"

	"github.com/Sigeth/opslab-checker/pkg/sdk"
)

// sudoMarker is printed to stderr from inside sudo before the command runs.
// Without it, sudo itself failed (the student revoked the checker's rights):
// its exit code must not be taken for the command's.
const sudoMarker = "opslab-checker: sudo ok"

// runSSH runs cmd on a vm machine: the checker user logs in with its key,
// the machine's host key pinned, and runs cmd as user through sudo.
func (c *Checker) runSSH(ctx context.Context, target checkerio.Target, machine, user string, cmd []string) (kubeexec.Result, *sdk.Result, error) {
	if c.SSH == nil {
		return kubeexec.Result{}, nil, fmt.Errorf("machine %s: no SSH client", machine)
	}
	key, known, err := readSSHFiles(target.SSHPrivateKeyFile, target.SSHKnownHostsFile)
	if err != nil {
		return kubeexec.Result{}, nil, fmt.Errorf("machine %s: %w", machine, err)
	}
	if user == "" {
		user = "root"
	}
	argv := append([]string{"sudo", "-n", "-u", user, "--", "/bin/sh", "-c", "echo '" + sudoMarker + `' >&2; exec "$@"`, "sh"}, cmd...)
	res, err := c.SSH.Run(ctx, sshexec.Request{
		Addr:       sshAddr(target),
		User:       target.SSHUser,
		PrivateKey: key,
		KnownHosts: known,
		Command:    shellJoin(argv),
	})
	if err != nil {
		if ctx.Err() != nil {
			return kubeexec.Result{}, nil, err
		}
		fail := sdk.Fail(fmt.Sprintf("cannot run commands on %s: %v", machine, err))
		return kubeexec.Result{}, &fail, nil
	}
	stderr, ok := strings.CutPrefix(string(res.Stderr), sudoMarker+"\n")
	if !ok {
		fail := sdk.Fail(fmt.Sprintf("cannot run commands as %s on %s: %s", user, machine, strings.TrimSpace(string(res.Stderr))))
		return kubeexec.Result{}, &fail, nil
	}
	return kubeexec.Result{Stdout: res.Stdout, Stderr: []byte(stderr), ExitCode: res.ExitCode}, nil, nil
}

// sshLogin tries to log in from the checker. The key method presents the
// student's key, so a challenge testing another user gives that user the
// student's public key in its setup. A login that cannot be attempted (sshd
// stopped, host key changed) fails the task whatever is expected: stopping
// sshd does not count as denying logins.
func (c *Checker) sshLogin(ctx context.Context, target checkerio.Target, machine string, l *v1alpha1.SSHLoginCheck) (sdk.Result, error) {
	if target.Host == "" || target.SSHKnownHostsFile == "" {
		return sdk.Result{}, fmt.Errorf("sshLogin on machine %s (%s): %w", machine, target.Runtime, ErrUnsupported)
	}
	if c.Login == nil {
		return sdk.Result{}, fmt.Errorf("machine %s: no SSH client", machine)
	}
	known, err := os.ReadFile(target.SSHKnownHostsFile)
	if err != nil {
		return sdk.Result{}, err
	}
	req := sshexec.Request{Addr: sshAddr(target), User: l.User, KnownHosts: known}
	method := "the student's key"
	if l.Method == v1alpha1.SSHLoginPassword {
		req.Password, method = l.Password, "a password"
	} else if req.PrivateKey, err = os.ReadFile(target.StudentPrivateKeyFile); err != nil {
		return sdk.Result{}, err
	}

	allowed, err := c.Login(ctx, req)
	if err != nil {
		if ctx.Err() != nil {
			return sdk.Result{}, err
		}
		return sdk.Fail(fmt.Sprintf("cannot reach the SSH server of %s: %v", machine, err)), nil
	}
	wantAllowed := l.Expect == v1alpha1.ExpectAllowed
	switch {
	case allowed && wantAllowed:
		return sdk.Pass(fmt.Sprintf("%s can log in with %s", l.User, method)), nil
	case allowed:
		return sdk.Fail(fmt.Sprintf("%s can still log in with %s", l.User, method)), nil
	case wantAllowed:
		return sdk.Fail(fmt.Sprintf("%s cannot log in with %s", l.User, method)), nil
	default:
		return sdk.Pass(fmt.Sprintf("%s cannot log in with %s", l.User, method)), nil
	}
}

func readSSHFiles(keyFile, knownHostsFile string) (key, known []byte, err error) {
	if key, err = os.ReadFile(keyFile); err != nil {
		return nil, nil, err
	}
	if known, err = os.ReadFile(knownHostsFile); err != nil {
		return nil, nil, err
	}
	return key, known, nil
}

func sshAddr(target checkerio.Target) string {
	port := target.SSHPort
	if port == 0 {
		port = v1alpha1.SSHPort
	}
	return net.JoinHostPort(target.Host, strconv.Itoa(int(port)))
}

// shellJoin quotes argv for a POSIX shell: SSH runs a command line, not argv.
func shellJoin(argv []string) string {
	quoted := make([]string, len(argv))
	for i, a := range argv {
		quoted[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(quoted, " ")
}
