// Package checks implements the built-in check types of challenge.yaml.
package checks

import (
	"context"
	"errors"
	"fmt"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
	"github.com/Sigeth/opslab-core-go/pkg/kubeexec"
	"github.com/Sigeth/opslab-core-go/pkg/sshexec"

	"github.com/Sigeth/opslab-checker/pkg/sdk"
)

// ErrUnsupported is returned for check types not implemented yet.
var ErrUnsupported = errors.New("check type not supported by this checker version")

// Checker evaluates the built-in check types.
type Checker struct {
	// Exec runs commands in pod machines (shell and file checks).
	Exec kubeexec.Executor
	// SSH runs commands in vm machines, as the checker user.
	SSH sshexec.Executor
	// Login attempts SSH logins (sshLogin checks): sshexec.Login.
	Login func(context.Context, sshexec.Request) (bool, error)
}

// Check dispatches a task to the implementation of its check type. It is an
// sdk.CheckFunc.
func (ch *Checker) Check(ctx context.Context, env *sdk.Env, task v1alpha1.Task) (sdk.Result, error) {
	c := task.Check
	if c == nil {
		return sdk.Result{}, errors.New("task has no check (does the package need a custom checker?)")
	}
	target, err := env.Target(c.Machine)
	if err != nil {
		return sdk.Result{}, err
	}
	switch {
	case c.Port != nil:
		return port(ctx, target.Host, c.Port)
	case c.HTTP != nil:
		return httpCheck(ctx, target.Host, c.HTTP)
	case c.Shell != nil:
		return ch.shell(ctx, target, c.Machine, c.Shell)
	case c.File != nil:
		return ch.file(ctx, target, c.Machine, c.File)
	case c.SSHLogin != nil:
		return ch.sshLogin(ctx, target, c.Machine, c.SSHLogin)
	case c.KubeCEL != nil:
		return sdk.Result{}, fmt.Errorf("kubeCEL: %w", ErrUnsupported)
	case c.Goss != nil:
		return sdk.Result{}, fmt.Errorf("goss: %w", ErrUnsupported)
	}
	return sdk.Result{}, errors.New("check has no type")
}
