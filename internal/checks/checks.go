// Package checks implements the built-in check types of challenge.yaml.
package checks

import (
	"context"
	"errors"
	"fmt"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"

	"github.com/Sigeth/opslab-checker/pkg/sdk"
)

// ErrUnsupported is returned for check types not implemented yet.
var ErrUnsupported = errors.New("check type not supported by this checker version")

// Builtin dispatches a task to the implementation of its check type.
func Builtin(ctx context.Context, env *sdk.Env, task v1alpha1.Task) (sdk.Result, error) {
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
		return sdk.Result{}, fmt.Errorf("shell: %w", ErrUnsupported)
	case c.File != nil:
		return sdk.Result{}, fmt.Errorf("file: %w", ErrUnsupported)
	case c.SSHLogin != nil:
		return sdk.Result{}, fmt.Errorf("sshLogin: %w", ErrUnsupported)
	case c.KubeCEL != nil:
		return sdk.Result{}, fmt.Errorf("kubeCEL: %w", ErrUnsupported)
	case c.Goss != nil:
		return sdk.Result{}, fmt.Errorf("goss: %w", ErrUnsupported)
	}
	return sdk.Result{}, errors.New("check has no type")
}
