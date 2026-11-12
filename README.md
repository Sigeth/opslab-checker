# opslab-checker

Validation for opslab (working name) challenges:

- **`cmd/checker`**: the built-in checker image. It evaluates the `check:` declared on each task of a `challenge.yaml`.
- **`pkg/sdk`**: a Go SDK for **custom checkers**. Handle one task and the SDK does the rest: it reads the inputs, selects the tasks and prints the results.

The operator runs the checker as a Job **outside** the student's machines. The contract (environment variables, targets file, JSON-lines output) is defined in [opslab-core-go/pkg/checkerio](https://github.com/Sigeth/opslab-core-go/tree/main/pkg/checkerio). A custom checker may be written in any language, as long as it follows that contract.

## Built-in check types

| Type | Status |
|---|---|
| `port` (tcp) | ✅ |
| `http` | ✅ |
| `shell`, `file` | ✅ on `pod` machines (Kubernetes exec) and `vm` machines (SSH) |
| `sshLogin` | ✅ on `vm` machines |
| `kubeCEL` | M4 |
| `goss` | later |

An unsupported check type is reported as a checker **error**, never as a failed task.

`shell` and `file` checks on `pod` machines run as the container user (UID 1000), whatever the check's `user`. When the machine cannot be reached, the task fails: a check never passes without evidence. The operator grants the checker's service account `pods/exec` in the instance namespace only.

On `vm` machines, the checker logs in over SSH as `opslab-checker`, with the instance's key and the machine's pinned host key, and runs the command as the check's `user` (default `root`) through `sudo`. A marker printed from inside `sudo` tells a failing command from a refused `sudo`: if the student revokes the checker's rights, the task fails instead of reading `sudo`'s exit code as the command's.

`sshLogin` tries a real login from the checker: with the student's key (`method: key`, the default) or the given `password`. `denied` passes only when the SSH server answers and refuses the login; an unreachable server or a changed host key fails the task whatever is expected, so stopping `sshd` does not count as denying logins.

## Custom checker in Go

```go
package main

import (
	"context"

	"github.com/Sigeth/opslab-checker/pkg/sdk"
	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
)

func main() {
	sdk.Main(func(ctx context.Context, env *sdk.Env, task v1alpha1.Task) (sdk.Result, error) {
		target, err := env.Target("server")
		if err != nil {
			return sdk.Result{}, err
		}
		_ = target.Host // probe the machine...
		return sdk.Fail("root login is still allowed"), nil
	})
}
```

Declare its image in `challenge.yaml` under `spec.validation.checkerImage`.

## Development

```sh
make lint test build
make image   # linux/amd64 (podman or docker)
```

## License

[MIT](LICENSE)
