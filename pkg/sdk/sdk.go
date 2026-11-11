// Package sdk runs checkers. It implements the checker contract of
// github.com/Sigeth/opslab-core-go/pkg/checkerio so a checker only has to
// decide whether one task passes.
//
// The built-in checker uses it, and so can custom checkers written in Go:
//
//	func main() {
//		sdk.Main(func(ctx context.Context, env *sdk.Env, task v1alpha1.Task) (sdk.Result, error) {
//			host := env.Targets.Machines["server"].Host
//			// ... probe host ...
//			return sdk.Pass("root login rejected"), nil
//		})
//	}
package sdk

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"time"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
	"github.com/Sigeth/opslab-core-go/pkg/challenge"
	"github.com/Sigeth/opslab-core-go/pkg/checkerio"
)

// DefaultPackageDir is where the operator mounts the package files when
// checkerio.EnvPackageDir is not set.
const DefaultPackageDir = "/opslab/package"

// TaskTimeout bounds the time spent checking one task.
const TaskTimeout = 30 * time.Second

// Env is what a check can use.
type Env struct {
	// Package is the defaulted challenge manifest.
	Package *v1alpha1.ChallengePackage
	// Files of the package (goss specs, scripts...).
	Files fs.FS
	// Targets describes how to reach each machine.
	Targets *checkerio.Targets
}

// Target returns how to reach a machine.
func (e *Env) Target(machine string) (checkerio.Target, error) {
	t, ok := e.Targets.Machines[machine]
	if !ok {
		return t, fmt.Errorf("no target for machine %q", machine)
	}
	return t, nil
}

// Result of checking one task.
type Result struct {
	Passed  bool
	Message string
}

// Pass returns a passing result.
func Pass(message string) Result { return Result{Passed: true, Message: message} }

// Fail returns a failing result. The message is shown to the student.
func Fail(message string) Result { return Result{Passed: false, Message: message} }

// CheckFunc checks one task. Return an error only when the task could not be
// checked (the run is then reported as a checker error, not as a failure).
type CheckFunc func(ctx context.Context, env *Env, task v1alpha1.Task) (Result, error)

// Main runs the checker with the configuration from the environment and exits.
func Main(check CheckFunc) {
	if err := Run(context.Background(), check, ConfigFromEnv(), os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "checker error:", err)
		os.Exit(1)
	}
}

// Config locates the checker inputs.
type Config struct {
	// Tasks to check; empty checks every task.
	Tasks []string
	// TargetsFile is the path of the targets JSON file.
	TargetsFile string
	// Files of the package.
	Files fs.FS
}

// ConfigFromEnv reads the configuration set by the operator.
func ConfigFromEnv() Config {
	dir := os.Getenv(checkerio.EnvPackageDir)
	if dir == "" {
		dir = DefaultPackageDir
	}
	return Config{
		Tasks:       checkerio.TasksFromEnv(),
		TargetsFile: os.Getenv(checkerio.EnvTargetsFile),
		Files:       os.DirFS(dir),
	}
}

// Run checks the configured tasks and writes one result per task to out.
func Run(ctx context.Context, check CheckFunc, cfg Config, out io.Writer) error {
	if cfg.TargetsFile == "" {
		return errors.New(checkerio.EnvTargetsFile + " is not set")
	}
	targets, err := checkerio.ReadTargets(cfg.TargetsFile)
	if err != nil {
		return err
	}
	pkg, err := challenge.Load(cfg.Files)
	if err != nil {
		return err
	}
	challenge.SetDefaults(pkg)
	env := &Env{Package: pkg, Files: cfg.Files, Targets: targets}

	tasks, err := selectTasks(pkg.Spec.Tasks, cfg.Tasks)
	if err != nil {
		return err
	}
	for _, task := range tasks {
		taskCtx, cancel := context.WithTimeout(ctx, TaskTimeout)
		res, err := check(taskCtx, env, task)
		cancel()
		if err != nil {
			return fmt.Errorf("task %s: %w", task.ID, err)
		}
		if err := checkerio.WriteResult(out, v1alpha1.TaskResult{Task: task.ID, Passed: res.Passed, Message: res.Message}); err != nil {
			return err
		}
	}
	return nil
}

func selectTasks(all []v1alpha1.Task, ids []string) ([]v1alpha1.Task, error) {
	if len(ids) == 0 {
		return all, nil
	}
	selected := make([]v1alpha1.Task, 0, len(ids))
	for _, id := range ids {
		i := slices.IndexFunc(all, func(t v1alpha1.Task) bool { return t.ID == id })
		if i < 0 {
			return nil, fmt.Errorf("unknown task %q", id)
		}
		selected = append(selected, all[i])
	}
	return selected, nil
}
