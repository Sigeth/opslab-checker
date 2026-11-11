package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
	"github.com/Sigeth/opslab-core-go/pkg/checkerio"

	"github.com/Sigeth/opslab-checker/pkg/sdk"
)

// newServer starts an HTTP server and returns its host and port.
func newServer(t *testing.T, status int, body string) (string, int32) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	host, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	p, _ := strconv.Atoi(portStr)
	return host, int32(p)
}

// closedPort returns a local port nothing listens on.
func closedPort(t *testing.T) int32 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return int32(p)
}

func manifest(port, closed int32) string {
	return `apiVersion: opslab.io/v1alpha1
kind: ChallengePackage
metadata: {name: web, version: 0.1.0}
spec:
  title: Web
  summary: Serve a page and close the debug port.
  category: containers
  difficulty: easy
  machines:
    - {name: app, runtime: pod, image: example}
  access:
    terminals: [{machine: app}]
  tasks:
    - id: serves-ok
      title: Serve the page
      points: 1
      check: {machine: app, http: {port: ` + itoa(port) + `, expectBody: "^hello"}}
    - id: port-open
      title: Listen
      points: 1
      check: {machine: app, port: {port: ` + itoa(port) + `, expect: open}}
    - id: debug-closed
      title: Close the debug port
      points: 1
      check: {machine: app, port: {port: ` + itoa(closed) + `, expect: closed}}
    - id: not-found
      title: Hide the admin page
      points: 1
      check: {machine: app, http: {port: ` + itoa(port) + `, path: /admin, expectStatus: 404}}
`
}

func itoa(i int32) string { return strconv.Itoa(int(i)) }

func run(t *testing.T, manifest, host string, tasks ...string) ([]v1alpha1.TaskResult, error) {
	t.Helper()
	targets, _ := json.Marshal(checkerio.Targets{Machines: map[string]checkerio.Target{
		"app": {Runtime: v1alpha1.RuntimePod, Host: host},
	}})
	targetsFile := filepath.Join(t.TempDir(), "targets.json")
	if err := os.WriteFile(targetsFile, targets, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := sdk.Config{
		Tasks:       tasks,
		TargetsFile: targetsFile,
		Files:       fstest.MapFS{"challenge.yaml": {Data: []byte(manifest)}},
	}
	var out bytes.Buffer
	if err := sdk.Run(context.Background(), (&Checker{}).Check, cfg, &out); err != nil {
		return nil, err
	}
	return checkerio.ParseResults(&out)
}

func TestNetworkChecks(t *testing.T) {
	host, port := newServer(t, http.StatusOK, "hello world")
	results, err := run(t, manifest(port, closedPort(t)), host)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"serves-ok": true, "port-open": true, "debug-closed": true, "not-found": false}
	if len(results) != len(want) {
		t.Fatalf("got %d results: %+v", len(results), results)
	}
	for _, r := range results {
		if r.Passed != want[r.Task] {
			t.Errorf("%s: passed=%v (%s), want %v", r.Task, r.Passed, r.Message, want[r.Task])
		}
	}
}

func TestFailureMessages(t *testing.T) {
	host, port := newServer(t, http.StatusOK, "goodbye")
	results, err := run(t, manifest(port, port), host, "serves-ok", "debug-closed")
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Passed || !strings.Contains(results[0].Message, "does not match") {
		t.Errorf("serves-ok: %+v", results[0])
	}
	if results[1].Passed || !strings.Contains(results[1].Message, "still open") {
		t.Errorf("debug-closed: %+v", results[1])
	}
}

func TestUnknownTaskIsAnError(t *testing.T) {
	if _, err := run(t, manifest(1, 2), "127.0.0.1", "nope"); err == nil {
		t.Fatal("expected an error")
	}
}

func TestUnsupportedCheckIsAnError(t *testing.T) {
	m := strings.Replace(manifest(1, 2), "http: {port: 1, expectBody: \"^hello\"}", "shell: {run: \"true\"}", 1)
	_, err := run(t, m, "127.0.0.1", "serves-ok")
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("expected ErrUnsupported, got %v", err)
	}
}
