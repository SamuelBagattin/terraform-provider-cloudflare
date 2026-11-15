package wranglerauth

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fakeWrangler is a shell script standing in for wrangler. Every
// `auth token` run appends a line to <dir>/calls and dumps its environment to
// <dir>/env; `--version` prints version without counting as a call.
type fakeWrangler struct {
	dir  string
	path string
}

// newFakeWrangler writes a fake wrangler whose `auth token` behaviour is body
// (POSIX sh). In body, $DIR is the fake's directory and $N the 1-based number
// of the current `auth token` call.
func newFakeWrangler(t *testing.T, version, body string) *fakeWrangler {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake wrangler is a POSIX shell script")
	}
	dir := t.TempDir()
	script := fmt.Sprintf(`#!/bin/sh
DIR='%s'
if [ "$1" = "--version" ]; then
  echo "%s"
  exit 0
fi
echo call >> "$DIR/calls"
N=$(wc -l < "$DIR/calls" | tr -d ' ')
env > "$DIR/env"
%s
`, dir, version, body)
	path := filepath.Join(dir, "wrangler")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return &fakeWrangler{dir: dir, path: path}
}

// oauthBody prints a pretty-printed OAuth token "tok-<N>", like wrangler does.
const oauthBody = `printf '{\n    "type": "oauth",\n    "token": "tok-%s"\n}\n' "$N"`

func (f *fakeWrangler) calls(t *testing.T) int {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.dir, "calls"))
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(b), "\n")
}

func (f *fakeWrangler) env(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.dir, "env"))
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			env[k] = v
		}
	}
	return env
}

// source builds a TokenSource on the fake, with a private lock file.
func (f *fakeWrangler) source(t *testing.T, mutate ...func(*Config)) *TokenSource {
	t.Helper()
	cfg := Config{
		Command:  []string{f.path},
		Timeout:  10 * time.Second,
		LockPath: filepath.Join(t.TempDir(), "wrangler-auth.lock"),
	}
	for _, m := range mutate {
		m(&cfg)
	}
	s, err := NewTokenSource(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// clearCredentialEnv makes the tests independent of the developer's shell.
func clearCredentialEnv(t *testing.T) {
	t.Helper()
	for _, name := range append([]string{ProfileEnvVarKey}, CredentialEnvVars...) {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
}
