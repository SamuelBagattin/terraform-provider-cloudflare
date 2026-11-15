package wranglerauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
)

const (
	// ProfileEnvVarKey is read by wrangler (>= 4.159.0) to select an auth profile.
	ProfileEnvVarKey = "CLOUDFLARE_AUTH_PROFILE"

	maxStdout = 1 << 20
	maxStderr = 64 << 10
	// waitDelay bounds how long Wait keeps reading the pipes after the process
	// was killed, in case a grandchild (e.g. node started by npx) holds them.
	waitDelay = 2 * time.Second
	// maxJSONCandidates bounds the scan for the JSON object in stdout.
	maxJSONCandidates = 1000
)

// CredentialEnvVars are the variables that make wrangler return them instead
// of the OAuth token. They are removed from wrangler's environment. The CF_*
// names are deprecated aliases that wrangler still honours.
var CredentialEnvVars = []string{
	"CLOUDFLARE_API_TOKEN",
	"CLOUDFLARE_API_KEY",
	"CLOUDFLARE_EMAIL",
	"CLOUDFLARE_API_USER_SERVICE_KEY",
	"CF_API_TOKEN",
	"CF_API_KEY",
	"CF_EMAIL",
}

// environ is the environment of the wrangler process: ours, minus the
// credential variables, with the requested profile and without colours.
func (s *TokenSource) environ() []string {
	env := os.Environ()
	out := make([]string, 0, len(env)+2)
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		switch {
		case slices.ContainsFunc(CredentialEnvVars, func(v string) bool { return strings.EqualFold(v, name) }):
		case strings.EqualFold(name, "FORCE_COLOR"):
		case s.cfg.Profile != "" && strings.EqualFold(name, ProfileEnvVarKey):
		default:
			out = append(out, kv)
		}
	}
	if s.cfg.Profile != "" {
		out = append(out, ProfileEnvVarKey+"="+s.cfg.Profile)
	}
	return append(out, "FORCE_COLOR=0")
}

// profileRequested reports whether wrangler will be asked for a profile, from
// our configuration or from the inherited environment.
func (s *TokenSource) profileRequested() bool {
	if s.cfg.Profile != "" {
		return true
	}
	v, ok := os.LookupEnv(ProfileEnvVarKey)
	return ok && v != ""
}

// limitedBuffer keeps the first max bytes written and discards the rest, so a
// misbehaving wrangler cannot make the provider buffer unbounded output.
type limitedBuffer struct {
	buf bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); room > 0 {
		b.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// run executes wrangler with args. stdin is the null device, so wrangler never
// sees a terminal and cannot prompt or start an interactive login. The process
// (and its process group, where supported) is killed after the timeout.
//
// A non-nil error is either a *Error (not found, timeout), the caller's
// context error, or an *exec.ExitError for a non-zero exit status.
func (s *TokenSource) run(ctx context.Context, args ...string) (stdout, stderr []byte, err error) {
	runCtx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()

	argv := append(slices.Clone(s.cfg.Command), args...)
	cmd := exec.CommandContext(runCtx, argv[0], argv[1:]...)
	cmd.Env = s.environ()
	cmd.Stdin = nil // the null device
	outBuf := &limitedBuffer{max: maxStdout}
	errBuf := &limitedBuffer{max: maxStderr}
	cmd.Stdout = outBuf
	cmd.Stderr = errBuf
	cmd.WaitDelay = waitDelay
	setProcessGroup(cmd)

	err = cmd.Run()
	stdout, stderr = outBuf.buf.Bytes(), errBuf.buf.Bytes()
	switch {
	case err == nil:
		return stdout, stderr, nil
	case errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist):
		return nil, stderr, &Error{
			Kind: ErrNotFound,
			Detail: fmt.Sprintf("Could not run %q: %v. Install wrangler >= %s (for example `npm install --global wrangler`), "+
				"or set wrangler_command (CLOUDFLARE_WRANGLER_COMMAND), for example to \"npx wrangler\".",
				s.commandString(), err, minVersion),
		}
	case ctx.Err() != nil:
		return nil, stderr, ctx.Err()
	case runCtx.Err() != nil:
		return nil, stderr, &Error{
			Kind: ErrTimeout,
			Detail: fmt.Sprintf("%q did not finish within %s and was stopped. A first `npx wrangler` run may need to download wrangler: "+
				"run it once by hand, or raise CLOUDFLARE_WRANGLER_TIMEOUT.", s.commandString()+" "+strings.Join(args, " "), s.cfg.Timeout),
			Stderr: stderrExcerpt(stderr),
		}
	default:
		return stdout, stderr, err
	}
}

func (s *TokenSource) commandString() string {
	return strings.Join(s.cfg.Command, " ")
}

// tokenResponse is the output of `wrangler auth token --json`:
// {"type":"oauth","token":…}, {"type":"api_token","token":…} or
// {"type":"api_key","key":…,"email":…}.
type tokenResponse struct {
	Type  string `json:"type"`
	Token string `json:"token"`
	Key   string `json:"key"`
}

func (r tokenResponse) secrets() []string { return []string{r.Token, r.Key} }

var knownTokenTypes = []string{"oauth", "api_token", "api_key"}

// parseTokenResponse finds the JSON object in wrangler's stdout. Wrangler
// pretty-prints it, and other lines (proxy notices, warnings, update hints)
// may surround it, so every '{' is tried as the start of a JSON value. An
// object whose type is a known token type wins over any other object that
// happens to have a "type" field.
func parseTokenResponse(stdout []byte) (tokenResponse, bool) {
	var fallback *tokenResponse
	for i, n := 0, 0; i < len(stdout) && n < maxJSONCandidates; i, n = i+1, n+1 {
		j := bytes.IndexByte(stdout[i:], '{')
		if j < 0 {
			break
		}
		i += j
		var r tokenResponse
		if err := json.NewDecoder(bytes.NewReader(stdout[i:])).Decode(&r); err != nil || r.Type == "" {
			continue
		}
		if slices.Contains(knownTokenTypes, r.Type) {
			return r, true
		}
		if fallback == nil {
			fallback = &r
		}
	}
	if fallback != nil {
		return *fallback, true
	}
	return tokenResponse{}, false
}
