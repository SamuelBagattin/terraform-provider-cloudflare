package wranglerauth

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"golang.org/x/sync/singleflight"
)

const (
	DefaultTimeout = 30 * time.Second
	DefaultTTL     = 5 * time.Minute
)

// Config configures a [TokenSource].
type Config struct {
	// Command is the argv prefix that runs wrangler, e.g. {"npx", "wrangler"}.
	Command []string
	// Profile, if set, is passed to wrangler as CLOUDFLARE_AUTH_PROFILE.
	Profile string
	// Timeout bounds each wrangler run, and the wait for the lock. Defaults to
	// DefaultTimeout.
	Timeout time.Duration
	// TTL is how long a token is reused before wrangler is asked again.
	// Wrangler does not say when its token expires, so this is short; a 401
	// from the API also forces a refresh. Defaults to DefaultTTL.
	TTL time.Duration
	// LockPath is the inter-process lock file. Defaults to DefaultLockPath().
	LockPath string
}

// TokenSource hands out the OAuth token of the local wrangler session.
// It is safe for concurrent use.
type TokenSource struct {
	cfg Config
	now func() time.Time

	mu             sync.Mutex
	token          string
	fetchedAt      time.Time
	profileChecked bool

	group singleflight.Group
}

func NewTokenSource(cfg Config) (*TokenSource, error) {
	if len(cfg.Command) == 0 || cfg.Command[0] == "" {
		return nil, errors.New("wranglerauth: empty wrangler command")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.TTL <= 0 {
		cfg.TTL = DefaultTTL
	}
	if cfg.LockPath == "" {
		cfg.LockPath = DefaultLockPath()
	}
	return &TokenSource{cfg: cfg, now: time.Now}, nil
}

// Token returns the cached token, or asks wrangler for one when the cache is
// empty or older than the TTL.
func (s *TokenSource) Token(ctx context.Context) (string, error) {
	if tok, ok := s.cached(""); ok {
		return tok, nil
	}
	return s.fetch(ctx)
}

// Refresh is called with a token the API rejected. It drops that token and
// asks wrangler again, unless another caller already replaced it, in which
// case the newer token is returned without running wrangler.
func (s *TokenSource) Refresh(ctx context.Context, stale string) (string, error) {
	if tok, ok := s.cached(stale); ok {
		return tok, nil
	}
	return s.fetch(ctx)
}

// cached returns the cached token if it is fresh and is not stale. A stale
// token found in the cache is dropped.
func (s *TokenSource) cached(stale string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && s.token == stale {
		s.token = ""
	}
	if s.token != "" && s.now().Sub(s.fetchedAt) < s.cfg.TTL {
		return s.token, true
	}
	return "", false
}

// fetch runs wrangler once for all concurrent callers.
func (s *TokenSource) fetch(ctx context.Context) (string, error) {
	ch := s.group.DoChan("token", func() (any, error) {
		// The run is shared by every waiting caller, so the first caller's
		// cancellation must not abort it; it has its own timeouts.
		tok, err := s.fetchFromWrangler(context.WithoutCancel(ctx))
		if err != nil {
			return "", err
		}
		s.mu.Lock()
		s.token, s.fetchedAt = tok, s.now()
		s.mu.Unlock()
		return tok, nil
	})
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case r := <-ch:
		if r.Err != nil {
			return "", r.Err
		}
		return r.Val.(string), nil
	}
}

func (s *TokenSource) fetchFromWrangler(ctx context.Context) (string, error) {
	if err := s.checkProfileSupport(ctx); err != nil {
		return "", err
	}

	lockCtx, cancel := context.WithTimeout(ctx, s.cfg.Timeout+waitDelay)
	release, err := acquireLock(lockCtx, s.cfg.LockPath)
	cancel()
	switch {
	case err == nil:
		defer release()
	case errors.Is(err, context.DeadlineExceeded):
		return "", &Error{
			Kind: ErrTimeout,
			Detail: fmt.Sprintf("Waited %s for the lock %s, held by another provider process running wrangler.",
				s.cfg.Timeout+waitDelay, s.cfg.LockPath),
		}
	default:
		tflog.Warn(ctx, "wranglerauth: cannot take the inter-process lock; running wrangler without it", map[string]any{
			"lock_path": s.cfg.LockPath,
			"error":     err.Error(),
		})
	}

	start := time.Now()
	tflog.Debug(ctx, "wranglerauth: running wrangler auth token", map[string]any{
		"command": s.commandString(),
		"profile": s.cfg.Profile,
	})
	stdout, stderr, runErr := s.run(ctx, "auth", "token", "--json")
	var exitErr *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exitErr) {
		return "", runErr
	}

	resp, found := parseTokenResponse(stdout)
	secrets := resp.secrets()
	if runErr == nil && found {
		if resp.Type != "oauth" {
			return "", &Error{
				Kind: ErrWrongTokenType,
				Detail: fmt.Sprintf("wrangler returned credentials of type %q instead of an OAuth token. "+
					"Wrangler does this when CLOUDFLARE_API_TOKEN or CLOUDFLARE_API_KEY/CLOUDFLARE_EMAIL are set. "+
					"The provider removes them from wrangler's environment, so they probably come from a .env file in the working directory: "+
					"remove them there, or configure the provider with api_token instead of use_wrangler_auth.", resp.Type),
				Stderr: stderrExcerpt(stderr, secrets...),
			}
		}
		if resp.Token == "" {
			return "", &Error{Kind: ErrFailed, Detail: "wrangler returned an empty OAuth token.", Stderr: stderrExcerpt(stderr)}
		}
		tflog.Debug(ctx, "wranglerauth: got an OAuth token from wrangler", map[string]any{
			"duration_ms": time.Since(start).Milliseconds(),
		})
		return resp.Token, nil
	}

	if notLoggedIn(stdout) || notLoggedIn(stderr) {
		return "", &Error{Kind: ErrNotLoggedIn, Detail: s.loginHint(), Stderr: stderrExcerpt(stderr, secrets...)}
	}
	if v, ok := s.version(ctx); ok && v.less(minVersion) {
		return "", &Error{
			Kind: ErrTooOld,
			Detail: fmt.Sprintf("wrangler %s is too old: `wrangler auth token --json` needs wrangler >= %s. "+
				"Upgrade it, for example with `npm install --global wrangler@latest`, or update the project's wrangler dependency when using npx.",
				v, minVersion),
			Stderr: stderrExcerpt(stderr, secrets...),
		}
	}
	detail := fmt.Sprintf("`%s auth token --json` failed: %v.", s.commandString(), runErr)
	if runErr == nil {
		detail = fmt.Sprintf("`%s auth token --json` printed no token. Check that wrangler_command runs wrangler >= %s.", s.commandString(), minVersion)
	}
	return "", &Error{Kind: ErrFailed, Detail: detail, Stderr: stderrExcerpt(stderr, secrets...)}
}

func notLoggedIn(out []byte) bool {
	return strings.Contains(strings.ToLower(string(out)), "not logged in")
}

func (s *TokenSource) loginHint() string {
	if s.cfg.Profile != "" {
		return fmt.Sprintf("wrangler has no valid OAuth session for profile %q. Run `%s auth create %s` to log in, then retry.",
			s.cfg.Profile, s.commandString(), s.cfg.Profile)
	}
	return fmt.Sprintf("wrangler has no valid OAuth session (never logged in, logged out, or the session could not be refreshed). "+
		"Run `%s login`, then retry.", s.commandString())
}

// version runs `wrangler --version`. It is only used to explain a failure or
// to check profile support, so it stays off the token path.
func (s *TokenSource) version(ctx context.Context) (version, bool) {
	stdout, _, err := s.run(ctx, "--version")
	if err != nil {
		return version{}, false
	}
	return parseVersion(string(stdout))
}

// checkProfileSupport makes sure wrangler honours CLOUDFLARE_AUTH_PROFILE when
// a profile is requested: older versions ignore it and would return the token
// of another login. Checked once per TokenSource.
func (s *TokenSource) checkProfileSupport(ctx context.Context) error {
	if !s.profileRequested() {
		return nil
	}
	s.mu.Lock()
	checked := s.profileChecked
	s.mu.Unlock()
	if checked {
		return nil
	}

	stdout, stderr, err := s.run(ctx, "--version")
	if err != nil {
		var e *Error
		if errors.As(err, &e) {
			return err
		}
		return &Error{
			Kind: ErrFailed,
			Detail: fmt.Sprintf("`%s --version` failed (%v). The wrangler version must be known to select an auth profile.",
				s.commandString(), err),
			Stderr: stderrExcerpt(stderr),
		}
	}
	v, ok := parseVersion(string(stdout))
	if !ok {
		return &Error{
			Kind:   ErrFailed,
			Detail: fmt.Sprintf("Could not read a version from `%s --version`. The wrangler version must be known to select an auth profile.", s.commandString()),
			Stderr: stderrExcerpt(stderr),
		}
	}
	if v.less(minProfileVersion) {
		return &Error{
			Kind: ErrTooOld,
			Detail: fmt.Sprintf("wrangler %s cannot select an auth profile: it reads CLOUDFLARE_AUTH_PROFILE from version %s on, "+
				"and older versions silently use another login. Upgrade wrangler, or remove wrangler_profile and unset CLOUDFLARE_AUTH_PROFILE.",
				v, minProfileVersion),
		}
	}
	s.mu.Lock()
	s.profileChecked = true
	s.mu.Unlock()
	return nil
}
