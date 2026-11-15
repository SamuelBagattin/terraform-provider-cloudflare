package wranglerauth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

func TestTokenOAuth(t *testing.T) {
	clearCredentialEnv(t)
	f := newFakeWrangler(t, "4.162.0", oauthBody)
	tok, err := f.source(t).Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok != "tok-1" {
		t.Fatalf("token = %q, want tok-1", tok)
	}
}

func TestTokenNoisyOutput(t *testing.T) {
	clearCredentialEnv(t)
	f := newFakeWrangler(t, "4.162.0", `
echo "Proxy environment variables detected. We'll use your proxy for fetch requests."
echo '▲ [WARNING] something odd happened {not json}'
echo '{"type": "update-check", "latest": "9.9.9"}'
printf '{\n    "type": "oauth",\n    "token": "tok-noisy"\n}\n'
echo 'trailing line with a { brace'
echo 'some warning on stderr' >&2`)
	tok, err := f.source(t).Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok != "tok-noisy" {
		t.Fatalf("token = %q, want tok-noisy", tok)
	}
}

func TestTokenRejectsAPIToken(t *testing.T) {
	clearCredentialEnv(t)
	const secret = "SECRET-api-token-value"
	f := newFakeWrangler(t, "4.162.0", `
printf '{\n    "type": "api_token",\n    "token": "`+secret+`"\n}\n'
echo "debug: using `+secret+`" >&2`)
	_, err := f.source(t).Token(context.Background())
	if !errors.Is(err, ErrWrongTokenType) {
		t.Fatalf("err = %v, want ErrWrongTokenType", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaks the token: %v", err)
	}
	if !strings.Contains(err.Error(), "api_token") {
		t.Fatalf("error should name the type: %v", err)
	}
}

func TestTokenRejectsAPIKey(t *testing.T) {
	clearCredentialEnv(t)
	const secret = "SECRET-global-api-key"
	f := newFakeWrangler(t, "4.162.0", `
printf '{"type":"api_key","key":"`+secret+`","email":"a@example.com"}\n'
echo "`+secret+`" >&2`)
	_, err := f.source(t).Token(context.Background())
	if !errors.Is(err, ErrWrongTokenType) {
		t.Fatalf("err = %v, want ErrWrongTokenType", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaks the key: %v", err)
	}
}

func TestTokenNotLoggedIn(t *testing.T) {
	clearCredentialEnv(t)
	f := newFakeWrangler(t, "4.162.0", `
printf '\033[31m✘ [ERROR]\033[0m Not logged in. Please run `+"`wrangler login`"+` to authenticate.\n' >&2
exit 1`)
	_, err := f.source(t).Token(context.Background())
	if !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("err = %v, want ErrNotLoggedIn", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "login`") {
		t.Fatalf("error should tell how to log in: %v", msg)
	}
	if strings.Contains(msg, "\033") {
		t.Fatalf("error keeps ANSI codes: %q", msg)
	}
}

func TestTokenNotLoggedInProfileHint(t *testing.T) {
	clearCredentialEnv(t)
	f := newFakeWrangler(t, "4.162.0", `echo "Not logged in." >&2; exit 1`)
	_, err := f.source(t, func(c *Config) { c.Profile = "work" }).Token(context.Background())
	if !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("err = %v, want ErrNotLoggedIn", err)
	}
	if !strings.Contains(err.Error(), "auth create work") {
		t.Fatalf("error should point to `wrangler auth create work`: %v", err)
	}
}

func TestTokenWranglerTooOld(t *testing.T) {
	clearCredentialEnv(t)
	f := newFakeWrangler(t, "4.56.0", `echo "Unknown arguments: json, auth, token" >&2; exit 1`)
	_, err := f.source(t).Token(context.Background())
	if !errors.Is(err, ErrTooOld) {
		t.Fatalf("err = %v, want ErrTooOld", err)
	}
	if !strings.Contains(err.Error(), "4.56.0") || !strings.Contains(err.Error(), "4.57.0") {
		t.Fatalf("error should give both versions: %v", err)
	}
}

func TestTokenProfileNeedsRecentWrangler(t *testing.T) {
	clearCredentialEnv(t)
	f := newFakeWrangler(t, "4.120.0", oauthBody)
	_, err := f.source(t, func(c *Config) { c.Profile = "work" }).Token(context.Background())
	if !errors.Is(err, ErrTooOld) {
		t.Fatalf("err = %v, want ErrTooOld", err)
	}
	if !strings.Contains(err.Error(), "4.159.0") {
		t.Fatalf("error should give the minimum version: %v", err)
	}
	if n := f.calls(t); n != 0 {
		t.Fatalf("auth token ran %d times; it must not run when the profile cannot be honoured", n)
	}
}

func TestTokenInheritedProfileNeedsRecentWrangler(t *testing.T) {
	clearCredentialEnv(t)
	t.Setenv(ProfileEnvVarKey, "inherited")
	f := newFakeWrangler(t, "4.158.9", oauthBody)
	if _, err := f.source(t).Token(context.Background()); !errors.Is(err, ErrTooOld) {
		t.Fatalf("err = %v, want ErrTooOld", err)
	}
}

func TestTokenMalformedOutput(t *testing.T) {
	clearCredentialEnv(t)
	f := newFakeWrangler(t, "4.162.0", `echo "hello"`)
	_, err := f.source(t).Token(context.Background())
	if !errors.Is(err, ErrFailed) {
		t.Fatalf("err = %v, want ErrFailed", err)
	}
}

func TestTokenUnexpectedFailure(t *testing.T) {
	clearCredentialEnv(t)
	f := newFakeWrangler(t, "4.162.0", `echo "boom: keyring locked" >&2; exit 3`)
	_, err := f.source(t).Token(context.Background())
	if !errors.Is(err, ErrFailed) {
		t.Fatalf("err = %v, want ErrFailed", err)
	}
	if !strings.Contains(err.Error(), "keyring locked") {
		t.Fatalf("error should carry wrangler's stderr: %v", err)
	}
}

func TestTokenNotFound(t *testing.T) {
	clearCredentialEnv(t)
	for _, command := range [][]string{
		{filepath.Join(t.TempDir(), "missing", "wrangler")},
		{"wrangler-that-does-not-exist-4242"},
	} {
		s, err := NewTokenSource(Config{Command: command, LockPath: filepath.Join(t.TempDir(), "lock")})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Token(context.Background()); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%v: err = %v, want ErrNotFound", command, err)
		}
	}
}

func TestTokenTimeout(t *testing.T) {
	clearCredentialEnv(t)
	f := newFakeWrangler(t, "4.162.0", `sleep 5; `+oauthBody)
	s := f.source(t, func(c *Config) { c.Timeout = 300 * time.Millisecond })
	start := time.Now()
	_, err := s.Token(context.Background())
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("Token returned after %s; the process group was not killed", elapsed)
	}
}

func TestTokenCallerCancellation(t *testing.T) {
	clearCredentialEnv(t)
	f := newFakeWrangler(t, "4.162.0", `sleep 1; `+oauthBody)
	s := f.source(t)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := s.Token(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	// The shared run is not cancelled by the caller and still fills the cache.
	tok, err := s.Token(context.Background())
	if err != nil || tok != "tok-1" {
		t.Fatalf("Token = %q, %v; want tok-1", tok, err)
	}
	if n := f.calls(t); n != 1 {
		t.Fatalf("wrangler ran %d times, want 1", n)
	}
}

func TestTokenTTL(t *testing.T) {
	clearCredentialEnv(t)
	f := newFakeWrangler(t, "4.162.0", oauthBody)
	s := f.source(t, func(c *Config) { c.TTL = 5 * time.Minute })
	now := time.Now()
	s.now = func() time.Time { return now }
	ctx := context.Background()

	for _, step := range []struct {
		advance time.Duration
		want    string
		calls   int
	}{
		{0, "tok-1", 1},
		{4 * time.Minute, "tok-1", 1},
		{2 * time.Minute, "tok-2", 2}, // 6 min after the first fetch
		{time.Minute, "tok-2", 2},
	} {
		now = now.Add(step.advance)
		tok, err := s.Token(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if tok != step.want || f.calls(t) != step.calls {
			t.Fatalf("after +%s: token %q, %d calls; want %q, %d", step.advance, tok, f.calls(t), step.want, step.calls)
		}
	}
}

func TestTokenConcurrentCallersShareOneRun(t *testing.T) {
	clearCredentialEnv(t)
	f := newFakeWrangler(t, "4.162.0", `sleep 0.5; `+oauthBody)
	s := f.source(t)

	const callers = 20
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, err := s.Token(context.Background())
			if err == nil && tok != "tok-1" {
				err = errors.New("unexpected token " + tok)
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := f.calls(t); n != 1 {
		t.Fatalf("wrangler ran %d times for %d concurrent callers, want 1", n, callers)
	}
}

func TestRefreshDeduplicatesStaleToken(t *testing.T) {
	clearCredentialEnv(t)
	f := newFakeWrangler(t, "4.162.0", `sleep 0.3; `+oauthBody)
	s := f.source(t)
	ctx := context.Background()
	stale, err := s.Token(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Ten requests get a 401 with the same token at once: one wrangler run.
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if tok, err := s.Refresh(ctx, stale); err != nil || tok != "tok-2" {
				t.Errorf("Refresh = %q, %v; want tok-2", tok, err)
			}
		}()
	}
	wg.Wait()
	// A late 401 for the old token does not run wrangler again.
	if tok, err := s.Refresh(ctx, stale); err != nil || tok != "tok-2" {
		t.Fatalf("late Refresh = %q, %v; want tok-2", tok, err)
	}
	if n := f.calls(t); n != 2 {
		t.Fatalf("wrangler ran %d times, want 2", n)
	}
}

func TestWranglerEnvironment(t *testing.T) {
	clearCredentialEnv(t)
	for _, name := range CredentialEnvVars {
		t.Setenv(name, "must-not-reach-wrangler")
	}
	t.Setenv(ProfileEnvVarKey, "from-shell")
	t.Setenv("FORCE_COLOR", "1")
	t.Setenv("WRANGLERAUTH_TEST_KEEP", "kept")

	f := newFakeWrangler(t, "4.162.0", oauthBody)
	if _, err := f.source(t, func(c *Config) { c.Profile = "work" }).Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	env := f.env(t)
	for _, name := range CredentialEnvVars {
		if v, ok := env[name]; ok {
			t.Errorf("%s reached wrangler (%q)", name, v)
		}
	}
	if got := env[ProfileEnvVarKey]; got != "work" {
		t.Errorf("%s = %q, want work", ProfileEnvVarKey, got)
	}
	if got := env["FORCE_COLOR"]; got != "0" {
		t.Errorf("FORCE_COLOR = %q, want 0", got)
	}
	if got := env["WRANGLERAUTH_TEST_KEEP"]; got != "kept" {
		t.Errorf("unrelated variables must be kept, got %q", got)
	}
}

func TestWranglerEnvironmentKeepsInheritedProfile(t *testing.T) {
	clearCredentialEnv(t)
	t.Setenv(ProfileEnvVarKey, "from-shell")
	f := newFakeWrangler(t, "4.162.0", oauthBody)
	if _, err := f.source(t).Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := f.env(t)[ProfileEnvVarKey]; got != "from-shell" {
		t.Fatalf("%s = %q, want the inherited from-shell", ProfileEnvVarKey, got)
	}
}

func TestWranglerStdinIsEmpty(t *testing.T) {
	clearCredentialEnv(t)
	// A wrangler that waited for input would hang until the timeout.
	f := newFakeWrangler(t, "4.162.0", `if [ -t 0 ]; then touch "$DIR/tty"; fi; read -r line; `+oauthBody)
	if _, err := f.source(t, func(c *Config) { c.Timeout = 2 * time.Second }).Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "tty")); err == nil {
		t.Fatal("wrangler got a terminal on stdin")
	}
}

func TestLockSerialisesProcesses(t *testing.T) {
	clearCredentialEnv(t)
	// The fake records an overlap if two runs are inside it at the same time.
	f := newFakeWrangler(t, "4.162.0", `
if ! mkdir "$DIR/inflight" 2>/dev/null; then echo overlap >> "$DIR/overlap"; fi
sleep 0.3
rmdir "$DIR/inflight" 2>/dev/null
`+oauthBody)
	lock := filepath.Join(t.TempDir(), "shared.lock")
	// Two sources stand for two provider processes (e.g. two aliases).
	a := f.source(t, func(c *Config) { c.LockPath = lock })
	b := f.source(t, func(c *Config) { c.LockPath = lock })

	var wg sync.WaitGroup
	for _, s := range []*TokenSource{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Token(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if _, err := os.Stat(filepath.Join(f.dir, "overlap")); err == nil {
		t.Fatal("two wrangler runs overlapped despite the lock")
	}
	if n := f.calls(t); n != 2 {
		t.Fatalf("wrangler ran %d times, want 2", n)
	}
}

func TestStderrExcerptIsValidUTF8(t *testing.T) {
	// "é" is two bytes; the leading "x" puts the cut in the middle of one.
	long := []byte("x" + strings.Repeat("é", maxStderrExcerpt))
	got := stderrExcerpt(long)
	if !utf8.ValidString(got) {
		t.Fatal("excerpt is not valid UTF-8")
	}
	if !strings.HasPrefix(got, "[...]") || len(got) > maxStderrExcerpt+len("[...]") {
		t.Fatalf("excerpt not truncated: %d bytes", len(got))
	}
	if got := stderrExcerpt([]byte("bad \xff byte and secret-1 \x1b[31mred\x1b[0m"), "secret-1"); got != "bad  byte and [redacted] red" {
		t.Fatalf("got %q", got)
	}
}

func TestParseTokenResponse(t *testing.T) {
	for _, tc := range []struct {
		name, out, wantType, wantToken string
		found                          bool
	}{
		{"pretty", "{\n    \"type\": \"oauth\",\n    \"token\": \"a\"\n}\n", "oauth", "a", true},
		{"compact", `{"type":"oauth","token":"b"}`, "oauth", "b", true},
		{"known type wins", `{"type":"notice"} {"type":"oauth","token":"c"}`, "oauth", "c", true},
		{"other type as fallback", `{"type":"notice"}`, "notice", "", true},
		{"no type", `{"token":"x"}`, "", "", false},
		{"empty", "", "", "", false},
		{"garbage", "{{{ not json", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, found := parseTokenResponse([]byte(tc.out))
			if found != tc.found || r.Type != tc.wantType || r.Token != tc.wantToken {
				t.Fatalf("got %+v, %v; want type %q token %q, %v", r, found, tc.wantType, tc.wantToken, tc.found)
			}
		})
	}
}

func TestSplitCommand(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    []string
		wantErr bool
	}{
		{"wrangler", []string{"wrangler"}, false},
		{"  npx   wrangler ", []string{"npx", "wrangler"}, false},
		{`"/Applications/My Tools/wrangler" --flag`, []string{"/Applications/My Tools/wrangler", "--flag"}, false},
		{`pnpm exec 'wrangler'`, []string{"pnpm", "exec", "wrangler"}, false},
		{"", nil, true},
		{"   ", nil, true},
		{`"`, nil, true},
		{`npx "wrangler`, nil, true},
		{`"" wrangler`, nil, true},
	} {
		got, err := SplitCommand(tc.in)
		if (err != nil) != tc.wantErr || strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("SplitCommand(%q) = %q, %v; want %q, err %v", tc.in, got, err, tc.want, tc.wantErr)
		}
	}
}

func TestParseVersion(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want version
		ok   bool
	}{
		{"4.162.0\n", version{4, 162, 0}, true},
		{" ⛅️ wrangler 4.57.0 (update available 4.60.1)", version{4, 57, 0}, true},
		{"no version", version{}, false},
	} {
		got, ok := parseVersion(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("parseVersion(%q) = %v, %v; want %v, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
	if !(version{4, 56, 9}).less(minVersion) || (version{4, 57, 0}).less(minVersion) || (version{5, 0, 0}).less(minProfileVersion) {
		t.Fatal("version ordering is wrong")
	}
}
