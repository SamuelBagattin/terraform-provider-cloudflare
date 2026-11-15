package wranglerauth

import (
	"errors"
	"regexp"
	"strings"
)

// Sentinel errors, usable with errors.Is on the *Error values returned by
// [TokenSource].
var (
	ErrNotFound       = errors.New("wrangler executable not found")
	ErrTooOld         = errors.New("wrangler version too old")
	ErrNotLoggedIn    = errors.New("wrangler is not logged in")
	ErrWrongTokenType = errors.New("wrangler did not return an OAuth token")
	ErrTimeout        = errors.New("wrangler timed out")
	ErrFailed         = errors.New("wrangler failed")
)

// Error describes a failed attempt to get a token from wrangler.
//
// It never contains the token: Detail is written by this package, and Stderr
// is wrangler's standard error, stripped of ANSI codes, truncated and with any
// known secret redacted. Wrangler's standard output is never included because
// that is where it prints the token.
type Error struct {
	Kind   error
	Detail string
	Stderr string
}

func (e *Error) Error() string {
	if e.Stderr == "" {
		return e.Detail
	}
	return e.Detail + "\n\nwrangler stderr:\n" + e.Stderr
}

func (e *Error) Unwrap() error { return e.Kind }

const maxStderrExcerpt = 4 << 10

var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

// stderrExcerpt prepares wrangler's standard error for an error message:
// colour codes removed, secrets redacted, and at most maxStderrExcerpt bytes
// (the end is kept, since that is where wrangler prints the error).
func stderrExcerpt(stderr []byte, secrets ...string) string {
	s := ansiEscape.ReplaceAllString(string(stderr), "")
	for _, secret := range secrets {
		if secret != "" {
			s = strings.ReplaceAll(s, secret, "[redacted]")
		}
	}
	s = strings.TrimSpace(s)
	if len(s) > maxStderrExcerpt {
		s = "[...]" + s[len(s)-maxStderrExcerpt:]
	}
	// Diagnostics travel as protobuf strings, which must be valid UTF-8: the
	// cut above may split a character, and wrangler's output is not trusted.
	return strings.ToValidUTF8(s, "")
}
