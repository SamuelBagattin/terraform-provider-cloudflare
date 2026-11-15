package wranglerauth

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// SplitCommand turns a wrangler_command value such as "npx wrangler" into an
// argv. Single and double quotes group words, so that paths with spaces work,
// but this is not a shell: no expansion, globbing, pipes or redirections.
func SplitCommand(s string) ([]string, error) {
	var (
		args  []string
		cur   strings.Builder
		inArg bool
		quote rune
	)
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
			inArg = true
		case unicode.IsSpace(r):
			if inArg {
				args = append(args, cur.String())
				cur.Reset()
				inArg = false
			}
		default:
			cur.WriteRune(r)
			inArg = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated %c quote in wrangler command %q", quote, s)
	}
	if inArg {
		args = append(args, cur.String())
	}
	if len(args) == 0 || args[0] == "" {
		return nil, errors.New("wrangler command is empty")
	}
	return args, nil
}

type version struct{ major, minor, patch int }

var (
	// minVersion is the first wrangler with `wrangler auth token --json`.
	minVersion = version{4, 57, 0}
	// minProfileVersion is the first wrangler that reads CLOUDFLARE_AUTH_PROFILE.
	// Older versions ignore the variable silently and would hand out the token
	// of another profile, so a profile requires at least this version.
	minProfileVersion = version{4, 159, 0}
)

var versionPattern = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)

// parseVersion extracts the first x.y.z from the output of `wrangler --version`.
func parseVersion(s string) (version, bool) {
	m := versionPattern.FindStringSubmatch(s)
	if m == nil {
		return version{}, false
	}
	var v version
	var err error
	if v.major, err = strconv.Atoi(m[1]); err != nil {
		return version{}, false
	}
	if v.minor, err = strconv.Atoi(m[2]); err != nil {
		return version{}, false
	}
	if v.patch, err = strconv.Atoi(m[3]); err != nil {
		return version{}, false
	}
	return v, true
}

func (v version) less(o version) bool {
	if v.major != o.major {
		return v.major < o.major
	}
	if v.minor != o.minor {
		return v.minor < o.minor
	}
	return v.patch < o.patch
}

func (v version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch)
}
