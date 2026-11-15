package wranglerauth

import (
	"io"
	"net/http"

	"github.com/cloudflare/cloudflare-go/v7/option"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Middleware authenticates every request with the wrangler OAuth token.
//
// It overwrites Authorization and removes X-Auth-Key, X-Auth-Email and
// X-Auth-User-Service-Key, which cloudflare-go may have set from the
// environment (DefaultClientOptions reads CLOUDFLARE_API_TOKEN & co. on its
// own). Installed as a client option, it runs before the per-request logging
// middleware, which redacts the Authorization header.
//
// On a 401 it refreshes the token, then replays the request once with the new
// token if the body can be replayed (no body, or req.GetBody set). Otherwise
// the 401 is returned as is, and the next request uses the new token.
func (s *TokenSource) Middleware() option.Middleware {
	return func(req *http.Request, next option.MiddlewareNext) (*http.Response, error) {
		ctx := req.Context()
		token, err := s.Token(ctx)
		if err != nil {
			return nil, err
		}

		res, err := next(authorize(req, token))
		if err != nil || res == nil || res.StatusCode != http.StatusUnauthorized {
			return res, err
		}

		tflog.Debug(ctx, "wranglerauth: the API answered 401, refreshing the wrangler token")
		fresh, rerr := s.Refresh(ctx, token)
		if rerr != nil {
			tflog.Warn(ctx, "wranglerauth: could not refresh the token after a 401", map[string]any{"error": rerr.Error()})
			return res, nil
		}
		if fresh == token || !replayable(req) {
			return res, nil
		}

		retry := req.Clone(ctx)
		if req.Body != nil && req.Body != http.NoBody {
			body, berr := req.GetBody()
			if berr != nil {
				return res, nil
			}
			retry.Body = body
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
		_ = res.Body.Close()
		return next(authorize(retry, fresh))
	}
}

func authorize(req *http.Request, token string) *http.Request {
	r := req.Clone(req.Context())
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Del("X-Auth-Key")
	r.Header.Del("X-Auth-Email")
	r.Header.Del("X-Auth-User-Service-Key")
	return r
}

func replayable(req *http.Request) bool {
	return req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
}
