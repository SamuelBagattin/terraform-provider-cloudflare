package wranglerauth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// apiServer accepts only "Bearer <valid>" and records what it saw.
type apiServer struct {
	*httptest.Server
	valid string

	mu      sync.Mutex
	auths   []string
	bodies  []string
	headers []http.Header
}

func newAPIServer(t *testing.T, valid string) *apiServer {
	t.Helper()
	s := &apiServer{valid: valid}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.auths = append(s.auths, r.Header.Get("Authorization"))
		s.bodies = append(s.bodies, string(body))
		s.headers = append(s.headers, r.Header.Clone())
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer "+s.valid {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{}}`))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *apiServer) seen() (auths, bodies []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.auths...), append([]string(nil), s.bodies...)
}

func do(t *testing.T, ts *TokenSource, req *http.Request) *http.Response {
	t.Helper()
	res, err := ts.Middleware()(req, http.DefaultClient.Do)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	t.Cleanup(func() { _ = res.Body.Close() })
	return res
}

func TestMiddlewareSetsBearerAndStripsLegacyHeaders(t *testing.T) {
	clearCredentialEnv(t)
	f := newFakeWrangler(t, "4.162.0", oauthBody)
	srv := newAPIServer(t, "tok-1")

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/user", nil)
	req.Header.Set("Authorization", "Bearer from-environment")
	req.Header.Set("X-Auth-Key", "legacy-key")
	req.Header.Set("X-Auth-Email", "someone@example.com")
	req.Header.Set("X-Auth-User-Service-Key", "v1.0-service-key")
	if res := do(t, f.source(t), req); res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}

	srv.mu.Lock()
	h := srv.headers[0]
	srv.mu.Unlock()
	if got := h.Get("Authorization"); got != "Bearer tok-1" {
		t.Fatalf("Authorization = %q", got)
	}
	for _, name := range []string{"X-Auth-Key", "X-Auth-Email", "X-Auth-User-Service-Key"} {
		if v := h.Get(name); v != "" {
			t.Errorf("%s was sent: %q", name, v)
		}
	}
	if req.Header.Get("Authorization") != "Bearer from-environment" {
		t.Error("the caller's request was modified")
	}
}

func TestMiddleware401RefreshesAndRetriesOnce(t *testing.T) {
	clearCredentialEnv(t)
	f := newFakeWrangler(t, "4.162.0", oauthBody) // tok-1, then tok-2
	srv := newAPIServer(t, "tok-2")
	ts := f.source(t)

	// strings.Reader: http.NewRequest sets GetBody, so the body can be replayed.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/zones", strings.NewReader(`{"name":"example.com"}`))
	if res := do(t, ts, req); res.StatusCode != http.StatusOK {
		t.Fatalf("status %d after retry", res.StatusCode)
	}
	auths, bodies := srv.seen()
	if strings.Join(auths, ",") != "Bearer tok-1,Bearer tok-2" {
		t.Fatalf("server saw %q", auths)
	}
	for i, b := range bodies {
		if b != `{"name":"example.com"}` {
			t.Fatalf("attempt %d body = %q, want the original body", i+1, b)
		}
	}
	if n := f.calls(t); n != 2 {
		t.Fatalf("wrangler ran %d times, want 2", n)
	}
}

func TestMiddleware401RetriesOnlyOnce(t *testing.T) {
	clearCredentialEnv(t)
	f := newFakeWrangler(t, "4.162.0", oauthBody)
	srv := newAPIServer(t, "never-valid")

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/user", nil)
	if res := do(t, f.source(t), req); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", res.StatusCode)
	}
	if auths, _ := srv.seen(); len(auths) != 2 {
		t.Fatalf("server got %d requests, want 2 (one retry)", len(auths))
	}
}

func TestMiddleware401NoRetryWhenTokenUnchanged(t *testing.T) {
	clearCredentialEnv(t)
	f := newFakeWrangler(t, "4.162.0", `printf '{"type":"oauth","token":"same"}\n'`)
	srv := newAPIServer(t, "other")

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/user", nil)
	if res := do(t, f.source(t), req); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", res.StatusCode)
	}
	if auths, _ := srv.seen(); len(auths) != 1 {
		t.Fatalf("server got %d requests; replaying with the same token is pointless", len(auths))
	}
}

func TestMiddleware401BodyNotReplayable(t *testing.T) {
	clearCredentialEnv(t)
	f := newFakeWrangler(t, "4.162.0", oauthBody)
	srv := newAPIServer(t, "tok-2")
	ts := f.source(t)

	// io.NopCloser hides the reader type: no GetBody, the body is read once.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/zones", io.NopCloser(strings.NewReader("payload")))
	if req.GetBody != nil {
		t.Fatal("test setup: GetBody should be nil")
	}
	if res := do(t, ts, req); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d, want the original 401", res.StatusCode)
	}
	if auths, _ := srv.seen(); len(auths) != 1 {
		t.Fatalf("server got %d requests, want 1 (no retry without GetBody)", len(auths))
	}

	// The token was still refreshed, so the next request goes through.
	next, _ := http.NewRequest(http.MethodGet, srv.URL+"/user", nil)
	if res := do(t, ts, next); res.StatusCode != http.StatusOK {
		t.Fatalf("next request status %d", res.StatusCode)
	}
	if n := f.calls(t); n != 2 {
		t.Fatalf("wrangler ran %d times, want 2", n)
	}
}

func TestMiddlewareTokenError(t *testing.T) {
	clearCredentialEnv(t)
	f := newFakeWrangler(t, "4.162.0", `echo "Not logged in." >&2; exit 1`)
	srv := newAPIServer(t, "x")
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/user", nil)
	if _, err := f.source(t).Middleware()(req, http.DefaultClient.Do); err == nil {
		t.Fatal("expected an error")
	}
	if auths, _ := srv.seen(); len(auths) != 0 {
		t.Fatal("no request may be sent without a token")
	}
}
