// This file is intentionally NOT code-generated (fork patch: wrangler OAuth auth).

package internal_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/terraform-provider-cloudflare/internal"
	"github.com/cloudflare/terraform-provider-cloudflare/internal/consts"
	"github.com/cloudflare/terraform-provider-cloudflare/internal/wranglerauth"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// fakeWranglerCommand writes a shell script that answers
// `wrangler auth token --json` with the given OAuth token.
func fakeWranglerCommand(t *testing.T, token string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake wrangler is a POSIX shell script")
	}
	path := filepath.Join(t.TempDir(), "wrangler")
	script := fmt.Sprintf("#!/bin/sh\nprintf '{\\n    \"type\": \"oauth\",\\n    \"token\": \"%s\"\\n}\\n'\n", token)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// isolateWranglerEnv keeps the test independent of the developer's shell and
// keeps the lock file out of the real user cache directory.
func isolateWranglerEnv(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", "")
	for _, name := range append([]string{
		wranglerauth.UseWranglerAuthEnvVarKey,
		wranglerauth.WranglerCommandEnvVarKey,
		wranglerauth.ProfileEnvVarKey,
	}, wranglerauth.CredentialEnvVars...) {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWranglerAuthEndToEnd(t *testing.T) {
	isolateWranglerEnv(t)
	// These would normally authenticate the client (cloudflare-go reads them
	// in DefaultClientOptions); in wrangler mode they must not be sent.
	t.Setenv("CLOUDFLARE_API_TOKEN", strings.Repeat("e", 40))
	t.Setenv("CLOUDFLARE_API_KEY", strings.Repeat("k", 37))
	t.Setenv("CLOUDFLARE_EMAIL", "env@example.com")

	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{}}`))
	}))
	defer srv.Close()

	ctx := context.Background()
	resp := provider.ConfigureResponse{}
	internal.NewProvider(testProviderVersion)().Configure(ctx, provider.ConfigureRequest{
		TerraformVersion: testTerraformVersion,
		Config: providerConfig(t, ctx, map[string]tftypes.Value{
			consts.BaseURLSchemaKey:               tftypes.NewValue(tftypes.String, srv.URL),
			wranglerauth.UseWranglerAuthSchemaKey: tftypes.NewValue(tftypes.Bool, true),
			wranglerauth.WranglerCommandSchemaKey: tftypes.NewValue(tftypes.String, fakeWranglerCommand(t, "oauth-token-123")),
		}),
	}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Configure failed: %v", resp.Diagnostics)
	}
	if resp.Diagnostics.WarningsCount() != 1 {
		t.Fatalf("want one warning about the ignored environment variables, got %v", resp.Diagnostics)
	}

	client, ok := resp.ResourceData.(*cloudflare.Client)
	if !ok {
		t.Fatalf("ResourceData is %T", resp.ResourceData)
	}
	var res map[string]any
	if err := client.Get(ctx, "user", nil, &res); err != nil {
		t.Fatalf("GET /user: %v", err)
	}
	if a := got.Get("Authorization"); a != "Bearer oauth-token-123" {
		t.Fatalf("Authorization = %q, want the wrangler token", a)
	}
	for _, name := range []string{"X-Auth-Key", "X-Auth-Email"} {
		if v := got.Get(name); v != "" {
			t.Errorf("%s was sent from the environment: %q", name, v)
		}
	}
}

func TestWranglerAuthValidateRejectsAPIToken(t *testing.T) {
	isolateWranglerEnv(t)
	ctx := context.Background()
	cfg := providerConfig(t, ctx, map[string]tftypes.Value{
		consts.APITokenSchemaKey:              tftypes.NewValue(tftypes.String, strings.Repeat("a", 40)),
		wranglerauth.UseWranglerAuthSchemaKey: tftypes.NewValue(tftypes.Bool, true),
	})
	dv, err := tfprotov6.NewDynamicValue(cfg.Raw.Type(), cfg.Raw)
	if err != nil {
		t.Fatal(err)
	}
	server := providerserver.NewProtocol6(internal.NewProvider(testProviderVersion)())()
	resp, err := server.ValidateProviderConfig(ctx, &tfprotov6.ValidateProviderConfigRequest{Config: &dv})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range resp.Diagnostics {
		if d.Severity == tfprotov6.DiagnosticSeverityError && strings.Contains(d.Detail, "api_token") {
			return
		}
	}
	t.Fatalf("want an error about api_token at validate time, got %v", resp.Diagnostics)
}

func TestWranglerAuthOffByDefault(t *testing.T) {
	isolateWranglerEnv(t)
	t.Setenv(wranglerauth.WranglerCommandEnvVarKey, filepath.Join(t.TempDir(), "missing-wrangler"))
	// Without use_wrangler_auth, wrangler is never run, even if configured.
	if ua := configureAndCaptureUserAgent(t, map[string]tftypes.Value{
		consts.APITokenSchemaKey: tftypes.NewValue(tftypes.String, strings.Repeat("a", 40)),
	}); ua == "" {
		t.Fatal("no request sent")
	}
}
