package wranglerauth

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// configureEnv isolates Configure from the developer's environment; HOME is
// moved so that the default lock file lands in a temporary directory.
func configureEnv(t *testing.T) {
	t.Helper()
	clearCredentialEnv(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", "")
	for _, name := range []string{UseWranglerAuthEnvVarKey, WranglerCommandEnvVarKey, WranglerTimeoutEnvVarKey, WranglerTokenTTLEnvVarKey} {
		t.Setenv(name, "")
	}
}

func enabledModel(command string) ProviderModel {
	return ProviderModel{
		UseWranglerAuth: types.BoolValue(true),
		WranglerCommand: types.StringValue(command),
		WranglerProfile: types.StringNull(),
	}
}

func nullCredentials() Credentials {
	return Credentials{
		APIToken:          types.StringNull(),
		APIKey:            types.StringNull(),
		Email:             types.StringNull(),
		APIUserServiceKey: types.StringNull(),
	}
}

func diagText(d diag.Diagnostics) string {
	var b strings.Builder
	for _, x := range d {
		b.WriteString(x.Summary() + ": " + x.Detail() + "\n")
	}
	return b.String()
}

func TestConfigureDisabled(t *testing.T) {
	configureEnv(t)
	var diags diag.Diagnostics
	m := ProviderModel{UseWranglerAuth: types.BoolNull(), WranglerCommand: types.StringNull(), WranglerProfile: types.StringNull()}
	if opts := Configure(context.Background(), m, nullCredentials(), &diags); opts != nil || len(diags) != 0 {
		t.Fatalf("opts=%v diags=%s", opts, diagText(diags))
	}
}

func TestConfigureExplicitFalseWinsOverEnv(t *testing.T) {
	configureEnv(t)
	t.Setenv(UseWranglerAuthEnvVarKey, "true")
	var diags diag.Diagnostics
	m := ProviderModel{UseWranglerAuth: types.BoolValue(false), WranglerCommand: types.StringNull(), WranglerProfile: types.StringNull()}
	if opts := Configure(context.Background(), m, nullCredentials(), &diags); opts != nil || len(diags) != 0 {
		t.Fatalf("opts=%v diags=%s", opts, diagText(diags))
	}
}

func TestConfigureEnabledFromEnv(t *testing.T) {
	configureEnv(t)
	f := newFakeWrangler(t, "4.162.0", oauthBody)
	t.Setenv(UseWranglerAuthEnvVarKey, "1")
	t.Setenv(WranglerCommandEnvVarKey, f.path)
	var diags diag.Diagnostics
	m := ProviderModel{UseWranglerAuth: types.BoolNull(), WranglerCommand: types.StringNull(), WranglerProfile: types.StringNull()}
	opts := Configure(context.Background(), m, nullCredentials(), &diags)
	if diags.HasError() || len(opts) != 1 {
		t.Fatalf("opts=%v diags=%s", opts, diagText(diags))
	}
	if n := f.calls(t); n != 1 {
		t.Fatalf("Configure must fetch the first token (fail fast); wrangler ran %d times", n)
	}
}

func TestConfigureInvalidEnv(t *testing.T) {
	for name, value := range map[string]string{
		UseWranglerAuthEnvVarKey:  "maybe",
		WranglerTimeoutEnvVarKey:  "soon",
		WranglerTokenTTLEnvVarKey: "-5m",
	} {
		t.Run(name, func(t *testing.T) {
			configureEnv(t)
			f := newFakeWrangler(t, "4.162.0", oauthBody)
			t.Setenv(name, value)
			m := enabledModel(f.path)
			if name == UseWranglerAuthEnvVarKey {
				m.UseWranglerAuth = types.BoolNull()
			}
			var diags diag.Diagnostics
			if opts := Configure(context.Background(), m, nullCredentials(), &diags); opts != nil || !diags.HasError() {
				t.Fatalf("want an error, got opts=%v diags=%s", opts, diagText(diags))
			}
			if !strings.Contains(diagText(diags), name) {
				t.Fatalf("error should name %s: %s", name, diagText(diags))
			}
		})
	}
}

func TestConfigureConflictingCredentials(t *testing.T) {
	configureEnv(t)
	f := newFakeWrangler(t, "4.162.0", oauthBody)
	for _, tc := range []struct {
		name  string
		creds func(*Credentials)
		want  string
	}{
		{"api_token", func(c *Credentials) { c.APIToken = types.StringValue("x") }, "api_token"},
		{"api_key and email", func(c *Credentials) { c.APIKey = types.StringValue("k"); c.Email = types.StringValue("e") }, "api_key, email"},
		{"api_user_service_key", func(c *Credentials) { c.APIUserServiceKey = types.StringValue("v1.0-x") }, "api_user_service_key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			creds := nullCredentials()
			tc.creds(&creds)
			var diags diag.Diagnostics
			if opts := Configure(context.Background(), enabledModel(f.path), creds, &diags); opts != nil || !diags.HasError() {
				t.Fatalf("want an error, got opts=%v diags=%s", opts, diagText(diags))
			}
			if !strings.Contains(diagText(diags), tc.want) {
				t.Fatalf("error should name %q: %s", tc.want, diagText(diags))
			}
		})
	}
	if n := f.calls(t); n != 0 {
		t.Fatalf("wrangler ran %d times despite the configuration error", n)
	}
}

func TestConfigureConflictWhenEnabledFromEnv(t *testing.T) {
	configureEnv(t)
	t.Setenv(UseWranglerAuthEnvVarKey, "true")
	creds := nullCredentials()
	creds.APIToken = types.StringValue("x")
	m := ProviderModel{UseWranglerAuth: types.BoolNull(), WranglerCommand: types.StringNull(), WranglerProfile: types.StringNull()}
	var diags diag.Diagnostics
	if Configure(context.Background(), m, creds, &diags); !diags.HasError() {
		t.Fatal("api_token in HCL with CLOUDFLARE_USE_WRANGLER_AUTH=true must fail")
	}
}

func TestConfigureWarnsAboutCredentialEnv(t *testing.T) {
	configureEnv(t)
	f := newFakeWrangler(t, "4.162.0", oauthBody)
	t.Setenv("CLOUDFLARE_API_TOKEN", "env-token")
	t.Setenv("CLOUDFLARE_EMAIL", "a@example.com")
	var diags diag.Diagnostics
	opts := Configure(context.Background(), enabledModel(f.path), nullCredentials(), &diags)
	if diags.HasError() || len(opts) != 1 {
		t.Fatalf("opts=%v diags=%s", opts, diagText(diags))
	}
	if diags.WarningsCount() != 1 {
		t.Fatalf("want one warning, got %s", diagText(diags))
	}
	text := diagText(diags)
	if !strings.Contains(text, "CLOUDFLARE_API_TOKEN, CLOUDFLARE_EMAIL") || strings.Contains(text, "env-token") {
		t.Fatalf("warning should name the variables and never their values: %s", text)
	}
	if _, ok := f.env(t)["CLOUDFLARE_API_TOKEN"]; ok {
		t.Fatal("CLOUDFLARE_API_TOKEN reached wrangler")
	}
}

func TestConfigureFailsFast(t *testing.T) {
	configureEnv(t)
	f := newFakeWrangler(t, "4.162.0", `echo "Not logged in. Please run `+"`wrangler login`"+` to authenticate." >&2; exit 1`)
	var diags diag.Diagnostics
	if opts := Configure(context.Background(), enabledModel(f.path), nullCredentials(), &diags); opts != nil || !diags.HasError() {
		t.Fatalf("want an error, got opts=%v diags=%s", opts, diagText(diags))
	}
	if text := diagText(diags); !strings.Contains(text, "login`") {
		t.Fatalf("error should tell how to log in: %s", text)
	}
}

func TestConfigureInvalidCommand(t *testing.T) {
	configureEnv(t)
	var diags diag.Diagnostics
	if Configure(context.Background(), enabledModel(`npx "wrangler`), nullCredentials(), &diags); !diags.HasError() {
		t.Fatal("an unterminated quote must be rejected")
	}
}

func TestConfigureNeverLeaksToken(t *testing.T) {
	configureEnv(t)
	const secret = "SECRET-from-dotenv"
	f := newFakeWrangler(t, "4.162.0", `printf '{"type":"api_token","token":"`+secret+`"}\n'; echo "`+secret+`" >&2`)
	var diags diag.Diagnostics
	Configure(context.Background(), enabledModel(f.path), nullCredentials(), &diags)
	if !diags.HasError() {
		t.Fatal("an api_token answer must be rejected")
	}
	if strings.Contains(diagText(diags), secret) {
		t.Fatalf("diagnostics leak the token: %s", diagText(diags))
	}
}
