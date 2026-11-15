package wranglerauth

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/cloudflare-go/v7/option"
	"github.com/cloudflare/terraform-provider-cloudflare/internal/consts"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	UseWranglerAuthSchemaKey = "use_wrangler_auth"
	WranglerCommandSchemaKey = "wrangler_command"
	WranglerProfileSchemaKey = "wrangler_profile"

	UseWranglerAuthEnvVarKey  = "CLOUDFLARE_USE_WRANGLER_AUTH"
	WranglerCommandEnvVarKey  = "CLOUDFLARE_WRANGLER_COMMAND"
	WranglerTimeoutEnvVarKey  = "CLOUDFLARE_WRANGLER_TIMEOUT"
	WranglerTokenTTLEnvVarKey = "CLOUDFLARE_WRANGLER_TOKEN_TTL"

	DefaultCommand = "wrangler"
)

// ProviderModel holds the provider attributes of this package. It is embedded
// by value in the provider model.
type ProviderModel struct {
	UseWranglerAuth types.Bool   `tfsdk:"use_wrangler_auth" json:"use_wrangler_auth"`
	WranglerCommand types.String `tfsdk:"wrangler_command" json:"wrangler_command"`
	WranglerProfile types.String `tfsdk:"wrangler_profile" json:"wrangler_profile"`
}

// Credentials are the provider's other credential attributes, as configured
// in HCL.
type Credentials struct {
	APIToken          types.String
	APIKey            types.String
	Email             types.String
	APIUserServiceKey types.String
}

// conflictingAttributes are the HCL attributes that cannot be combined with
// use_wrangler_auth. api_user_service_key is included: in wrangler mode the
// OAuth token is the only credential sent, which keeps the behaviour simple to
// reason about. Origin CA certificate endpoints therefore need a separate
// provider alias configured with an API token.
var conflictingAttributes = []string{
	consts.APITokenSchemaKey,
	consts.APIKeySchemaKey,
	consts.EmailSchemaKey,
	consts.APIUserServiceKeySchemaKey,
}

// ignoredEnvVars are the provider credential variables that are ignored, with
// a warning, in wrangler mode.
var ignoredEnvVars = []string{
	consts.APITokenEnvVarKey,
	consts.APIKeyEnvVarKey,
	consts.EmailEnvVarKey,
	consts.APIUserServiceKeyEnvVarKey,
}

// AddSchemaAttributes adds the wrangler attributes to the provider schema.
func AddSchemaAttributes(attrs map[string]schema.Attribute) {
	attrs[UseWranglerAuthSchemaKey] = schema.BoolAttribute{
		Optional: true,
		MarkdownDescription: fmt.Sprintf("Authenticate with the OAuth session of `wrangler login` instead of an API token. "+
			"The provider gets the token from `wrangler auth token --json` (wrangler >= %s) and asks again when it expires. "+
			"Meant for local workstations; use API tokens in CI. Wrangler's OAuth scopes are limited, so resources outside them fail with 403 errors. "+
			"Conflicts with `api_token`, `api_key`, `email` and `api_user_service_key`; their environment variables are ignored. "+
			"Alternatively, can be configured using the `%s` environment variable.", minVersion, UseWranglerAuthEnvVarKey),
		Validators: []validator.Bool{exclusiveCredentialsValidator{}},
	}
	attrs[WranglerCommandSchemaKey] = schema.StringAttribute{
		Optional: true,
		MarkdownDescription: fmt.Sprintf("Command that runs wrangler when `use_wrangler_auth` is enabled, for example `npx wrangler`. "+
			"It is split on spaces (quotes group words) and is not run through a shell. Defaults to `%s`. "+
			"Alternatively, can be configured using the `%s` environment variable.", DefaultCommand, WranglerCommandEnvVarKey),
		Validators: []validator.String{stringvalidator.LengthAtLeast(1)},
	}
	attrs[WranglerProfileSchemaKey] = schema.StringAttribute{
		Optional: true,
		MarkdownDescription: fmt.Sprintf("Wrangler auth profile (created with `wrangler auth create`) to take the OAuth token from, "+
			"passed to wrangler as `%s`. Requires wrangler >= %s. When unset, wrangler uses `%s` from the environment, "+
			"then the profile bound to the working directory with `wrangler auth activate`, then the default login.",
			ProfileEnvVarKey, minProfileVersion, ProfileEnvVarKey),
		Validators: []validator.String{stringvalidator.LengthAtLeast(1)},
	}
}

// exclusiveCredentialsValidator rejects use_wrangler_auth = true next to
// another credential attribute, at validate time. Configure checks again, for
// the case where wrangler mode is enabled from the environment.
type exclusiveCredentialsValidator struct{}

func (exclusiveCredentialsValidator) Description(context.Context) string {
	return "use_wrangler_auth cannot be combined with api_token, api_key, email or api_user_service_key"
}

func (v exclusiveCredentialsValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (exclusiveCredentialsValidator) ValidateBool(ctx context.Context, req validator.BoolRequest, resp *validator.BoolResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() || !req.ConfigValue.ValueBool() {
		return
	}
	var set []string
	for _, name := range conflictingAttributes {
		var value types.String
		if diags := req.Config.GetAttribute(ctx, path.Root(name), &value); diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
		if !value.IsNull() && !value.IsUnknown() {
			set = append(set, name)
		}
	}
	if len(set) > 0 {
		resp.Diagnostics.AddAttributeError(req.Path, "Conflicting Cloudflare credentials", conflictMessage(set))
	}
}

func conflictMessage(set []string) string {
	return fmt.Sprintf("%s cannot be combined with %s. Remove %s from the provider configuration, or disable %s.",
		UseWranglerAuthSchemaKey, strings.Join(set, ", "), strings.Join(set, ", "), UseWranglerAuthSchemaKey)
}

// Configure turns wrangler mode on when use_wrangler_auth (or its environment
// variable) is true. It returns the client options to append, or nil when the
// mode is off. On failure it adds error diagnostics and returns nil; the
// caller must stop when diags has errors.
//
// It fails fast: the first token is fetched here, so a missing wrangler, a
// missing login or a wrong token type is reported before any API call.
func Configure(ctx context.Context, m ProviderModel, creds Credentials, diags *diag.Diagnostics) []option.RequestOption {
	enabled, ok := boolSetting(m.UseWranglerAuth, UseWranglerAuthEnvVarKey, diags)
	if !ok || !enabled {
		return nil
	}

	values := map[string]types.String{
		consts.APITokenSchemaKey:          creds.APIToken,
		consts.APIKeySchemaKey:            creds.APIKey,
		consts.EmailSchemaKey:             creds.Email,
		consts.APIUserServiceKeySchemaKey: creds.APIUserServiceKey,
	}
	var set []string
	for _, name := range conflictingAttributes {
		if v := values[name]; !v.IsNull() && !v.IsUnknown() {
			set = append(set, name)
		}
	}
	if len(set) > 0 {
		diags.AddAttributeError(path.Root(UseWranglerAuthSchemaKey), "Conflicting Cloudflare credentials", conflictMessage(set))
		return nil
	}

	var ignored []string
	for _, name := range ignoredEnvVars {
		if _, ok := os.LookupEnv(name); ok {
			ignored = append(ignored, name)
		}
	}
	if len(ignored) > 0 {
		diags.AddWarning("Cloudflare credential environment variables ignored",
			fmt.Sprintf("%s is enabled, so the provider ignores %s and does not pass them to wrangler. Unset them to remove this warning.",
				UseWranglerAuthSchemaKey, strings.Join(ignored, ", ")))
	}

	commandLine := DefaultCommand
	if !m.WranglerCommand.IsNull() && !m.WranglerCommand.IsUnknown() {
		commandLine = m.WranglerCommand.ValueString()
	} else if v, ok := os.LookupEnv(WranglerCommandEnvVarKey); ok && v != "" {
		commandLine = v
	}
	command, err := SplitCommand(commandLine)
	if err != nil {
		diags.AddAttributeError(path.Root(WranglerCommandSchemaKey), "Invalid wrangler command", err.Error())
		return nil
	}

	cfg := Config{Command: command}
	if !m.WranglerProfile.IsNull() && !m.WranglerProfile.IsUnknown() {
		cfg.Profile = m.WranglerProfile.ValueString()
	}
	if cfg.Timeout, ok = durationSetting(WranglerTimeoutEnvVarKey, DefaultTimeout, diags); !ok {
		return nil
	}
	if cfg.TTL, ok = durationSetting(WranglerTokenTTLEnvVarKey, DefaultTTL, diags); !ok {
		return nil
	}

	source, err := NewTokenSource(cfg)
	if err != nil {
		diags.AddError("Unable to configure wrangler authentication", err.Error())
		return nil
	}
	if _, err := source.Token(ctx); err != nil {
		diags.AddAttributeError(path.Root(UseWranglerAuthSchemaKey), "Unable to get an OAuth token from wrangler", err.Error())
		return nil
	}
	tflog.Info(ctx, "wranglerauth: authenticating with the wrangler OAuth session", map[string]any{
		"command": strings.Join(command, " "),
		"profile": cfg.Profile,
	})
	return []option.RequestOption{option.WithMiddleware(source.Middleware())}
}

// boolSetting reads a bool from HCL, then from the environment. ok is false
// when the environment value is invalid.
func boolSetting(v types.Bool, envVar string, diags *diag.Diagnostics) (value, ok bool) {
	if !v.IsNull() && !v.IsUnknown() {
		return v.ValueBool(), true
	}
	s, set := os.LookupEnv(envVar)
	if !set || s == "" {
		return false, true
	}
	b, err := strconv.ParseBool(s)
	if err != nil {
		diags.AddError("Invalid "+envVar, fmt.Sprintf("%s must be true or false, got %q.", envVar, s))
		return false, false
	}
	return b, true
}

// durationSetting reads a positive Go duration (e.g. "90s", "5m") from the
// environment.
func durationSetting(envVar string, def time.Duration, diags *diag.Diagnostics) (time.Duration, bool) {
	s, set := os.LookupEnv(envVar)
	if !set || s == "" {
		return def, true
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		diags.AddError("Invalid "+envVar, fmt.Sprintf("%s must be a positive duration such as \"90s\" or \"5m\", got %q.", envVar, s))
		return 0, false
	}
	return d, true
}
