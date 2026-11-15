# Local workstation only: reuse the OAuth session of `wrangler login`.
# In CI, use an API token instead.
provider "cloudflare" {
  use_wrangler_auth = true

  # Optional. Defaults to "wrangler"; any command that runs wrangler >= 4.57.0.
  wrangler_command = "npx wrangler"

  # Optional. A profile created with `wrangler auth create work`
  # (needs wrangler >= 4.159.0).
  wrangler_profile = "work"
}

# Resources outside wrangler's OAuth scopes (DNS records, zone settings,
# Zero Trust, ...) need an API token: give them a second provider alias.
provider "cloudflare" {
  alias     = "api_token"
  api_token = var.cloudflare_api_token
}
