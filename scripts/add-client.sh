#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Registers a tool as a static client (used by `make add-client`):
#   scripts/add-client.sh <id> <callback-url> [name] [config.yaml]
#
# Appends to staticClients (the last section of config.yaml) a client with
# secretEnv CLIENT_<ID>_SECRET (<ID> = id upper-cased, every character
# outside [A-Z0-9] replaced by "_"), preceded by the gomplate presence check
# that stops Dex when that variable is missing, then prints what to set on
# Railway and in the tool.
set -euo pipefail

id=${1:-}
url=${2:-}
name=${3:-$id}
config=${4:-config.yaml}

die() {
  echo "add-client: $*" >&2
  exit 1
}

[[ "$id" =~ ^[a-z0-9][a-z0-9-]{1,31}$ ]] || die "ID must match ^[a-z0-9][a-z0-9-]{1,31}\$ (got '$id')"
[[ "$url" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._~/%-]*$ ]] ||
  die "URL must be the exact https callback URL without query, e.g. https://tool.vocdoni.io/auth/callback (got '$url')"
[[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9\ ._-]{0,63}$ ]] || die "NAME may hold letters, digits, spaces, . _ - (got '$name')"
[ -f "$config" ] || die "$config not found"
[ "$(grep -E '^[A-Za-z]' "$config" | tail -1)" = "staticClients:" ] || die "staticClients must be the last section of $config"
grep -qE "^  - id: \"?$id\"?\$" "$config" && die "client '$id' already exists in $config"

env_name="CLIENT_$(printf '%s' "$id" | LC_ALL=C tr '[:lower:]' '[:upper:]' | tr -c 'A-Z0-9' '_')_SECRET"
grep -q "secretEnv: $env_name\$" "$config" && die "$env_name is already used in $config"

# Ensure the file ends with a newline before appending.
[ -z "$(tail -c1 "$config")" ] || echo >>"$config"
cat >>"$config" <<BLOCK
  # {{ if not (getenv "$env_name") }}{{ fail "$env_name is not set" }}{{ end }}
  - id: "$id"
    name: "$name"
    secretEnv: $env_name
    redirectURIs:
      - $url
BLOCK

cat <<MSG
Added client '$id' to $config.

1. Railway (project oauth, service oauth): set
     $env_name=<a new random secret, e.g. openssl rand -hex 32>
   then merge this change and redeploy the service (Railway → Deployments →
   Redeploy, or the configured image auto-update window) so Dex picks up the
   promoted image. Dex refuses to start while $env_name is unset.
2. The tool: OAUTH_ISSUER=https://oauth.vocdoni.org OAUTH_CLIENT_ID=$id
     OAUTH_CLIENT_SECRET=<the same secret> OAUTH_REDIRECT_URL=$url
MSG
