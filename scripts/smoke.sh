#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Container smoke test for the Vocdoni OAuth image (CI, promote, `make smoke`):
#   scripts/smoke.sh <image> [config.yaml]
#
# With a config argument the file is mounted over /etc/dex/config.yaml (used
# to test a config produced by `make add-client`); otherwise the baked one.
# Every run sets DEX_CONFIG_DISALLOW_UNKNOWN_FIELDS=true (Dex v2.46.0
# feature flag, pkg/featureflags/set.go), dummy Google credentials and a
# dummy secret for every `secretEnv: CLIENT_*_SECRET` in the config.
#
# A. Railway mode: root (--user 0, as RAILWAY_RUN_UID=0) with a root-owned
#    volume at /data: discovery issuer, grant_types_supported ==
#    ["authorization_code"], response_types_supported == ["code"],
#    code_challenge_methods_supported == ["S256"], /keys has a key, /healthz
#    OK, logo served, PKCE enforced (no code_challenge -> invalid_request),
#    Google redirect carries hd=vocdoni.org and <ISSUER>/callback, SQLite
#    file created, logs are JSON.
# B. A missing CLIENT_*_SECRET stops the container (gomplate presence check).
# C. A misspelt key stops the container (unknown fields disallowed).
# D. Default user (uid 1001) with a fresh named volume starts (local docker).
#
# Needs docker, curl and jq, and outbound HTTPS (the Google connector fetches
# Google's discovery document at start). Temporary files go under $SMOKE_TMP
# (default $RUNNER_TEMP, else ~/.cache/folio/tmp), never /tmp.
set -euo pipefail

image=${1:?usage: scripts/smoke.sh <image> [config.yaml]}
src_config=${2:-}
tmp_root=${SMOKE_TMP:-${RUNNER_TEMP:-$HOME/.cache/folio/tmp}}
mkdir -p "$tmp_root"
work=$(mktemp -d "$tmp_root/oauth-smoke.XXXXXX")
run_id=oauth-smoke-$$
issuer=http://127.0.0.1:5556
containers=()
volumes=()

cleanup() {
  for c in "${containers[@]}"; do docker rm -f "$c" >/dev/null 2>&1 || true; done
  for v in "${volumes[@]}"; do docker volume rm -f "$v" >/dev/null 2>&1 || true; done
  rm -rf "$work"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}
pass() { echo "ok: $*"; }

# The config under test: the baked file (extracted) or the argument.
config=$work/config.yaml
if [ -n "$src_config" ]; then
  cp "$src_config" "$config"
else
  docker run --rm --entrypoint cat "$image" /etc/dex/config.yaml >"$config"
fi
chmod 0644 "$config"

envs=("ISSUER=$issuer" PORT=5556 DEX_CONFIG_DISALLOW_UNKNOWN_FIELDS=true
  GOOGLE_CLIENT_ID=smoke.apps.googleusercontent.com GOOGLE_CLIENT_SECRET=smoke-google-secret)
secrets=$(grep -oE 'secretEnv: *CLIENT_[A-Z0-9_]+_SECRET' "$config" | awk '{print $2}' | sort -u)
[ -n "$secrets" ] || fail "no staticClients secretEnv found in the config"
for s in $secrets; do envs+=("$s=smoke-$s"); done
first_secret=$(echo "$secrets" | head -1)
env_args=()
for e in "${envs[@]}"; do env_args+=(-e "$e"); done

# new_volume <suffix>: creates a named volume, sets $vol.
new_volume() {
  vol="$run_id-$1"
  docker volume create "$vol" >/dev/null
  volumes+=("$vol")
}

# start <name> <docker args...>: runs the image detached, sets $started.
start() {
  started="$run_id-$1"
  shift
  docker run -d --name "$started" -p 127.0.0.1::5556 "$@" "$image" >/dev/null
  containers+=("$started")
}

# wait_healthy <container>: prints the base URL once /healthz answers.
wait_healthy() {
  local c=$1 base
  for _ in $(seq 1 60); do
    if [ "$(docker inspect -f '{{.State.Running}}' "$c")" != true ]; then
      docker logs "$c" >&2 || true
      fail "$c exited during start"
    fi
    base="http://$(docker port "$c" 5556/tcp | head -1)"
    if curl -fsS -o /dev/null "$base/healthz" 2>/dev/null; then
      echo "$base"
      return
    fi
    sleep 0.5
  done
  docker logs "$c" >&2 || true
  fail "$c: /healthz never answered"
}

# expect_exit <container> <log pattern>: the container must stop non-zero.
expect_exit() {
  local c=$1 pattern=$2
  for _ in $(seq 1 40); do
    [ "$(docker inspect -f '{{.State.Running}}' "$c")" = true ] || break
    sleep 0.5
  done
  [ "$(docker inspect -f '{{.State.Running}}' "$c")" != true ] || fail "$c still running"
  [ "$(docker inspect -f '{{.State.ExitCode}}' "$c")" != 0 ] || fail "$c exited 0"
  docker logs "$c" 2>&1 | grep -q -- "$pattern" || { docker logs "$c" >&2; fail "$c: log lacks '$pattern'"; }
}

# ---- A. Railway mode ---------------------------------------------------------
new_volume railway
docker run --rm --user 0 -v "$vol:/data" --entrypoint /bin/sh "$image" -c 'chown 0:0 /data && chmod 0755 /data'
start railway --user 0 -v "$vol:/data" -v "$config:/etc/dex/config.yaml:ro" "${env_args[@]}"
a=$started
base=$(wait_healthy "$a")

disc=$(curl -fsS "$base/.well-known/openid-configuration")
jq -e --arg iss "$issuer" '.issuer == $iss' <<<"$disc" >/dev/null || fail "issuer: $(jq -c .issuer <<<"$disc")"
jq -e '.grant_types_supported == ["authorization_code"]' <<<"$disc" >/dev/null || fail "grant_types_supported: $(jq -c .grant_types_supported <<<"$disc")"
jq -e '.response_types_supported == ["code"]' <<<"$disc" >/dev/null || fail "response_types_supported: $(jq -c .response_types_supported <<<"$disc")"
jq -e '.code_challenge_methods_supported == ["S256"]' <<<"$disc" >/dev/null || fail "code_challenge_methods_supported: $(jq -c .code_challenge_methods_supported <<<"$disc")"
pass "discovery document"

curl -fsS "$base/keys" | jq -e '.keys | length >= 1' >/dev/null || fail "/keys has no key"
pass "/keys has a key"
[ "$(curl -fsS "$base/healthz")" != "" ] || fail "/healthz empty"
pass "/healthz"
[ "$(curl -fsS -o /dev/null -w '%{content_type}' "$base/theme/vocdoni-logo.png")" = image/png ] || fail "logo not served"
pass "logo served from /theme"

client_id=$(awk '/^  - id: /{gsub(/"/, "", $3); print $3; exit}' "$config")
redirect=$(awk '/redirectURIs:/{getline; sub(/^ *- */, ""); print; exit}' "$config")
q="client_id=$client_id&redirect_uri=$(jq -rn --arg u "$redirect" '$u|@uri')&response_type=code&scope=openid+email+profile&state=smoke"
loc=$(curl -sS -o /dev/null -w '%{redirect_url}' "$base/auth/google?$q")
[[ "$loc" == "$redirect"*"error=invalid_request"* ]] || fail "PKCE not enforced: $loc"
pass "PKCE required"
challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
loc=$(curl -sS -o /dev/null -w '%{redirect_url}' "$base/auth/google?$q&code_challenge=$challenge&code_challenge_method=S256")
[[ "$loc" == https://accounts.google.com/* ]] || fail "no Google redirect: $loc"
[[ "$loc" == *"hd=vocdoni.org"* ]] || fail "Google redirect lacks hd=vocdoni.org: $loc"
[[ "$loc" == *"redirect_uri=$(jq -rn --arg u "$issuer/callback" '$u|@uri')"* ]] || fail "Google redirect_uri: $loc"
[[ "$loc" != *"prompt="* ]] || fail "Google redirect sends a prompt parameter: $loc"
pass "Google redirect (hd=vocdoni.org, <ISSUER>/callback, no prompt)"

docker exec "$a" test -s /data/dex.db || fail "/data/dex.db not created"
pass "SQLite database on the root-owned volume"
docker logs "$a" 2>&1 | head -5 | jq -e . >/dev/null || fail "logs are not JSON"
pass "JSON logs"

# ---- B. missing client secret ---------------------------------------------------
b_env=()
for e in "${envs[@]}"; do [[ "$e" == "$first_secret="* ]] || b_env+=(-e "$e"); done
start nosecret -v "$config:/etc/dex/config.yaml:ro" "${b_env[@]}"
expect_exit "$started" "$first_secret is not set"
pass "missing $first_secret stops the container"

# ---- C. unknown field -------------------------------------------------------------
sed 's/skipApprovalScreen:/skipAprovalScreen:/' "$config" >"$work/typo.yaml"
chmod 0644 "$work/typo.yaml"
start typo -v "$work/typo.yaml:/etc/dex/config.yaml:ro" "${env_args[@]}"
expect_exit "$started" 'unknown field "skipAprovalScreen"'
pass "unknown fields are rejected"

# ---- D. default user, named volume ------------------------------------------------
new_volume default
start default -v "$vol:/data" -v "$config:/etc/dex/config.yaml:ro" "${env_args[@]}"
wait_healthy "$started" >/dev/null
pass "default user with a named volume"

echo "smoke test passed: $image"
