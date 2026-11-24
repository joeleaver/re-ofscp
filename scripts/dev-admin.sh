#!/usr/bin/env bash
# Run the admin console locally against a real provider and database.
#
#   scripts/dev-admin.sh          # rhypedb-server + re-ofscp + trunk serve
#   scripts/dev-admin.sh setup    # (in another shell) create the first owner
#
# Values come from scripts/dev-admin.env. The console is served at
# http://localhost:$DEV_UI_PORT/admin/ by `trunk serve`, which proxies
# /api/ to the provider, so the browser sees one origin. The provider runs
# with ADMIN_LOOPBACK_HTTP=true, which it accepts only for a localhost
# DOMAIN (docs/decisions/0005). Data lives in target/dev-admin and is
# kept between runs; delete that directory to start over.
#
# Needs rhypedb-server (RHYPEDB_SERVER_BIN, or scripts/install-rhypedb.sh)
# and trunk.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
set -a
# shellcheck source=dev-admin.env
source "$repo_root/scripts/dev-admin.env"
set +a

if [[ "${1:-}" == "setup" ]]; then
  body=$(printf '{"setupToken":"%s","username":"%s","password":"%s"}' \
    "$ADMIN_SETUP_TOKEN" "$DEV_ADMIN_USERNAME" "$DEV_ADMIN_PASSWORD")
  curl --fail-with-body -sS -X POST \
    -H 'content-type: application/json' \
    -H "origin: http://$DOMAIN" \
    --data "$body" \
    "http://127.0.0.1:$DEV_SERVER_PORT/api/admin/setup"
  echo
  exit 0
fi

rhypedb_bin="${RHYPEDB_SERVER_BIN:-$("$repo_root/scripts/install-rhypedb.sh")}"
data="$repo_root/target/dev-admin"
mkdir -p "$data"

pids=()
cleanup() {
  for pid in "${pids[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

"$rhypedb_bin" \
  --schema "$repo_root/schema.rhype" \
  --data-dir "$data/rhypedb" \
  --listen "127.0.0.1:$DEV_RHYPEDB_HTTP_PORT" \
  --tcp-listen "127.0.0.1:$DEV_RHYPEDB_TCP_PORT" \
  >"$data/rhypedb.log" 2>&1 &
pids+=($!)

cargo build --manifest-path "$repo_root/Cargo.toml" --bin re-ofscp
BIND="127.0.0.1:$DEV_SERVER_PORT" \
  RHYPEDB_ADDR="127.0.0.1:$DEV_RHYPEDB_TCP_PORT" \
  "$repo_root/target/debug/re-ofscp" >"$data/server.log" 2>&1 &
pids+=($!)

cd "$repo_root/admin-web"
trunk serve \
  --port "$DEV_UI_PORT" \
  --proxy-backend "http://127.0.0.1:$DEV_SERVER_PORT/api/"
