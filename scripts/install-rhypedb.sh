#!/usr/bin/env bash
# Install the rhypedb-server that integration tests run against, at exactly
# the commit Cargo.toml pins for rhypedb-client (one source of truth).
#
#   scripts/install-rhypedb.sh            # installs, prints the binary path
#   export RHYPEDB_SERVER_BIN=$(scripts/install-rhypedb.sh)
#   scripts/install-rhypedb.sh --print-rev   # just the pinned commit
#
# Installs into ${RHYPEDB_ROOT:-$HOME/.local/rhypedb-<rev>}; reuses an
# existing install. Under GitHub Actions it also exports RHYPEDB_SERVER_BIN.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rev="$(sed -n 's/^rhypedb-client = {.*rev = "\([0-9a-f]\{40\}\)".*/\1/p' "$repo_root/Cargo.toml")"
if [[ -z "$rev" ]]; then
  echo "could not find the rhypedb-client rev in Cargo.toml" >&2
  exit 1
fi
if [[ "${1:-}" == "--print-rev" ]]; then
  echo "$rev"
  exit 0
fi
root="${RHYPEDB_ROOT:-$HOME/.local/rhypedb-${rev:0:7}}"
bin="$root/bin/rhypedb-server"

if [[ ! -x "$bin" ]]; then
  echo "installing rhypedb-server @ $rev into $root" >&2
  cargo install --locked \
    --git https://github.com/joeleaver/rhypedb --rev "$rev" \
    --no-default-features --root "$root" rhypedb-server >&2
fi

if [[ -n "${GITHUB_ENV:-}" ]]; then
  echo "RHYPEDB_SERVER_BIN=$bin" >> "$GITHUB_ENV"
fi
echo "$bin"
