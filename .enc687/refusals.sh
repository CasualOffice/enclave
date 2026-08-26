#!/bin/sh
# The three no-key outcomes, driven against the real binary.
set -u
export DATABASE_URL='postgres://enclave:enclave@127.0.0.1:55432/enclave'
export DATABASE_PLATFORM_URL="$DATABASE_URL"
export RUST_LOG=error

BIN=../target/debug/enclave-api

run_in() {
  cfg="$1"
  cp "refuse/$cfg" enclave.yaml
  $BIN 2>&1 | grep -v '^{' | head -6
  echo "  (exit $?)"
  cp base.yaml enclave.yaml
}

cd "$(dirname "$0")" || exit 1
cp base.yaml enclave.yaml

echo "=== profile: production, no auth.signing_keys.key_ref ==="
run_in prod.yaml

echo
echo "=== profile: community, bind 0.0.0.0, no key_ref ==="
run_in exposed.yaml

echo
echo "=== profile: community, loopback, key_ref set to a bad value ==="
ENC687_BAD_KEY="this-is-not-a-key" run_in badkey.yaml
