#!/bin/sh
# The ENC-687 end-to-end transcript, against the running binary. Not committed.
set -u
BASE=http://127.0.0.1:8099
HOST_ALPHA=tenant-alpha.enclave.test
EMAIL=owner@tenant-alpha.example
PASS=correct-horse-battery-staple

HDRS=$(curl -sS -D - -o /dev/null -X POST "$BASE/api/v1/auth/login" \
  -H "Host: $HOST_ALPHA" -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}")

RT=$(printf '%s' "$HDRS" | grep -o 'enclave_rt=[^;]*' | head -1 | cut -d= -f2)
CSRF=$(printf '%s' "$HDRS" | grep -o 'enclave_csrf=[^;]*' | head -1 | cut -d= -f2)
COOKIE="enclave_rt=$RT; enclave_csrf=$CSRF"

echo "captured refresh cookie: ${#RT} chars   csrf: ${#CSRF} chars"

echo
echo "=== POST /api/v1/auth/refresh — rotation ==="
curl -sS -D - -o /dev/null -X POST "$BASE/api/v1/auth/refresh" \
  -H "Host: $HOST_ALPHA" -H "Cookie: $COOKIE" -H "x-csrf-token: $CSRF" | head -6

echo
echo "=== POST /api/v1/auth/refresh — replaying the consumed token (K4) ==="
curl -sS -w '\nstatus %{http_code}\n' -X POST "$BASE/api/v1/auth/refresh" \
  -H "Host: $HOST_ALPHA" -H "Cookie: $COOKIE" -H "x-csrf-token: $CSRF"

echo
echo "=== POST /api/v1/auth/logout — after the family was destroyed by the replay ==="
NEW=$(curl -sS -D - -o /dev/null -X POST "$BASE/api/v1/auth/login" \
  -H "Host: $HOST_ALPHA" -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}")
RT2=$(printf '%s' "$NEW" | grep -o 'enclave_rt=[^;]*' | head -1 | cut -d= -f2)
CSRF2=$(printf '%s' "$NEW" | grep -o 'enclave_csrf=[^;]*' | head -1 | cut -d= -f2)
curl -sS -D - -o /dev/null -X POST "$BASE/api/v1/auth/logout" \
  -H "Host: $HOST_ALPHA" -H "Cookie: enclave_rt=$RT2; enclave_csrf=$CSRF2" \
  -H "x-csrf-token: $CSRF2" | head -6

echo
echo "=== the same refresh token after logout ==="
curl -sS -w '\nstatus %{http_code}\n' -X POST "$BASE/api/v1/auth/refresh" \
  -H "Host: $HOST_ALPHA" -H "Cookie: enclave_rt=$RT2; enclave_csrf=$CSRF2" \
  -H "x-csrf-token: $CSRF2"
