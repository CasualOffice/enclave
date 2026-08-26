#!/bin/sh
set -u
BASE=http://127.0.0.1:8099
H=tenant-alpha.enclave.test
BODY='{"email":"owner@tenant-alpha.example","password":"correct-horse-battery-staple"}'

RESP=$(curl -sS -D /tmp/enc687.h -X POST "$BASE/api/v1/auth/login" -H "Host: $H" -H 'Content-Type: application/json' -d "$BODY")
AT=$(printf '%s' "$RESP" | python3 -c 'import sys,json;print(json.load(sys.stdin)["accessToken"])')
RT=$(grep -o 'enclave_rt=[^;]*' /tmp/enc687.h | head -1 | cut -d= -f2)
CSRF=$(grep -o 'enclave_csrf=[^;]*' /tmp/enc687.h | head -1 | cut -d= -f2)

echo "=== POST /api/v1/auth/logout (bearer + refresh cookie + csrf) ==="
curl -sS -D - -o /dev/null -X POST "$BASE/api/v1/auth/logout" \
  -H "Host: $H" -H "Authorization: Bearer $AT" \
  -H "Cookie: enclave_rt=$RT; enclave_csrf=$CSRF" -H "x-csrf-token: $CSRF" | head -6

echo
echo "=== the refresh token that logout revoked ==="
curl -sS -w '\nstatus %{http_code}\n' -X POST "$BASE/api/v1/auth/refresh" \
  -H "Host: $H" -H "Cookie: enclave_rt=$RT; enclave_csrf=$CSRF" -H "x-csrf-token: $CSRF"

echo
echo "=== token_revocations rows written by the family revocation ==="
