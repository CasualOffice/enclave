#!/bin/sh
# The positive control for the refusals: a key supplied by reference actually signs.
set -u
cd "$(dirname "$0")" || exit 1

export DATABASE_URL='postgres://enclave:enclave@127.0.0.1:55432/enclave'
export DATABASE_PLATFORM_URL="$DATABASE_URL"
export RUST_LOG=info

# Generated here, in the shell, and exported. It is never written to a file in the repository and
# never appears in a configuration document — the document holds `env://ENC687_SIGNING_KEY`.
ENC687_SIGNING_KEY=$(openssl genpkey -algorithm ed25519 -outform DER 2>/dev/null | base64 | tr -d '\n')
export ENC687_SIGNING_KEY
echo "generated ${#ENC687_SIGNING_KEY} chars of base64 PKCS#8 into the environment"

cp refuse/configured.yaml enclave.yaml
../target/debug/enclave-api > configured.log 2>&1 &
PID=$!
sleep 4

echo
echo "=== what the binary said about its key ==="
grep -o '"message":"signing with the configured key[^"]*"' configured.log
grep -o '"kid":"[^"]*"' configured.log | head -1

echo
echo "=== login against the configured-key deployment ==="
curl -sS -o /dev/null -w 'status %{http_code}\n' -X POST http://127.0.0.1:8095/api/v1/auth/login \
  -H 'Host: tenant-alpha.enclave.test' -H 'Content-Type: application/json' \
  -d '{"email":"owner@tenant-alpha.example","password":"correct-horse-battery-staple"}'

TOKEN=$(curl -sS -X POST http://127.0.0.1:8095/api/v1/auth/login \
  -H 'Host: tenant-alpha.enclave.test' -H 'Content-Type: application/json' \
  -d '{"email":"owner@tenant-alpha.example","password":"correct-horse-battery-staple"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["accessToken"])')

echo "token kid header: $(printf '%s' "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null)"

echo
echo "=== GET /api/v1/me with a token signed by the configured key ==="
curl -sS -o /dev/null -w 'status %{http_code}\n' http://127.0.0.1:8095/api/v1/me \
  -H 'Host: tenant-alpha.enclave.test' -H "Authorization: Bearer $TOKEN"

echo
echo "=== the key material must not be in the log ==="
if grep -qF "$(printf '%s' "$ENC687_SIGNING_KEY" | cut -c1-24)" configured.log; then
  echo "LEAKED"
else
  echo "absent from the log (positive control: the log has $(wc -l < configured.log) lines)"
fi

kill $PID 2>/dev/null
cp base.yaml enclave.yaml
