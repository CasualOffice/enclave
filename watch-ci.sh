#!/bin/bash
# Emit one line per check as it settles; stop when none are pending.
prev=""
for i in $(seq 1 40); do
  s=$(gh pr checks 82 --json name,bucket 2>/dev/null)
  if [ -z "$s" ]; then s='[]'; fi
  cur=$(printf '%s' "$s" | jq -r '.[] | select(.bucket!="pending") | "\(.name): \(.bucket)"' | sort)
  printf '%s\n' "$cur" | grep -vxF -f <(printf '%s\n' "$prev") || true
  prev="$cur"
  n=$(printf '%s' "$s" | jq -r 'length')
  if [ "$n" != "0" ] && printf '%s' "$s" | jq -e 'all(.bucket!="pending")' >/dev/null 2>&1; then
    echo "ALL CHECKS COMPLETE"
    exit 0
  fi
  sleep 30
done
echo "WATCH TIMED OUT"
