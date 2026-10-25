#!/usr/bin/env bash
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# P1 smoke test without a GPU: observes a local Python HTTP server that
# receives three curl requests, then checks the net events it produced.
#
#   make && sudo ./tests/net_smoke.sh
#
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
PORT=18000

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo." >&2; exit 1; }
command -v python3 >/dev/null && command -v curl >/dev/null ||
	{ echo "Needs python3 and curl." >&2; exit 1; }

python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$TMP" >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true; rm -rf "$TMP"' EXIT
sleep 1

"$ROOT/build/heideltrace" -p "$SRV" --port "$PORT" -o "$TMP/out.jsonl" -d 4 &
AGENT=$!
sleep 1.5
for _ in 1 2 3; do
	curl -s -o /dev/null "http://127.0.0.1:$PORT/"
done
wait "$AGENT"

OUT="$TMP/out.jsonl"
count() { grep -c "$1" "$OUT" || true; }
RECV=$(count '"dir":"recv"')
SEND=$(count '"dir":"send"')
CONNS=$(grep -o '"sock":"0x[0-9a-f]*"' "$OUT" | sort -u | wc -l)

FAIL=0
check() {
	if [ "$2" -ge "$3" ]; then
		echo "  [OK]    $1: $2"
	else
		echo "  [FAIL]  $1: $2 (expected at least $3)"
		FAIL=1
	fi
}
echo "P1 smoke test results:"
check "recv events" "$RECV" 3
check "send events" "$SEND" 3
check "distinct connections" "$CONNS" 3

echo
echo "Sample net events:"
grep -m2 '"type":"net"' "$OUT"
exit $FAIL
