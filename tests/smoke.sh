#!/usr/bin/env bash
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# Smoke test without a GPU: attaches heideltrace to a fake application that
# uses a fake libcuda.so, then checks the events it produced.
#
#   make && sudo ./tests/smoke.sh
#
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo." >&2; exit 1; }
[ -x "$ROOT/build/heideltrace" ] || { echo "Run make first." >&2; exit 1; }

gcc -O1 -shared -fPIC -o "$TMP/libcuda.so.1" "$ROOT/tests/fake_libcuda.c"
ln -s libcuda.so.1 "$TMP/libcuda.so"
gcc -O1 -o "$TMP/fake_app" "$ROOT/tests/fake_app.c" -L"$TMP" -lcuda -Wl,-rpath,"$TMP"

"$TMP/fake_app" &
APP=$!
"$ROOT/build/heideltrace" -p "$APP" -o "$TMP/out.jsonl" -d 8 --disable P1 --enable P7
wait "$APP"

OUT="$TMP/out.jsonl"
count() { grep -c "$1" "$OUT" || true; }

FAIL=0
expect() {
	local name=$1 got=$2 want=$3
	if [ "$got" -eq "$want" ]; then
		echo "  [OK]    $name: $got"
	else
		echo "  [FAIL]  $name: $got (expected $want)"
		FAIL=1
	fi
}

echo "Smoke test results:"
# 13 steps (10 parent + 3 child), each with 2 boundaries: sync and blocking DtoH
expect "step events"                "$(count '"type":"step"')" 26
expect "steps with 20 launches"     "$(count '"launches":20,"graphs":1')" 13
expect "memcpy events"              "$(count '"type":"memcpy"')" 26
expect "alloc/free events"          "$(count '"type":"alloc"')" 4
expect "child process seen (P6)"    "$(count '"type":"proc_start"')" 1
expect "processes exited (P6)"      "$(count '"type":"proc_exit"')" 2

echo
echo "Sample step event:"
grep -m1 '"launches":20' "$OUT"
exit $FAIL
