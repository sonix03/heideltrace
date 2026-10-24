#!/usr/bin/env bash
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# Uji asap tanpa GPU: memasang heideltrace pada aplikasi tiruan yang memakai
# libcuda.so tiruan, lalu memeriksa kejadian yang dihasilkan.
#
#   make && sudo ./tests/smoke.sh
#
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

[ "$(id -u)" -eq 0 ] || { echo "Jalankan dengan sudo." >&2; exit 1; }
[ -x "$ROOT/build/heideltrace" ] || { echo "Jalankan make terlebih dahulu." >&2; exit 1; }

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
		echo "  [GAGAL] $name: $got (diharapkan $want)"
		FAIL=1
	fi
}

echo "Hasil uji asap:"
# 13 langkah (10 induk + 3 anak), masing-masing 2 batas: sync dan DtoH sinkron
expect "kejadian step"                  "$(count '"type":"step"')" 26
expect "step dengan 20 peluncuran"      "$(count '"launches":20,"graphs":1')" 13
expect "kejadian memcpy"                "$(count '"type":"memcpy"')" 26
expect "kejadian alloc/free"            "$(count '"type":"alloc"')" 4
expect "proses anak terdeteksi (P6)"    "$(count '"type":"proc_start"')" 1
expect "proses berhenti (P6)"           "$(count '"type":"proc_exit"')" 2

echo
echo "Contoh kejadian step:"
grep -m1 '"launches":20' "$OUT"
exit $FAIL
