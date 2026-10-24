#!/usr/bin/env bash
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# Menghitung pemanggilan setiap fungsi cu* pada libcuda.so oleh satu proses.
# Hasilnya dipakai untuk memastikan fungsi mana yang benar-benar dipanggil
# (misalnya cuLaunchKernel atau cuLaunchKernel_ptsz) sebelum agen dipakai.
#
#   sudo ./scripts/count_cuda_calls.sh PID [DETIK]
#
# PID adalah proses yang memakai GPU, lihat:
#   nvidia-smi --query-compute-apps=pid,process_name --format=csv
#
# PERHATIAN: skrip ini memasang uprobe pada SEMUA fungsi cu* (ratusan) di
# proses tersebut sehingga proses akan melambat selama pengukuran. Jalankan
# hanya di server uji, saat tidak ada pengguna lain, sambil memberi beban.
#
set -euo pipefail

if [ $# -lt 1 ]; then
	sed -n '4,16p' "$0" | sed 's/^# \{0,1\}//'
	exit 1
fi
PID=$1
DUR=${2:-30}

[ "$(id -u)" -eq 0 ] || { echo "Jalankan dengan sudo." >&2; exit 1; }
command -v bpftrace >/dev/null || { echo "bpftrace tidak ditemukan." >&2; exit 1; }
[ -d "/proc/$PID" ] || { echo "PID $PID tidak ditemukan." >&2; exit 1; }

LIB=$(grep -m1 -oE '/[^ ]*libcuda\.so[^ ]*' "/proc/$PID/maps" || true)
if [ -z "$LIB" ]; then
	echo "PID $PID belum memuat libcuda.so. Pilih proses yang memakai GPU." >&2
	exit 1
fi
LIB="/proc/$PID/root$LIB"

echo "Menghitung pemanggilan cu* pada $LIB selama $DUR detik..." >&2
exec bpftrace -p "$PID" -e "
uprobe:$LIB:cu* { @calls[func] = count(); }
interval:s:$DUR { exit(); }
END {
	printf(\"\\nJumlah pemanggilan selama %d detik (terbanyak di bawah):\\n\", $DUR);
	print(@calls);
	clear(@calls);
}"
