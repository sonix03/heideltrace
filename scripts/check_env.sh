#!/usr/bin/env bash
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# Memeriksa apakah mesin siap menjalankan heideltrace.
# Skrip ini hanya membaca informasi sistem dan tidak mengubah apa pun.
#
#   ./scripts/check_env.sh [PID]
#
set -u

ok()   { printf '  [OK]    %s\n' "$*"; }
warn() { printf '  [AWAS]  %s\n' "$*"; }
bad()  { printf '  [GAGAL] %s\n' "$*"; FAIL=1; }
FAIL=0

kconfig() {
	local key=$1
	if [ -r /proc/config.gz ]; then
		zcat /proc/config.gz | grep -E "^${key}=" | cut -d= -f2
	elif [ -r "/boot/config-$(uname -r)" ]; then
		grep -E "^${key}=" "/boot/config-$(uname -r)" | cut -d= -f2
	fi
}

echo "Kernel"
KREL=$(uname -r)
KVER=$(echo "$KREL" | cut -d. -f1-2)
if [ "$(printf '%s\n5.15\n' "$KVER" | sort -V | head -1)" = "5.15" ]; then
	ok "versi $KREL (minimal 5.15 untuk BPF cookie pada uprobe)"
else
	bad "versi $KREL, dibutuhkan minimal 5.15"
fi
[ "$(uname -m)" = "x86_64" ] && ok "arsitektur x86_64" || warn "arsitektur $(uname -m) belum diuji"

if [ -r /sys/kernel/btf/vmlinux ]; then
	ok "BTF kernel tersedia (/sys/kernel/btf/vmlinux)"
else
	bad "BTF kernel tidak ada, CO-RE tidak dapat digunakan"
fi

for key in CONFIG_BPF_SYSCALL CONFIG_DEBUG_INFO_BTF CONFIG_UPROBE_EVENTS CONFIG_BPF_EVENTS CONFIG_FTRACE_SYSCALLS; do
	val=$(kconfig "$key")
	if [ -z "$val" ] && [ ! -r /proc/config.gz ] && [ ! -r "/boot/config-$KREL" ]; then
		warn "$key tidak dapat diperiksa (konfigurasi kernel tidak ditemukan)"
	elif [ "$val" = "y" ]; then
		ok "$key=y"
	else
		bad "$key tidak aktif"
	fi
done

echo
echo "Hak akses"
if [ "$(id -u)" -eq 0 ]; then
	ok "berjalan sebagai root"
else
	warn "bukan root; heideltrace perlu dijalankan dengan sudo"
fi
if [ -r /proc/sys/kernel/unprivileged_bpf_disabled ]; then
	ok "kernel.unprivileged_bpf_disabled=$(cat /proc/sys/kernel/unprivileged_bpf_disabled) (tidak berpengaruh untuk root)"
fi
if grep -q lockdown /sys/kernel/security/lsm 2>/dev/null; then
	mode=$(sed -n 's/.*\[\(.*\)\].*/\1/p' /sys/kernel/security/lockdown 2>/dev/null)
	[ "$mode" = "none" ] || [ -z "$mode" ] && ok "kernel lockdown tidak aktif" \
		|| bad "kernel lockdown '$mode' dapat menolak program eBPF tracing"
fi

echo
echo "GPU dan CUDA"
if command -v nvidia-smi >/dev/null 2>&1; then
	ok "$(nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader | head -1)"
else
	warn "nvidia-smi tidak ditemukan"
fi
LIBS=$(ldconfig -p 2>/dev/null | grep -E 'libcuda\.so(\.1)? ' | awk '{print $NF}' | sort -u)
[ -n "$LIBS" ] && ok "libcuda.so: $(echo $LIBS)" || warn "libcuda.so tidak ada di cache ldconfig"

if [ $# -ge 1 ]; then
	PID=$1
	echo
	echo "Proses sasaran $PID"
	if [ ! -d "/proc/$PID" ]; then
		bad "PID $PID tidak ditemukan"
	else
		ok "$(tr '\0' ' ' < /proc/$PID/cmdline | cut -c1-100)"
		LIB=$(grep -m1 -oE '/[^ ]*libcuda\.so[^ ]*' "/proc/$PID/maps" 2>/dev/null)
		[ -n "$LIB" ] && ok "libcuda dimuat: $LIB" \
			|| warn "libcuda belum dimuat oleh PID ini (mungkin dipakai proses anaknya)"
		for c in /proc/$PID/task/*/children; do cat "$c"; done 2>/dev/null | tr ' ' '\n' | grep -v '^$' |
			while read -r child; do
				ok "proses anak $child: $(cat /proc/$child/comm 2>/dev/null)"
			done
	fi
fi

echo
echo "Alat build"
for t in clang make cc pkg-config; do
	command -v "$t" >/dev/null 2>&1 && ok "$t: $(command -v $t)" || bad "$t tidak ditemukan"
done
for h in gelf.h zlib.h openssl/opensslv.h; do
	echo "#include <$h>" | cc -E - >/dev/null 2>&1 && ok "header $h" || bad "header $h tidak ada (libelf-dev / zlib1g-dev / libssl-dev)"
done
command -v bpftrace >/dev/null 2>&1 && ok "bpftrace (untuk scripts/count_cuda_calls.sh)" \
	|| warn "bpftrace tidak ada (hanya dibutuhkan untuk scripts/count_cuda_calls.sh)"

echo
[ $FAIL -eq 0 ] && echo "Semua syarat utama terpenuhi." || echo "Ada syarat yang belum terpenuhi."
exit $FAIL
