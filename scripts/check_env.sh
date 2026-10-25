#!/usr/bin/env bash
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# Checks whether a machine can run heideltrace.
# Read-only: it only inspects the system and changes nothing.
#
#   ./scripts/check_env.sh [PID]
#
set -u

ok()   { printf '  [OK]    %s\n' "$*"; }
warn() { printf '  [WARN]  %s\n' "$*"; }
bad()  { printf '  [FAIL]  %s\n' "$*"; FAIL=1; }
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
	ok "version $KREL (5.15 or newer is needed for BPF cookies on uprobes)"
else
	bad "version $KREL, 5.15 or newer is required"
fi
[ "$(uname -m)" = "x86_64" ] && ok "architecture x86_64" || bad "architecture $(uname -m) is not supported yet (build targets amd64)"

if [ -r /sys/kernel/btf/vmlinux ]; then
	ok "kernel BTF available (/sys/kernel/btf/vmlinux)"
else
	bad "no kernel BTF, CO-RE cannot work"
fi

# CONFIG_FTRACE_SYSCALLS is only needed for P8.
for key in CONFIG_BPF_SYSCALL CONFIG_DEBUG_INFO_BTF CONFIG_UPROBE_EVENTS CONFIG_BPF_EVENTS CONFIG_FTRACE_SYSCALLS; do
	val=$(kconfig "$key")
	if [ -z "$val" ] && [ ! -r /proc/config.gz ] && [ ! -r "/boot/config-$KREL" ]; then
		warn "$key cannot be checked (kernel config not found)"
	elif [ "$val" = "y" ]; then
		ok "$key=y"
	else
		bad "$key is not enabled"
	fi
done

echo
echo "Privileges"
if [ "$(id -u)" -eq 0 ]; then
	ok "running as root"
else
	warn "not root; heideltrace must be run with sudo"
fi
if grep -q lockdown /sys/kernel/security/lsm 2>/dev/null; then
	mode=$(sed -n 's/.*\[\(.*\)\].*/\1/p' /sys/kernel/security/lockdown 2>/dev/null)
	[ "$mode" = "none" ] || [ -z "$mode" ] && ok "kernel lockdown is off" \
		|| bad "kernel lockdown '$mode' may reject eBPF tracing programs"
fi

echo
echo "GPU and CUDA"
if command -v nvidia-smi >/dev/null 2>&1; then
	ok "$(nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader | head -1)"
else
	warn "nvidia-smi not found"
fi
LIBS=$(ldconfig -p 2>/dev/null | grep -E 'libcuda\.so(\.1)? ' | awk '{print $NF}' | sort -u)
[ -n "$LIBS" ] && ok "libcuda.so: $(echo $LIBS)" || warn "libcuda.so is not in the ldconfig cache"

if [ $# -ge 1 ]; then
	PID=$1
	echo
	echo "Target process $PID"
	if [ ! -d "/proc/$PID" ]; then
		bad "PID $PID not found"
	else
		ok "$(tr '\0' ' ' < /proc/$PID/cmdline | cut -c1-100)"
		LIB=$(grep -m1 -oE '/[^ ]*libcuda\.so[^ ]*' "/proc/$PID/maps" 2>/dev/null)
		[ -n "$LIB" ] && ok "libcuda loaded: $LIB" \
			|| warn "this PID has not loaded libcuda (a child process may use it)"
		for c in /proc/$PID/task/*/children; do cat "$c"; done 2>/dev/null | tr ' ' '\n' | grep -v '^$' |
			while read -r child; do
				ok "child process $child: $(cat /proc/$child/comm 2>/dev/null)"
			done
	fi
fi

echo
echo "Optional tools"
# The agent is a static binary; Go and clang are only needed to rebuild it.
command -v go >/dev/null 2>&1 && ok "go: $(go version | cut -d' ' -f3)" \
	|| warn "go not found (only needed to build; a prebuilt build/heideltrace works without it)"
command -v clang >/dev/null 2>&1 && ok "clang: $(command -v clang)" \
	|| warn "clang not found (only needed for 'make generate' after changing bpf/)"
command -v bpftrace >/dev/null 2>&1 && ok "bpftrace (for scripts/count_cuda_calls.sh)" \
	|| warn "bpftrace not found (only needed for scripts/count_cuda_calls.sh)"

echo
[ $FAIL -eq 0 ] && echo "All required checks passed." || echo "Some required checks failed."
exit $FAIL
