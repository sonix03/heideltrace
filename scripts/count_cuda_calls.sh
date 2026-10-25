#!/usr/bin/env bash
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# Counts the calls of every cu* function in libcuda.so made by one process.
# Use it to confirm which functions are really called (for example
# cuLaunchKernel or cuLaunchKernel_ptsz) before relying on the agent.
#
#   sudo ./scripts/count_cuda_calls.sh PID [SECONDS]
#
# PID is the process that uses the GPU, see:
#   nvidia-smi --query-compute-apps=pid,process_name --format=csv
#
# WARNING: this attaches a uprobe to EVERY cu* function (hundreds) of the
# process, so it slows down while counting. Only run it on a test server
# that nobody else is using, while sending load.
#
set -euo pipefail

if [ $# -lt 1 ]; then
	sed -n '4,16p' "$0" | sed 's/^# \{0,1\}//'
	exit 1
fi
PID=$1
DUR=${2:-30}

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo." >&2; exit 1; }
command -v bpftrace >/dev/null || { echo "bpftrace not found." >&2; exit 1; }
[ -d "/proc/$PID" ] || { echo "PID $PID not found." >&2; exit 1; }

LIB=$(grep -m1 -oE '/[^ ]*libcuda\.so[^ ]*' "/proc/$PID/maps" || true)
if [ -z "$LIB" ]; then
	echo "PID $PID has not loaded libcuda.so. Pick the process that uses the GPU." >&2
	exit 1
fi
LIB="/proc/$PID/root$LIB"

echo "Counting cu* calls in $LIB for $DUR seconds..." >&2
exec bpftrace -p "$PID" -e "
uprobe:$LIB:cu* { @calls[func] = count(); }
interval:s:$DUR { exit(); }
END {
	printf(\"\\nCalls in %d seconds (most frequent last):\\n\", $DUR);
	print(@calls);
	clear(@calls);
}"
