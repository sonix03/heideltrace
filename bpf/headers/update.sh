#!/usr/bin/env bash
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# Refreshes the vendored libbpf headers in this directory.
#
#   ./bpf/headers/update.sh            # libbpf headers only
#   ./bpf/headers/update.sh vmlinux    # also regenerate vmlinux.h (needs bpftool)
#
# vmlinux.h only has to come from a kernel that has every type the programs
# use. CO-RE relocates field offsets at load time, so the same object runs on
# other kernel versions.
set -euo pipefail

LIBBPF_VERSION=1.8.0
DIR=$(cd "$(dirname "$0")" && pwd)

prefix="libbpf-${LIBBPF_VERSION}"
curl -sSL "https://github.com/libbpf/libbpf/archive/refs/tags/v${LIBBPF_VERSION}.tar.gz" |
	tar -xz -C "$DIR" --xform='s#.*/##' \
		"$prefix/LICENSE.BSD-2-Clause" \
		"$prefix/src/bpf_core_read.h" \
		"$prefix/src/bpf_helper_defs.h" \
		"$prefix/src/bpf_helpers.h" \
		"$prefix/src/bpf_tracing.h"
echo "libbpf v${LIBBPF_VERSION} headers updated"

if [ "${1:-}" = "vmlinux" ]; then
	"${BPFTOOL:-bpftool}" btf dump file /sys/kernel/btf/vmlinux format c > "$DIR/vmlinux.h"
	echo "vmlinux.h regenerated from $(uname -r)"
fi
