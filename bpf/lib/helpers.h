/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * Helpers shared by the eBPF programs.
 *
 * Every program only READS process and kernel state. No helper here or in
 * the .bpf.c files writes to process memory (bpf_probe_write_user),
 * overrides return values (bpf_override_return), or sends signals
 * (bpf_send_signal). Each program returns early when the event does not
 * come from a target process.
 */
#ifndef __HT_HELPERS_H
#define __HT_HELPERS_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"
#include "common.h"
#include "maps.h"

static __always_inline bool is_target(__u32 tgid)
{
	return bpf_map_lookup_elem(&targets, &tgid) != NULL;
}

static __always_inline bool enabled(__u32 idx)
{
	__u32 *v = bpf_map_lookup_elem(&control, &idx);

	return v && *v;
}

static __always_inline void count_drop(void)
{
	__u32 zero = 0;
	__u64 *d = bpf_map_lookup_elem(&dropped, &zero);

	if (d)
		*d += 1;
}

/* Reserves and initializes an event. The caller must submit it. */
static __always_inline struct ht_event *ev_new(__u32 type, __u64 id, __u64 now)
{
	struct ht_event *e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return NULL;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->ts_ns = now;
	e->tgid = id >> 32;
	e->tid = (__u32)id;
	e->type = type;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	return e;
}

/* Returns the summary of a thread, creating an empty one if needed. */
static __always_inline struct tstat *tstat_get(__u32 tid)
{
	struct tstat *s, zero = {};

	s = bpf_map_lookup_elem(&tstats, &tid);
	if (s)
		return s;
	bpf_map_update_elem(&tstats, &tid, &zero, BPF_NOEXIST);
	return bpf_map_lookup_elem(&tstats, &tid);
}

#endif /* __HT_HELPERS_H */
