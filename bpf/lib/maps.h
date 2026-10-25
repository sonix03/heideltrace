/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * Maps shared by every eBPF object.
 *
 * Each .bpf.c file is compiled into its own object and therefore declares
 * its own copy of these maps. At load time internal/loader creates one
 * instance of each map and hands it to every object through
 * MapReplacements, so all programs see the same data. Keep the names in
 * sync with sharedMaps in internal/loader/loader.go.
 */
#ifndef __HT_MAPS_H
#define __HT_MAPS_H

#include "common.h"

/* Filter map: tgid of every target process. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, HT_MAX_TARGETS);
	__type(key, __u32);
	__type(value, __u32);
} targets SEC(".maps");

/* Control map: switches probes on and off at runtime. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, HT_CTRL_MAX);
	__type(key, __u32);
	__type(value, __u32);
} control SEC(".maps");

/* Event channel to user space. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, HT_RINGBUF_BYTES);
} events SEC(".maps");

/* Events that did not fit in the ring buffer. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} dropped SEC(".maps");

/* Entry time of calls in flight, paired with the matching return probe. */
struct inflight_key {
	__u32 tid;
	__u32 sym;
};

struct inflight_val {
	__u64 ts;
	__u64 arg;
	__u64 arg2;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, HT_MAX_INFLIGHT);
	__type(key, struct inflight_key);
	__type(value, struct inflight_val);
} inflight SEC(".maps");

/* Per-thread summary map. */
enum tstate {
	TS_UNKNOWN	= 0,
	TS_ONCPU	= 1,
	TS_RUNNABLE	= 2,
	TS_SLEEPING	= 3,
};

struct tstat {
	struct ht_step step;
	__u64 last_mark;	/* last launch or last step boundary */
	__u64 state_ts;		/* time of the last scheduling state change */
	__u32 state;		/* enum tstate */
	__u32 lead_pending;	/* 1 = the next launch is the first of the step */
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, HT_MAX_THREADS);
	__type(key, __u32);
	__type(value, struct tstat);
} tstats SEC(".maps");

#endif /* __HT_MAPS_H */
