// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * P8: ioctl calls of target processes (optional, not loaded by default).
 *
 * A rough estimate of driver activity. Every ioctl of a target is recorded;
 * filtering to /dev/nvidia* file descriptors is left to user space.
 */
#include "helpers.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* inflight key reserved for ioctl, outside the range of symbol indices. */
#define SYM_IOCTL	0xffffffff

SEC("tp/syscalls/sys_enter_ioctl")
int on_ioctl_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct inflight_key k = {};
	struct inflight_val v = {};

	if (!is_target(id >> 32) || !enabled(HT_P8_IOCTL))
		return 0;

	k.tid = (__u32)id;
	k.sym = SYM_IOCTL;
	v.ts = bpf_ktime_get_ns();
	v.arg = ctx->args[1];	/* cmd */
	v.arg2 = ctx->args[0];	/* fd */
	bpf_map_update_elem(&inflight, &k, &v, BPF_ANY);
	return 0;
}

SEC("tp/syscalls/sys_exit_ioctl")
int on_ioctl_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct inflight_key k = {};
	struct inflight_val *vp;
	struct ht_event *e;
	__u64 now;

	k.tid = (__u32)id;
	k.sym = SYM_IOCTL;
	vp = bpf_map_lookup_elem(&inflight, &k);
	if (!vp)
		return 0;

	now = bpf_ktime_get_ns();
	e = ev_new(EV_IOCTL, id, now);
	if (e) {
		e->dur_ns = now - vp->ts;
		e->arg = vp->arg;
		e->arg2 = vp->arg2;
		e->ret = (__s32)ctx->ret;
		bpf_ringbuf_submit(e, 0);
	}
	bpf_map_delete_elem(&inflight, &k);
	return 0;
}
