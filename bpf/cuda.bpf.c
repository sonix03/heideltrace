// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * P2, P3, P4, P7: uprobes on the CUDA Driver API in libcuda.so.
 *
 * User space attaches these programs per target PID and passes the symbol
 * index and function kind in the BPF cookie (see internal/abi/cuda.go).
 */
#include "helpers.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Keeps struct ht_event in the BTF so bpf2go can emit its Go layout. */
const struct ht_event *unused_ht_event __attribute__((unused));

static __always_inline __u32 ctrl_of(__u32 func)
{
	switch (func) {
	case F_LAUNCH_KERNEL:
	case F_LAUNCH_EX:
	case F_GRAPH_LAUNCH:
		return HT_P2_LAUNCH;
	case F_SYNC:
		return HT_P3_SYNC;
	case F_MEM_ALLOC:
	case F_MEM_FREE:
		return HT_P7_ALLOC;
	default:
		return HT_P4_MEMCPY;
	}
}

/*
 * Step boundary: a synchronization or a GPU -> host copy that waits for
 * the GPU. The summary since the previous boundary is sent as one EV_STEP
 * and then reset, so kernel launches are never sent one by one.
 */
static __always_inline void step_boundary(__u64 id, __u64 now, __u64 dur,
					  __u64 cookie, __u64 handle, __s32 ret)
{
	struct ht_event *e;
	struct tstat *s;

	s = tstat_get((__u32)id);
	if (!s)
		return;

	e = ev_new(EV_STEP, id, now);
	if (e) {
		e->dur_ns = dur;
		e->arg = handle;
		e->cookie = cookie;
		e->ret = ret;
		e->step = s->step;
		bpf_ringbuf_submit(e, 0);
	}

	__builtin_memset(&s->step, 0, sizeof(s->step));
	s->last_mark = now;
	s->lead_pending = 1;
}

/* ------------------------------------------------------------------ */
/* P2: kernel and CUDA Graph launches (entry probe only)               */
/* ------------------------------------------------------------------ */

SEC("uprobe")
int cuda_launch(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u64 cookie, now, gap;
	struct ht_event *e;
	struct tstat *s;
	__u32 func;

	if (!is_target(id >> 32) || !enabled(HT_P2_LAUNCH))
		return 0;

	cookie = bpf_get_attach_cookie(ctx);
	func = COOKIE_FUNC(cookie);
	now = bpf_ktime_get_ns();

	s = tstat_get((__u32)id);
	if (!s)
		return 0;

	if (s->lead_pending) {
		s->step.lead_ns = now - s->last_mark;
		s->lead_pending = 0;
	} else if (s->last_mark) {
		gap = now - s->last_mark;
		s->step.gap_sum_ns += gap;
		if (gap > s->step.gap_max_ns)
			s->step.gap_max_ns = gap;
	}
	s->last_mark = now;

	if (func == F_GRAPH_LAUNCH)
		s->step.graphs++;
	else
		s->step.launches++;

	/* Summary mode stops here. */
	if (!enabled(HT_MODE))
		return 0;

	e = ev_new(EV_LAUNCH, id, now);
	if (!e)
		return 0;
	e->cookie = cookie;

	if (func == F_GRAPH_LAUNCH) {
		/* cuGraphLaunch(CUgraphExec hGraphExec, CUstream hStream) */
		e->arg = PT_REGS_PARM1(ctx);
		e->arg2 = PT_REGS_PARM2(ctx);
	} else {
		__u64 grid, block;

		if (func == F_LAUNCH_EX) {
			/* cuLaunchKernelEx(const CUlaunchConfig *config, CUfunction f, ...) */
			__u32 dim[6] = {};

			bpf_probe_read_user(dim, sizeof(dim), (void *)PT_REGS_PARM1(ctx));
			e->arg = PT_REGS_PARM2(ctx);
			grid = (__u64)dim[0] * dim[1] * dim[2];
			block = (__u64)dim[3] * dim[4] * dim[5];
		} else {
			/* cuLaunchKernel(f, gridX, gridY, gridZ, blockX, blockY, blockZ, ...) */
			e->arg = PT_REGS_PARM1(ctx);
			grid = (__u64)(__u32)PT_REGS_PARM2(ctx) *
			       (__u32)PT_REGS_PARM3(ctx) *
			       (__u32)PT_REGS_PARM4(ctx);
			/* blockZ lives on the stack and is not read (usually 1). */
			block = (__u64)(__u32)PT_REGS_PARM5(ctx) *
				(__u32)PT_REGS_PARM6(ctx);
		}
		/* arg2 = grid blocks (40 bits) << 24 | threads per block (24 bits) */
		e->arg2 = ((grid & 0xffffffffffULL) << 24) | (block & 0xffffff);
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ------------------------------------------------------------------ */
/* P3, P4, P7: synchronization, memory copies, allocation              */
/* ------------------------------------------------------------------ */

SEC("uprobe")
int cuda_enter(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct inflight_key k = {};
	struct inflight_val v = {};
	__u64 cookie;
	__u32 func;

	if (!is_target(id >> 32))
		return 0;

	cookie = bpf_get_attach_cookie(ctx);
	func = COOKIE_FUNC(cookie);
	if (!enabled(ctrl_of(func)))
		return 0;

	k.tid = (__u32)id;
	k.sym = COOKIE_SYM(cookie);
	v.ts = bpf_ktime_get_ns();

	switch (func) {
	case F_SYNC:
		/* stream, event, or 0 for cuCtxSynchronize */
		v.arg = PT_REGS_PARM1(ctx);
		break;
	case F_MEM_ALLOC:
		/* cuMemAlloc(CUdeviceptr *dptr, size_t bytesize, ...) */
		v.arg = PT_REGS_PARM2(ctx);
		v.arg2 = PT_REGS_PARM1(ctx);
		break;
	case F_MEM_FREE:
		/* cuMemFree(CUdeviceptr dptr, ...) */
		v.arg2 = PT_REGS_PARM1(ctx);
		break;
	default:
		/* cuMemcpy*(dst, src, ByteCount[, hStream]) */
		v.arg = PT_REGS_PARM3(ctx);
		if (COOKIE_FLAGS(cookie) & HT_FLAG_ASYNC)
			v.arg2 = PT_REGS_PARM4(ctx);
		break;
	}

	bpf_map_update_elem(&inflight, &k, &v, BPF_ANY);
	return 0;
}

SEC("uretprobe")
int cuda_exit(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct inflight_key k = {};
	struct inflight_val v, *vp;
	struct ht_event *e;
	__u64 cookie, now, dur;
	__u32 func;
	__s32 ret;

	cookie = bpf_get_attach_cookie(ctx);
	k.tid = (__u32)id;
	k.sym = COOKIE_SYM(cookie);

	vp = bpf_map_lookup_elem(&inflight, &k);
	if (!vp)
		return 0;
	v = *vp;
	bpf_map_delete_elem(&inflight, &k);

	func = COOKIE_FUNC(cookie);
	now = bpf_ktime_get_ns();
	dur = now - v.ts;
	ret = (__s32)PT_REGS_RC(ctx);

	if (func == F_SYNC) {
		step_boundary(id, now, dur, cookie, v.arg, ret);
		return 0;
	}

	e = ev_new(func == F_MEM_ALLOC || func == F_MEM_FREE ? EV_ALLOC : EV_MEMCPY,
		   id, now);
	if (e) {
		e->dur_ns = dur;
		e->arg = v.arg;
		e->arg2 = v.arg2;
		e->cookie = cookie;
		e->ret = ret;
		if (func == F_MEM_ALLOC && v.arg2) {
			/* The allocated address is only known after the call returns. */
			__u64 ptr = 0;

			bpf_probe_read_user(&ptr, sizeof(ptr), (void *)v.arg2);
			e->arg2 = ptr;
		}
		bpf_ringbuf_submit(e, 0);
	}

	/* A synchronous GPU -> host copy also waits for the GPU to finish. */
	if (func == F_MEMCPY_DTOH && !(COOKIE_FLAGS(cookie) & HT_FLAG_ASYNC))
		step_boundary(id, now, dur, cookie, 0, ret);
	return 0;
}
