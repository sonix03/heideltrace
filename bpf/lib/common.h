/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * Contract between the eBPF programs and user space.
 *
 * internal/abi/abi.go mirrors every constant and struct in this file.
 * Change both together; TestEventLayout in internal/bpf fails if the
 * struct layouts drift apart.
 *
 * Probe codes P1-P8 follow Table III.3.1 of the thesis proposal.
 */
#ifndef __HT_COMMON_H
#define __HT_COMMON_H

/* Map size limits keep the kernel memory used by the agent small. */
#define HT_MAX_TARGETS		64
#define HT_MAX_THREADS		16384
#define HT_MAX_INFLIGHT		16384
#define HT_RINGBUF_BYTES	(4 * 1024 * 1024)

/* Indices of the control map. A value of 1 enables the probe, 0 disables it. */
enum ht_ctrl {
	HT_P1_NET	= 1,	/* TCP traffic of the API server */
	HT_P2_LAUNCH	= 2,	/* kernel and graph launches */
	HT_P3_SYNC	= 3,	/* synchronization */
	HT_P4_MEMCPY	= 4,	/* host <-> GPU memory copies */
	HT_P5_SCHED	= 5,	/* thread scheduling */
	HT_P6_PROC	= 6,	/* process creation and exit */
	HT_P7_ALLOC	= 7,	/* GPU memory allocation (optional) */
	HT_P8_IOCTL	= 8,	/* ioctl to the driver (optional) */
	HT_MODE		= 9,	/* 0 = summary, 1 = detailed */
	HT_CTRL_MAX	= 10,
};

/*
 * Kind of CUDA function. User space passes it in the BPF cookie together
 * with the symbol index so that it can name the exact function later.
 *   cookie = (symbol_index << 16) | (flags << 8) | kind
 */
enum ht_func {
	F_LAUNCH_KERNEL	= 1,	/* cuLaunchKernel(_ptsz) */
	F_LAUNCH_EX	= 2,	/* cuLaunchKernelEx(_ptsz) */
	F_GRAPH_LAUNCH	= 3,	/* cuGraphLaunch(_ptsz) */
	F_SYNC		= 4,	/* cuStreamSynchronize, cuEventSynchronize, cuCtxSynchronize */
	F_MEMCPY_HTOD	= 5,
	F_MEMCPY_DTOH	= 6,
	F_MEMCPY_DTOD	= 7,
	F_MEMCPY_ANY	= 8,	/* cuMemcpy(Async): the driver picks the direction */
	F_MEM_ALLOC	= 9,
	F_MEM_FREE	= 10,
};

#define HT_FLAG_ASYNC	0x1

#define COOKIE_FUNC(c)	((__u32)((c) & 0xff))
#define COOKIE_FLAGS(c)	((__u32)(((c) >> 8) & 0xff))
#define COOKIE_SYM(c)	((__u32)((c) >> 16))

enum ht_event_type {
	EV_STEP		= 1,	/* summary between two step boundaries (P2, P3, P5) */
	EV_LAUNCH	= 2,	/* one kernel launch, detailed mode only */
	EV_MEMCPY	= 3,	/* one memory copy (P4) */
	EV_ALLOC	= 4,	/* one GPU memory allocation or free (P7) */
	EV_NET		= 5,	/* one TCP send or receive (P1) */
	EV_PROC_START	= 6,	/* new child process of a target (P6) */
	EV_PROC_EXIT	= 7,	/* target process exited (P6) */
	EV_IOCTL	= 8,	/* one ioctl (P8) */
};

enum ht_net_dir {
	NET_RECV	= 1,
	NET_SEND	= 2,
	NET_CLOSE	= 3,
};

/* Values aggregated in the kernel between two step boundaries. */
struct ht_step {
	__u64 launches;		/* kernel launches */
	__u64 graphs;		/* CUDA Graph launches */
	__u64 lead_ns;		/* previous step boundary -> first launch */
	__u64 gap_sum_ns;	/* total gap between launches */
	__u64 gap_max_ns;	/* longest gap between launches */
	__u64 runq_ns;		/* runnable but waiting for a CPU */
	__u64 offcpu_ns;	/* not running because it waits (sleep, stop) */
	__u32 nr_preempt;	/* times preempted */
	__u32 nr_switch;	/* times switched off the CPU */
};

struct ht_event {
	__u64 ts_ns;		/* bpf_ktime_get_ns() when the event completed */
	__u64 dur_ns;		/* call duration, 0 if not applicable */
	__u64 arg;		/* byte count, stream/function handle, or parent tgid */
	__u64 arg2;		/* extra data, see internal/event/decode.go */
	__u64 cookie;		/* uprobe cookie (holds the symbol index) */
	__u32 tgid;
	__u32 tid;
	__u32 type;		/* enum ht_event_type */
	__s32 ret;		/* return value of the CUDA call (CUresult) or syscall */
	struct ht_step step;	/* only filled for EV_STEP */
	char comm[16];
};

/* Request to translate a PID from the agent's namespace to the kernel PID. */
struct xlate_req {
	__u32 want;	/* PID in the agent's namespace */
	__u32 got;	/* kernel PID, 0 if not found */
};

#endif /* __HT_COMMON_H */
