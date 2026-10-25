// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * P6: process creation and exit, plus PID namespace translation.
 *
 * Child processes of a target (for example the vLLM EngineCore) are added
 * to the filter map automatically. on_proc_exit is always loaded so the
 * maps never keep processes that are gone.
 */
#include "helpers.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * Inode of the agent's PID namespace. 0 means the agent runs in the initial
 * (host) namespace and PIDs need no translation. Maps and filters always
 * use kernel PIDs (initial namespace).
 */
const volatile __u64 pidns_ino = 0;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct xlate_req);
} xlate SEC(".maps");

/* tgid of a task as seen from the agent's PID namespace (0 if not visible). */
static __always_inline __u32 ns_tgid(struct task_struct *t)
{
	struct pid *p = BPF_CORE_READ(t, group_leader, thread_pid);
	unsigned int level = BPF_CORE_READ(p, level);

	for (int i = 0; i < 8; i++) {
		struct upid up = {};

		if (i > level)
			break;
		bpf_probe_read_kernel(&up, sizeof(up), &p->numbers[i]);
		if (up.ns && BPF_CORE_READ(up.ns, ns.inum) == pidns_ino)
			return up.nr;
	}
	return 0;
}

/* Runs once per new target, never on a hot path. */
SEC("iter/task")
int xlate_pid(struct bpf_iter__task *ctx)
{
	struct task_struct *t = ctx->task;
	struct xlate_req *x;
	__u32 zero = 0;

	if (!t || t->pid != t->tgid)
		return 0;
	x = bpf_map_lookup_elem(&xlate, &zero);
	if (!x || x->got)
		return 0;
	if (ns_tgid(t) == x->want)
		x->got = t->tgid;
	return 0;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(on_proc_fork, struct task_struct *parent, struct task_struct *child)
{
	__u32 ptgid, ctgid, one = 1;
	struct ht_event *e;
	int err;

	if (!enabled(HT_P6_PROC))
		return 0;

	ptgid = BPF_CORE_READ(parent, tgid);
	ctgid = BPF_CORE_READ(child, tgid);
	/* New threads of the same process already pass the tgid filter. */
	if (ptgid == ctgid || !is_target(ptgid))
		return 0;

	err = bpf_map_update_elem(&targets, &ctgid, &one, BPF_NOEXIST);

	e = ev_new(EV_PROC_START, bpf_get_current_pid_tgid(), bpf_ktime_get_ns());
	if (!e)
		return 0;
	e->tgid = ctgid;
	e->tid = BPF_CORE_READ(child, pid);
	e->arg = ptgid;
	/* Child PID in the agent's namespace, used for /proc and uprobes. */
	e->arg2 = pidns_ino ? ns_tgid(child) : ctgid;
	e->ret = err;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(on_proc_exit, struct task_struct *p)
{
	__u32 tgid = BPF_CORE_READ(p, tgid);
	__u32 tid = BPF_CORE_READ(p, pid);
	struct ht_event *e;

	if (!is_target(tgid))
		return 0;

	bpf_map_delete_elem(&tstats, &tid);
	if (tid != tgid)
		return 0;

	bpf_map_delete_elem(&targets, &tgid);
	e = ev_new(EV_PROC_EXIT, bpf_get_current_pid_tgid(), bpf_ktime_get_ns());
	if (e)
		bpf_ringbuf_submit(e, 0);
	return 0;
}
