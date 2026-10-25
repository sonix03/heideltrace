// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * P5: scheduler tracepoints.
 *
 * Accumulates, per target thread, how long it waited in the run queue and
 * how long it was off the CPU. The values end up in the next EV_STEP.
 */
#include "helpers.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define TASK_RUNNING	0

/* task_struct->state was renamed to __state in Linux 5.14. */
struct task_struct___new {
	unsigned int __state;
} __attribute__((preserve_access_index));

struct task_struct___old {
	long state;
} __attribute__((preserve_access_index));

static __always_inline long task_state(struct task_struct *t)
{
	struct task_struct___new *tn = (void *)t;
	struct task_struct___old *to = (void *)t;

	if (bpf_core_field_exists(tn->__state))
		return BPF_CORE_READ(tn, __state);
	return BPF_CORE_READ(to, state);
}

SEC("tp_btf/sched_switch")
int BPF_PROG(on_switch, bool preempt, struct task_struct *prev,
	     struct task_struct *next)
{
	__u64 now;
	struct tstat *s;
	__u32 tid;

	if (!enabled(HT_P5_SCHED))
		return 0;
	now = bpf_ktime_get_ns();

	/* Thread leaving the CPU. */
	if (is_target(BPF_CORE_READ(prev, tgid))) {
		tid = BPF_CORE_READ(prev, pid);
		s = tstat_get(tid);
		if (s) {
			if (preempt || task_state(prev) == TASK_RUNNING) {
				s->state = TS_RUNNABLE;
				s->step.nr_preempt++;
			} else {
				s->state = TS_SLEEPING;
			}
			s->state_ts = now;
			s->step.nr_switch++;
		}
	}

	/* Thread entering the CPU. */
	if (is_target(BPF_CORE_READ(next, tgid))) {
		tid = BPF_CORE_READ(next, pid);
		s = bpf_map_lookup_elem(&tstats, &tid);
		if (s) {
			if (s->state_ts) {
				if (s->state == TS_RUNNABLE)
					s->step.runq_ns += now - s->state_ts;
				else if (s->state == TS_SLEEPING)
					s->step.offcpu_ns += now - s->state_ts;
			}
			s->state = TS_ONCPU;
			s->state_ts = now;
		}
	}
	return 0;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(on_wakeup, struct task_struct *p)
{
	struct tstat *s;
	__u64 now;
	__u32 tid;

	if (!enabled(HT_P5_SCHED) || !is_target(BPF_CORE_READ(p, tgid)))
		return 0;

	tid = BPF_CORE_READ(p, pid);
	s = bpf_map_lookup_elem(&tstats, &tid);
	if (!s || s->state != TS_SLEEPING)
		return 0;

	now = bpf_ktime_get_ns();
	s->step.offcpu_ns += now - s->state_ts;
	s->state = TS_RUNNABLE;
	s->state_ts = now;
	return 0;
}
