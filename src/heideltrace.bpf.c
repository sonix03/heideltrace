// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Program eBPF heideltrace.
 *
 * Semua program di sini hanya MEMBACA keadaan proses dan kernel.
 * Tidak ada helper yang menulis ke memori proses (bpf_probe_write_user),
 * mengubah nilai kembali fungsi (bpf_override_return), atau mengirim
 * sinyal (bpf_send_signal). Setiap program langsung berhenti jika
 * kejadian tidak berasal dari proses sasaran.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "heideltrace.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define AF_INET		2
#define AF_INET6	10
#define TASK_RUNNING	0

/* Port lokal API server yang diamati pada P1. Nilai 0 = semua port. */
const volatile __u16 net_port = 8000;

/*
 * Inode namespace PID tempat agen berjalan. Nilai 0 berarti agen berada di
 * namespace PID awal (host) sehingga PID tidak perlu diterjemahkan.
 * Map dan filter selalu memakai PID versi kernel (namespace awal).
 */
const volatile __u64 pidns_ino = 0;

/* ------------------------------------------------------------------ */
/* Map                                                                */
/* ------------------------------------------------------------------ */

/* Map penyaring: tgid proses sasaran. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, HT_MAX_TARGETS);
	__type(key, __u32);
	__type(value, __u32);
} targets SEC(".maps");

/* Map kendali: menyalakan dan mematikan titik pengamatan saat berjalan. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, HT_CTRL_MAX);
	__type(key, __u32);
	__type(value, __u32);
} control SEC(".maps");

/* Saluran kejadian ke ruang pengguna. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, HT_RINGBUF_BYTES);
} events SEC(".maps");

/* Penghitung kejadian yang gagal masuk ring buffer. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} dropped SEC(".maps");

/* Waktu masuk fungsi yang sedang berjalan, dipasangkan dengan uretprobe. */
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

/* Map ringkasan per thread. */
enum tstate {
	TS_UNKNOWN	= 0,
	TS_ONCPU	= 1,
	TS_RUNNABLE	= 2,
	TS_SLEEPING	= 3,
};

struct tstat {
	struct ht_step step;
	__u64 last_mark;	/* peluncuran terakhir atau batas langkah terakhir */
	__u64 state_ts;		/* waktu perubahan keadaan penjadwalan terakhir */
	__u32 state;		/* enum tstate */
	__u32 lead_pending;	/* 1 = peluncuran berikutnya adalah yang pertama */
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, HT_MAX_THREADS);
	__type(key, __u32);
	__type(value, struct tstat);
} tstats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct xlate_req);
} xlate SEC(".maps");

/* Kunci khusus inflight untuk ioctl (P8), di luar rentang indeks simbol. */
#define SYM_IOCTL	0xffffffff

/* ------------------------------------------------------------------ */
/* Fungsi bantu                                                       */
/* ------------------------------------------------------------------ */

static __always_inline bool is_target(__u32 tgid)
{
	return bpf_map_lookup_elem(&targets, &tgid) != NULL;
}

static __always_inline bool enabled(__u32 idx)
{
	__u32 *v = bpf_map_lookup_elem(&control, &idx);

	return v && *v;
}

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

static __always_inline void count_drop(void)
{
	__u32 zero = 0;
	__u64 *d = bpf_map_lookup_elem(&dropped, &zero);

	if (d)
		*d += 1;
}

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

static __always_inline struct tstat *tstat_get(__u32 tid)
{
	struct tstat *s, zero = {};

	s = bpf_map_lookup_elem(&tstats, &tid);
	if (s)
		return s;
	bpf_map_update_elem(&tstats, &tid, &zero, BPF_NOEXIST);
	return bpf_map_lookup_elem(&tstats, &tid);
}

/*
 * Batas langkah: sinkronisasi atau penyalinan GPU -> host yang menunggu.
 * Ringkasan sejak batas sebelumnya dikirim sebagai satu EV_STEP lalu
 * direset sehingga peluncuran kernel tidak dikirim satu per satu.
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

/* task_struct->state berganti nama menjadi __state sejak Linux 5.14. */
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

/* tgid sebuah task dilihat dari namespace PID agen (0 jika tidak terlihat). */
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

/* Dijalankan sekali per proses sasaran baru, bukan pada jalur panas. */
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

/* ------------------------------------------------------------------ */
/* P2: peluncuran kernel dan CUDA Graph (uprobe saja)                  */
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

	/* Mode ringkas berhenti di sini. */
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
			/* blockZ ada di stack dan tidak dibaca (umumnya bernilai 1). */
			block = (__u64)(__u32)PT_REGS_PARM5(ctx) *
				(__u32)PT_REGS_PARM6(ctx);
		}
		/* arg2 = jumlah blok grid (40 bit) << 24 | thread per blok (24 bit) */
		e->arg2 = ((grid & 0xffffffffffULL) << 24) | (block & 0xffffff);
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ------------------------------------------------------------------ */
/* P3, P4, P7: sinkronisasi, penyalinan memori, alokasi                */
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
		/* stream, event, atau 0 untuk cuCtxSynchronize */
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
			/* Alamat hasil alokasi baru tersedia setelah fungsi kembali. */
			__u64 ptr = 0;

			bpf_probe_read_user(&ptr, sizeof(ptr), (void *)v.arg2);
			e->arg2 = ptr;
		}
		bpf_ringbuf_submit(e, 0);
	}

	/* Penyalinan GPU -> host yang sinkron juga menunggu GPU selesai. */
	if (func == F_MEMCPY_DTOH && !(COOKIE_FLAGS(cookie) & HT_FLAG_ASYNC))
		step_boundary(id, now, dur, cookie, 0, ret);
	return 0;
}

/* ------------------------------------------------------------------ */
/* P5: penjadwalan thread                                              */
/* ------------------------------------------------------------------ */

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

	/* Thread yang keluar dari CPU. */
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

	/* Thread yang masuk ke CPU. */
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

/* ------------------------------------------------------------------ */
/* P6: pembuatan dan penghentian proses                                */
/* ------------------------------------------------------------------ */

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
	/* Thread baru di proses yang sama sudah ikut tersaring lewat tgid. */
	if (ptgid == ctgid || !is_target(ptgid))
		return 0;

	err = bpf_map_update_elem(&targets, &ctgid, &one, BPF_NOEXIST);

	e = ev_new(EV_PROC_START, bpf_get_current_pid_tgid(), bpf_ktime_get_ns());
	if (!e)
		return 0;
	e->tgid = ctgid;
	e->tid = BPF_CORE_READ(child, pid);
	e->arg = ptgid;
	/* PID anak di namespace agen, dipakai untuk /proc dan pemasangan uprobe. */
	e->arg2 = pidns_ino ? ns_tgid(child) : ctgid;
	e->ret = err;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* Selalu terpasang agar map tidak berisi proses yang sudah berhenti. */
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

/* ------------------------------------------------------------------ */
/* P1: lalu lintas TCP pada API server                                 */
/* ------------------------------------------------------------------ */

static __always_inline int net_event(struct sock *sk, __u32 dir, __u64 bytes)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct ht_event *e;
	__u16 family;

	if (!is_target(id >> 32) || !enabled(HT_P1_NET))
		return 0;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6)
		return 0;
	if (net_port && BPF_CORE_READ(sk, __sk_common.skc_num) != net_port)
		return 0;

	e = ev_new(EV_NET, id, bpf_ktime_get_ns());
	if (!e)
		return 0;
	e->arg = bytes;
	e->arg2 = (__u64)sk;
	e->cookie = dir;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(on_tcp_send, struct sock *sk, struct msghdr *msg, size_t size)
{
	return net_event(sk, NET_SEND, size);
}

SEC("fentry/tcp_cleanup_rbuf")
int BPF_PROG(on_tcp_recv, struct sock *sk, int copied)
{
	if (copied <= 0)
		return 0;
	return net_event(sk, NET_RECV, copied);
}

SEC("fentry/tcp_close")
int BPF_PROG(on_tcp_close, struct sock *sk, long timeout)
{
	return net_event(sk, NET_CLOSE, 0);
}

/* ------------------------------------------------------------------ */
/* P8: ioctl ke driver (opsional, tidak dimuat secara bawaan)          */
/* ------------------------------------------------------------------ */

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
