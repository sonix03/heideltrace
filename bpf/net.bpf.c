// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * P1: TCP traffic of the API server.
 *
 * Records when a request is received and when every token is sent so that
 * TTFT and TPOT can be computed on the server side. Only sizes and times
 * are recorded, never payloads.
 */
#include "helpers.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define AF_INET		2
#define AF_INET6	10

/* Local port of the API server. 0 = all ports. */
const volatile __u16 net_port = 8000;

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
