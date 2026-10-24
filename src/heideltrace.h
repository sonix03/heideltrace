/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * Struktur data bersama antara program eBPF (heideltrace.bpf.c) dan
 * program ruang pengguna (heideltrace.c).
 *
 * Kode titik pengamatan P1-P8 mengikuti Tabel III.3.1 pada proposal.
 */
#ifndef __HEIDELTRACE_H
#define __HEIDELTRACE_H

/* Batas ukuran map agar memori kernel yang dipakai agen tetap kecil. */
#define HT_MAX_TARGETS		64
#define HT_MAX_THREADS		16384
#define HT_MAX_INFLIGHT		16384
#define HT_RINGBUF_BYTES	(4 * 1024 * 1024)

/* Indeks map kendali. Nilai 1 = menyala, 0 = mati. */
enum ht_ctrl {
	HT_P1_NET	= 1,	/* lalu lintas TCP API server */
	HT_P2_LAUNCH	= 2,	/* peluncuran kernel dan graf */
	HT_P3_SYNC	= 3,	/* sinkronisasi */
	HT_P4_MEMCPY	= 4,	/* penyalinan memori host <-> GPU */
	HT_P5_SCHED	= 5,	/* penjadwalan thread */
	HT_P6_PROC	= 6,	/* pembuatan dan penghentian proses */
	HT_P7_ALLOC	= 7,	/* alokasi memori GPU (opsional) */
	HT_P8_IOCTL	= 8,	/* ioctl ke driver (opsional) */
	HT_MODE		= 9,	/* 0 = ringkas, 1 = rinci */
	HT_CTRL_MAX	= 10,
};

/*
 * Jenis fungsi CUDA. Nilainya dikirim lewat BPF cookie bersama
 * indeks simbol agar ruang pengguna tahu nama fungsi yang tepat.
 *   cookie = (indeks_simbol << 16) | (flag << 8) | jenis
 */
enum ht_func {
	F_LAUNCH_KERNEL	= 1,	/* cuLaunchKernel(_ptsz) */
	F_LAUNCH_EX	= 2,	/* cuLaunchKernelEx(_ptsz) */
	F_GRAPH_LAUNCH	= 3,	/* cuGraphLaunch(_ptsz) */
	F_SYNC		= 4,	/* cuStreamSynchronize, cuEventSynchronize, cuCtxSynchronize */
	F_MEMCPY_HTOD	= 5,
	F_MEMCPY_DTOH	= 6,
	F_MEMCPY_DTOD	= 7,
	F_MEMCPY_ANY	= 8,	/* cuMemcpy(Async): arah ditentukan driver */
	F_MEM_ALLOC	= 9,
	F_MEM_FREE	= 10,
};

#define HT_FLAG_ASYNC	0x1

#define COOKIE_FUNC(c)	((__u32)((c) & 0xff))
#define COOKIE_FLAGS(c)	((__u32)(((c) >> 8) & 0xff))
#define COOKIE_SYM(c)	((__u32)((c) >> 16))

enum ht_event_type {
	EV_STEP		= 1,	/* ringkasan di antara dua batas langkah (P2, P3, P5) */
	EV_LAUNCH	= 2,	/* satu peluncuran kernel, hanya pada mode rinci */
	EV_MEMCPY	= 3,	/* satu penyalinan memori (P4) */
	EV_ALLOC	= 4,	/* satu alokasi atau pembebasan memori GPU (P7) */
	EV_NET		= 5,	/* satu pengiriman atau penerimaan TCP (P1) */
	EV_PROC_START	= 6,	/* proses anak baru dari proses sasaran (P6) */
	EV_PROC_EXIT	= 7,	/* proses sasaran berhenti (P6) */
	EV_IOCTL	= 8,	/* satu ioctl (P8) */
};

enum ht_net_dir {
	NET_RECV	= 1,
	NET_SEND	= 2,
	NET_CLOSE	= 3,
};

/* Besaran yang dikumpulkan di kernel di antara dua batas langkah. */
struct ht_step {
	__u64 launches;		/* jumlah peluncuran kernel */
	__u64 graphs;		/* jumlah peluncuran CUDA Graph */
	__u64 lead_ns;		/* batas langkah sebelumnya -> peluncuran pertama */
	__u64 gap_sum_ns;	/* total celah antarpeluncuran */
	__u64 gap_max_ns;	/* celah antarpeluncuran terpanjang */
	__u64 runq_ns;		/* siap berjalan tetapi belum mendapat giliran */
	__u64 offcpu_ns;	/* tidak berjalan karena menunggu (tidur, berhenti) */
	__u32 nr_preempt;	/* jumlah disela secara paksa */
	__u32 nr_switch;	/* jumlah keluar dari CPU */
};

struct ht_event {
	__u64 ts_ns;		/* bpf_ktime_get_ns() saat kejadian selesai */
	__u64 dur_ns;		/* lama pemanggilan, 0 jika tidak ada */
	__u64 arg;		/* ukuran byte, handle stream/fungsi, atau tgid induk */
	__u64 arg2;		/* informasi tambahan, lihat README */
	__u64 cookie;		/* cookie uprobe (berisi indeks simbol) */
	__u32 tgid;
	__u32 tid;
	__u32 type;		/* enum ht_event_type */
	__s32 ret;		/* nilai kembali fungsi CUDA (CUresult) atau syscall */
	struct ht_step step;	/* hanya diisi pada EV_STEP */
	char comm[16];
};

/* Permintaan penerjemahan PID dari namespace agen ke PID versi kernel. */
struct xlate_req {
	__u32 want;	/* PID di namespace agen */
	__u32 got;	/* PID versi kernel, 0 jika tidak ditemukan */
};

#endif /* __HEIDELTRACE_H */
