// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * heideltrace: agen observability berbasis eBPF untuk server inferensi LLM.
 *
 * Program ini memuat program eBPF, memasang titik pengamatan pada proses
 * sasaran tanpa mengubah prosesnya, lalu menuliskan setiap kejadian sebagai
 * satu baris JSON. Semua uprobe dipasang khusus untuk PID sasaran sehingga
 * proses lain yang memakai libcuda.so tidak ikut terkena biaya uprobe.
 */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include "heideltrace.h"
#include "heideltrace.skel.h"

#define HT_VERSION	"0.1.0"
#define MAX_LINKS	128
#define SCAN_MS		500
#define REPORT_MS	10000

/* ------------------------------------------------------------------ */
/* Daftar fungsi CUDA Driver API yang diamati                         */
/* ------------------------------------------------------------------ */

struct cuda_sym {
	const char *name;
	__u32 func;
	__u32 flags;
	__u32 ctrl;
};

static const struct cuda_sym cuda_syms[] = {
	/* P2: peluncuran kernel dan graf */
	{ "cuLaunchKernel",		F_LAUNCH_KERNEL, 0, HT_P2_LAUNCH },
	{ "cuLaunchKernel_ptsz",	F_LAUNCH_KERNEL, 0, HT_P2_LAUNCH },
	{ "cuLaunchKernelEx",		F_LAUNCH_EX, 0, HT_P2_LAUNCH },
	{ "cuLaunchKernelEx_ptsz",	F_LAUNCH_EX, 0, HT_P2_LAUNCH },
	{ "cuGraphLaunch",		F_GRAPH_LAUNCH, 0, HT_P2_LAUNCH },
	{ "cuGraphLaunch_ptsz",		F_GRAPH_LAUNCH, 0, HT_P2_LAUNCH },
	/* P3: sinkronisasi */
	{ "cuStreamSynchronize",	F_SYNC, 0, HT_P3_SYNC },
	{ "cuStreamSynchronize_ptsz",	F_SYNC, 0, HT_P3_SYNC },
	{ "cuEventSynchronize",		F_SYNC, 0, HT_P3_SYNC },
	{ "cuCtxSynchronize",		F_SYNC, 0, HT_P3_SYNC },
	/* P4: penyalinan memori */
	{ "cuMemcpyHtoD_v2",		F_MEMCPY_HTOD, 0, HT_P4_MEMCPY },
	{ "cuMemcpyHtoD_v2_ptds",	F_MEMCPY_HTOD, 0, HT_P4_MEMCPY },
	{ "cuMemcpyHtoDAsync_v2",	F_MEMCPY_HTOD, HT_FLAG_ASYNC, HT_P4_MEMCPY },
	{ "cuMemcpyHtoDAsync_v2_ptsz",	F_MEMCPY_HTOD, HT_FLAG_ASYNC, HT_P4_MEMCPY },
	{ "cuMemcpyDtoH_v2",		F_MEMCPY_DTOH, 0, HT_P4_MEMCPY },
	{ "cuMemcpyDtoH_v2_ptds",	F_MEMCPY_DTOH, 0, HT_P4_MEMCPY },
	{ "cuMemcpyDtoHAsync_v2",	F_MEMCPY_DTOH, HT_FLAG_ASYNC, HT_P4_MEMCPY },
	{ "cuMemcpyDtoHAsync_v2_ptsz",	F_MEMCPY_DTOH, HT_FLAG_ASYNC, HT_P4_MEMCPY },
	{ "cuMemcpyDtoD_v2",		F_MEMCPY_DTOD, 0, HT_P4_MEMCPY },
	{ "cuMemcpyDtoD_v2_ptds",	F_MEMCPY_DTOD, 0, HT_P4_MEMCPY },
	{ "cuMemcpyDtoDAsync_v2",	F_MEMCPY_DTOD, HT_FLAG_ASYNC, HT_P4_MEMCPY },
	{ "cuMemcpyDtoDAsync_v2_ptsz",	F_MEMCPY_DTOD, HT_FLAG_ASYNC, HT_P4_MEMCPY },
	{ "cuMemcpy",			F_MEMCPY_ANY, 0, HT_P4_MEMCPY },
	{ "cuMemcpy_ptds",		F_MEMCPY_ANY, 0, HT_P4_MEMCPY },
	{ "cuMemcpyAsync",		F_MEMCPY_ANY, HT_FLAG_ASYNC, HT_P4_MEMCPY },
	{ "cuMemcpyAsync_ptsz",		F_MEMCPY_ANY, HT_FLAG_ASYNC, HT_P4_MEMCPY },
	/* P7: alokasi memori GPU (opsional) */
	{ "cuMemAlloc_v2",		F_MEM_ALLOC, 0, HT_P7_ALLOC },
	{ "cuMemAllocAsync",		F_MEM_ALLOC, HT_FLAG_ASYNC, HT_P7_ALLOC },
	{ "cuMemAllocAsync_ptsz",	F_MEM_ALLOC, HT_FLAG_ASYNC, HT_P7_ALLOC },
	{ "cuMemFree_v2",		F_MEM_FREE, 0, HT_P7_ALLOC },
	{ "cuMemFreeAsync",		F_MEM_FREE, HT_FLAG_ASYNC, HT_P7_ALLOC },
	{ "cuMemFreeAsync_ptsz",	F_MEM_FREE, HT_FLAG_ASYNC, HT_P7_ALLOC },
};

#define N_CUDA_SYMS (sizeof(cuda_syms) / sizeof(cuda_syms[0]))

/* ------------------------------------------------------------------ */
/* Opsi                                                               */
/* ------------------------------------------------------------------ */

static struct env {
	int pids[HT_MAX_TARGETS];
	int npids;
	const char *output;
	const char *libcuda;
	int port;
	bool on[HT_CTRL_MAX];
	bool rinci;
	bool check;
	bool verbose;
	long duration;
} env = {
	.port = 8000,
	/* P1-P6 menyala, P7 dan P8 opsional */
	.on = { [HT_P1_NET] = true, [HT_P2_LAUNCH] = true, [HT_P3_SYNC] = true,
		[HT_P4_MEMCPY] = true, [HT_P5_SCHED] = true, [HT_P6_PROC] = true },
};

static void usage(FILE *f)
{
	fprintf(f,
"Pemakaian: heideltrace -p PID [opsi]\n"
"\n"
"Mengamati proses inferensi (misalnya vLLM) dan seluruh proses anaknya.\n"
"Hasil ditulis sebagai JSON Lines. Harus dijalankan sebagai root.\n"
"\n"
"  -p, --pid PID        PID sasaran, boleh diulang (proses anak ikut diamati)\n"
"  -o, --output FILE    berkas keluaran JSON Lines (bawaan: stdout)\n"
"      --port N         port API server untuk P1 (bawaan 8000, 0 = semua)\n"
"      --enable LIST    nyalakan titik pengamatan, contoh: P7,P8\n"
"      --disable LIST   matikan titik pengamatan, contoh: P1,P5\n"
"      --rinci          mulai pada mode rinci (setiap peluncuran kernel dikirim)\n"
"      --libcuda PATH   lokasi libcuda.so jika tidak terdeteksi otomatis\n"
"  -d, --duration SEC   berhenti otomatis setelah SEC detik\n"
"      --check          hanya muat program eBPF ke verifier lalu keluar\n"
"  -v, --verbose        tampilkan log libbpf\n"
"  -h, --help           tampilkan bantuan ini\n"
"\n"
"Saat berjalan: kirim SIGUSR1 untuk berpindah mode ringkas/rinci.\n");
}

static int parse_probe_list(const char *arg, bool val)
{
	char buf[128], *tok, *save = NULL;

	snprintf(buf, sizeof(buf), "%s", arg);
	for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
		char *end;
		long n;

		if (*tok == 'P' || *tok == 'p')
			tok++;
		n = strtol(tok, &end, 10);
		if (*end || n < HT_P1_NET || n > HT_P8_IOCTL) {
			fprintf(stderr, "Titik pengamatan tidak dikenal: %s\n", tok);
			return -1;
		}
		env.on[n] = val;
	}
	return 0;
}

static int parse_args(int argc, char **argv)
{
	enum { OPT_PORT = 256, OPT_ENABLE, OPT_DISABLE, OPT_RINCI, OPT_LIBCUDA, OPT_CHECK };
	static const struct option opts[] = {
		{ "pid",	required_argument, NULL, 'p' },
		{ "output",	required_argument, NULL, 'o' },
		{ "port",	required_argument, NULL, OPT_PORT },
		{ "enable",	required_argument, NULL, OPT_ENABLE },
		{ "disable",	required_argument, NULL, OPT_DISABLE },
		{ "rinci",	no_argument,       NULL, OPT_RINCI },
		{ "libcuda",	required_argument, NULL, OPT_LIBCUDA },
		{ "duration",	required_argument, NULL, 'd' },
		{ "check",	no_argument,       NULL, OPT_CHECK },
		{ "verbose",	no_argument,       NULL, 'v' },
		{ "help",	no_argument,       NULL, 'h' },
		{}
	};
	int c;

	while ((c = getopt_long(argc, argv, "p:o:d:vh", opts, NULL)) != -1) {
		switch (c) {
		case 'p':
			if (env.npids >= HT_MAX_TARGETS)
				return -1;
			env.pids[env.npids++] = atoi(optarg);
			break;
		case 'o':
			env.output = optarg;
			break;
		case OPT_PORT:
			env.port = atoi(optarg);
			break;
		case OPT_ENABLE:
			if (parse_probe_list(optarg, true))
				return -1;
			break;
		case OPT_DISABLE:
			if (parse_probe_list(optarg, false))
				return -1;
			break;
		case OPT_RINCI:
			env.rinci = true;
			break;
		case OPT_LIBCUDA:
			env.libcuda = optarg;
			break;
		case 'd':
			env.duration = atol(optarg);
			break;
		case OPT_CHECK:
			env.check = true;
			break;
		case 'v':
			env.verbose = true;
			break;
		case 'h':
			usage(stdout);
			exit(0);
		default:
			usage(stderr);
			return -1;
		}
	}
	if (!env.check && env.npids == 0) {
		fprintf(stderr, "Minimal satu PID sasaran harus diberikan (-p).\n\n");
		usage(stderr);
		return -1;
	}
	if (env.port < 0 || env.port > 65535) {
		fprintf(stderr, "Port tidak valid: %d\n", env.port);
		return -1;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* Keadaan program                                                    */
/* ------------------------------------------------------------------ */

static volatile sig_atomic_t exiting;
static volatile sig_atomic_t toggle_mode;
static bool quiet_libbpf;

static struct heideltrace_bpf *skel;
static FILE *out;
static __u64 n_events;

struct target {
	int pid;		/* PID di namespace agen (untuk /proc dan uprobe) */
	__u32 kpid;		/* PID versi kernel (kunci map penyaring) */
	bool used;
	bool cuda_attached;
	int nlinks;
	struct bpf_link *links[MAX_LINKS];
};

static struct target tgts[HT_MAX_TARGETS];
static __u64 pidns_ino;
static struct bpf_link *xlate_link;

static void sig_handler(int sig)
{
	if (sig == SIGUSR1)
		toggle_mode = 1;
	else
		exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	/* Simbol yang tidak ada pada versi libcuda tertentu bukan kesalahan. */
	if (quiet_libbpf && !env.verbose)
		return 0;
	return vfprintf(stderr, fmt, args);
}

static __u64 now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000;
}

/* Inode namespace PID awal selalu PROC_PID_INIT_INO (0xEFFFFFFC). */
static bool in_init_pidns(void)
{
	struct stat st;

	return stat("/proc/self/ns/pid", &st) == 0 && st.st_ino == 0xEFFFFFFCULL;
}

static void read_comm(int pid, char *buf, size_t len)
{
	char path[64];
	FILE *f;

	snprintf(buf, len, "?");
	snprintf(path, sizeof(path), "/proc/%d/comm", pid);
	f = fopen(path, "r");
	if (!f)
		return;
	if (fgets(buf, len, f))
		buf[strcspn(buf, "\n")] = '\0';
	fclose(f);
}

/* ------------------------------------------------------------------ */
/* Pengelolaan proses sasaran                                         */
/* ------------------------------------------------------------------ */

/*
 * Program eBPF selalu melihat PID versi kernel. Jika agen berjalan di
 * namespace PID lain (kontainer, WSL), PID diterjemahkan dengan task iterator.
 */
static __u32 kernel_pid(int pid)
{
	struct xlate_req req = { .want = pid };
	int fd = bpf_map__fd(skel->maps.xlate), iter;
	__u32 zero = 0;
	char buf[64];

	if (!pidns_ino)
		return pid;
	if (!xlate_link || bpf_map_update_elem(fd, &zero, &req, BPF_ANY))
		return 0;
	iter = bpf_iter_create(bpf_link__fd(xlate_link));
	if (iter < 0)
		return 0;
	while (read(iter, buf, sizeof(buf)) > 0)
		;
	close(iter);
	if (bpf_map_lookup_elem(fd, &zero, &req))
		return 0;
	return req.got;
}

static struct target *target_find(int pid)
{
	for (int i = 0; i < HT_MAX_TARGETS; i++)
		if (tgts[i].used && tgts[i].pid == pid)
			return &tgts[i];
	return NULL;
}

static struct target *target_find_k(__u32 kpid)
{
	for (int i = 0; i < HT_MAX_TARGETS; i++)
		if (tgts[i].used && tgts[i].kpid == kpid)
			return &tgts[i];
	return NULL;
}

/* kpid = 0 berarti PID versi kernel dicari sendiri. */
static struct target *target_add(int pid, __u32 kpid)
{
	struct target *t = target_find(pid);
	__u32 val = 1;
	char comm[32];

	if (t)
		return t;
	if (!kpid)
		kpid = kernel_pid(pid);
	if (!kpid) {
		fprintf(stderr, "[heideltrace] PID %d tidak dapat diterjemahkan ke PID kernel\n", pid);
		return NULL;
	}
	for (int i = 0; i < HT_MAX_TARGETS; i++) {
		if (tgts[i].used)
			continue;
		t = &tgts[i];
		memset(t, 0, sizeof(*t));
		t->used = true;
		t->pid = pid;
		t->kpid = kpid;
		if (bpf_map_update_elem(bpf_map__fd(skel->maps.targets), &kpid, &val, BPF_ANY))
			fprintf(stderr, "[heideltrace] gagal menambah PID %d ke map penyaring: %s\n",
				pid, strerror(errno));
		read_comm(pid, comm, sizeof(comm));
		if (kpid != (__u32)pid)
			fprintf(stderr, "[heideltrace] mengamati PID %d (%s), PID kernel %u\n",
				pid, comm, kpid);
		else
			fprintf(stderr, "[heideltrace] mengamati PID %d (%s)\n", pid, comm);
		return t;
	}
	fprintf(stderr, "[heideltrace] batas %d proses sasaran tercapai, PID %d diabaikan\n",
		HT_MAX_TARGETS, pid);
	return NULL;
}

static void target_detach(struct target *t)
{
	for (int i = 0; i < t->nlinks; i++)
		bpf_link__destroy(t->links[i]);
	t->nlinks = 0;
	t->cuda_attached = false;
}

static void target_remove(struct target *t)
{
	target_detach(t);
	bpf_map_delete_elem(bpf_map__fd(skel->maps.targets), &t->kpid);
	t->used = false;
	fprintf(stderr, "[heideltrace] PID %d berhenti, titik pengamatan dilepas\n", t->pid);
}

static int read_ppid(int pid)
{
	char path[64], buf[512], *p;
	int ppid = -1;
	FILE *f;

	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	f = fopen(path, "r");
	if (!f)
		return -1;
	if (fgets(buf, sizeof(buf), f)) {
		/* Nama proses bisa mengandung spasi, jadi cari ')' terakhir. */
		p = strrchr(buf, ')');
		if (p)
			sscanf(p + 1, " %*c %d", &ppid);
	}
	fclose(f);
	return ppid;
}

/* Tambahkan seluruh proses turunan yang sudah ada sebelum agen berjalan. */
static void add_descendants(void)
{
	bool added = true;

	while (added) {
		struct dirent *de;
		DIR *d;

		added = false;
		d = opendir("/proc");
		if (!d)
			return;
		while ((de = readdir(d))) {
			int pid, ppid;

			if (!isdigit((unsigned char)de->d_name[0]))
				continue;
			pid = atoi(de->d_name);
			if (target_find(pid))
				continue;
			ppid = read_ppid(pid);
			if (ppid > 0 && target_find(ppid) && target_add(pid, 0))
				added = true;
		}
		closedir(d);
	}
}

/* Cari libcuda.so yang dipetakan oleh proses. Mengembalikan 0 jika ada. */
static int find_libcuda(int pid, char *buf, size_t len)
{
	char path[64], line[PATH_MAX + 256];
	int found = -1;
	FILE *f;

	if (env.libcuda) {
		snprintf(buf, len, "%s", env.libcuda);
		return 0;
	}

	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	f = fopen(path, "r");
	if (!f)
		return -errno;
	while (fgets(line, sizeof(line), f)) {
		char *lib = strchr(line, '/');

		if (!lib || !strstr(lib, "/libcuda.so"))
			continue;
		lib[strcspn(lib, "\n")] = '\0';
		/* Lewat /proc/PID/root agar tetap benar jika proses berada di kontainer. */
		snprintf(buf, len, "/proc/%d/root%s", pid, lib);
		found = 0;
		break;
	}
	fclose(f);
	return found;
}

static void attach_cuda(struct target *t)
{
	char lib[PATH_MAX + 32];
	int ok = 0, missing = 0;

	if (find_libcuda(t->pid, lib, sizeof(lib)))
		return;	/* libcuda belum dimuat, coba lagi nanti */

	quiet_libbpf = true;
	for (size_t i = 0; i < N_CUDA_SYMS; i++) {
		const struct cuda_sym *s = &cuda_syms[i];
		__u64 cookie = ((__u64)i << 16) | (s->flags << 8) | s->func;
		bool launch = s->ctrl == HT_P2_LAUNCH;
		struct bpf_link *l;

		if (!env.on[s->ctrl])
			continue;
		if (t->nlinks + 2 > MAX_LINKS)
			break;

		LIBBPF_OPTS(bpf_uprobe_opts, uo, .func_name = s->name, .bpf_cookie = cookie);
		l = bpf_program__attach_uprobe_opts(launch ? skel->progs.cuda_launch :
						    skel->progs.cuda_enter,
						    t->pid, lib, 0, &uo);
		if (!l) {
			missing++;
			continue;
		}
		t->links[t->nlinks++] = l;
		ok++;
		if (launch)
			continue;

		LIBBPF_OPTS(bpf_uprobe_opts, ro, .func_name = s->name, .bpf_cookie = cookie,
			    .retprobe = true);
		l = bpf_program__attach_uprobe_opts(skel->progs.cuda_exit, t->pid, lib, 0, &ro);
		if (!l) {
			fprintf(stderr, "[heideltrace] uretprobe %s gagal: %s\n",
				s->name, strerror(errno));
			continue;
		}
		t->links[t->nlinks++] = l;
		ok++;
	}
	quiet_libbpf = false;

	t->cuda_attached = true;
	fprintf(stderr, "[heideltrace] PID %d: %d probe terpasang pada %s (%d simbol tidak ada)\n",
		t->pid, ok, lib, missing);
}

static void scan_targets(void)
{
	char path[64];

	for (int i = 0; i < HT_MAX_TARGETS; i++) {
		struct target *t = &tgts[i];

		if (!t->used)
			continue;
		snprintf(path, sizeof(path), "/proc/%d", t->pid);
		if (access(path, F_OK)) {
			target_remove(t);
			continue;
		}
		if (!t->cuda_attached)
			attach_cuda(t);
	}
}

/* ------------------------------------------------------------------ */
/* Keluaran JSON Lines                                                */
/* ------------------------------------------------------------------ */

static void json_str(const char *s, size_t max)
{
	fputc('"', out);
	for (size_t i = 0; i < max && s[i]; i++) {
		unsigned char c = s[i];

		if (c == '"' || c == '\\')
			fprintf(out, "\\%c", c);
		else if (c < 0x20)
			fprintf(out, "\\u%04x", c);
		else
			fputc(c, out);
	}
	fputc('"', out);
}

static const char *sym_name(__u64 cookie)
{
	__u32 i = COOKIE_SYM(cookie);

	return i < N_CUDA_SYMS ? cuda_syms[i].name : "?";
}

static const char *memcpy_dir(__u32 func)
{
	switch (func) {
	case F_MEMCPY_HTOD: return "htod";
	case F_MEMCPY_DTOH: return "dtoh";
	case F_MEMCPY_DTOD: return "dtod";
	default: return "any";
	}
}

static int handle_event(void *ctx, void *data, size_t len)
{
	const struct ht_event *e = data;
	__u32 func = COOKIE_FUNC(e->cookie);
	bool async = COOKIE_FLAGS(e->cookie) & HT_FLAG_ASYNC;
	struct target *t;
	int pid;

	if (len < sizeof(*e))
		return 0;
	n_events++;

	/* pid = PID di namespace agen, tgid dan tid = PID versi kernel */
	if (e->type == EV_PROC_START)
		pid = e->arg2;
	else
		pid = (t = target_find_k(e->tgid)) ? t->pid : (int)e->tgid;
	fprintf(out, "{\"ts_ns\":%llu,\"pid\":%d,\"tgid\":%u,\"tid\":%u,\"comm\":",
		(unsigned long long)e->ts_ns, pid, e->tgid, e->tid);
	json_str(e->comm, sizeof(e->comm));

	switch (e->type) {
	case EV_STEP:
		fprintf(out, ",\"type\":\"step\",\"fn\":\"%s\",\"wait_ns\":%llu,\"handle\":\"0x%llx\","
			"\"ret\":%d,\"launches\":%llu,\"graphs\":%llu,\"lead_ns\":%llu,"
			"\"gap_sum_ns\":%llu,\"gap_max_ns\":%llu,\"runq_ns\":%llu,"
			"\"offcpu_ns\":%llu,\"preempt\":%u,\"switches\":%u",
			sym_name(e->cookie), (unsigned long long)e->dur_ns,
			(unsigned long long)e->arg, e->ret,
			(unsigned long long)e->step.launches, (unsigned long long)e->step.graphs,
			(unsigned long long)e->step.lead_ns, (unsigned long long)e->step.gap_sum_ns,
			(unsigned long long)e->step.gap_max_ns, (unsigned long long)e->step.runq_ns,
			(unsigned long long)e->step.offcpu_ns, e->step.nr_preempt,
			e->step.nr_switch);
		break;
	case EV_LAUNCH:
		if (func == F_GRAPH_LAUNCH)
			fprintf(out, ",\"type\":\"launch\",\"fn\":\"%s\",\"graph\":\"0x%llx\","
				"\"stream\":\"0x%llx\"", sym_name(e->cookie),
				(unsigned long long)e->arg, (unsigned long long)e->arg2);
		else
			fprintf(out, ",\"type\":\"launch\",\"fn\":\"%s\",\"func\":\"0x%llx\","
				"\"grid\":%llu,\"block\":%llu", sym_name(e->cookie),
				(unsigned long long)e->arg, (unsigned long long)(e->arg2 >> 24),
				(unsigned long long)(e->arg2 & 0xffffff));
		break;
	case EV_MEMCPY:
		fprintf(out, ",\"type\":\"memcpy\",\"fn\":\"%s\",\"dir\":\"%s\",\"async\":%s,"
			"\"bytes\":%llu,\"dur_ns\":%llu,\"stream\":\"0x%llx\",\"ret\":%d",
			sym_name(e->cookie), memcpy_dir(func), async ? "true" : "false",
			(unsigned long long)e->arg, (unsigned long long)e->dur_ns,
			(unsigned long long)e->arg2, e->ret);
		break;
	case EV_ALLOC:
		fprintf(out, ",\"type\":\"alloc\",\"fn\":\"%s\",\"op\":\"%s\",\"bytes\":%llu,"
			"\"ptr\":\"0x%llx\",\"dur_ns\":%llu,\"ret\":%d",
			sym_name(e->cookie), func == F_MEM_ALLOC ? "alloc" : "free",
			(unsigned long long)e->arg, (unsigned long long)e->arg2,
			(unsigned long long)e->dur_ns, e->ret);
		break;
	case EV_NET:
		fprintf(out, ",\"type\":\"net\",\"dir\":\"%s\",\"bytes\":%llu,\"sock\":\"0x%llx\"",
			e->cookie == NET_RECV ? "recv" : e->cookie == NET_SEND ? "send" : "close",
			(unsigned long long)e->arg, (unsigned long long)e->arg2);
		break;
	case EV_PROC_START:
		t = target_find_k(e->arg);
		fprintf(out, ",\"type\":\"proc_start\",\"ppid\":%d",
			t ? t->pid : (int)e->arg);
		target_add(e->arg2, e->tgid);
		break;
	case EV_PROC_EXIT:
		fprintf(out, ",\"type\":\"proc_exit\"");
		t = target_find_k(e->tgid);
		if (t)
			target_remove(t);
		break;
	case EV_IOCTL:
		fprintf(out, ",\"type\":\"ioctl\",\"fd\":%llu,\"cmd\":\"0x%llx\",\"dur_ns\":%llu,"
			"\"ret\":%d", (unsigned long long)e->arg2, (unsigned long long)e->arg,
			(unsigned long long)e->dur_ns, e->ret);
		break;
	default:
		fprintf(out, ",\"type\":\"unknown\",\"raw_type\":%u", e->type);
	}
	fputs("}\n", out);
	return 0;
}

static __u64 read_dropped(void)
{
	int ncpu = libbpf_num_possible_cpus();
	__u64 sum = 0, *vals;
	__u32 zero = 0;

	if (ncpu <= 0)
		return 0;
	vals = calloc(ncpu, sizeof(*vals));
	if (!vals)
		return 0;
	if (!bpf_map_lookup_elem(bpf_map__fd(skel->maps.dropped), &zero, vals))
		for (int i = 0; i < ncpu; i++)
			sum += vals[i];
	free(vals);
	return sum;
}

static void write_meta(void)
{
	struct timespec mono, real;
	long long offset;

	clock_gettime(CLOCK_MONOTONIC, &mono);
	clock_gettime(CLOCK_REALTIME, &real);
	offset = (real.tv_sec - mono.tv_sec) * 1000000000LL + (real.tv_nsec - mono.tv_nsec);

	fprintf(out, "{\"type\":\"meta\",\"version\":\"%s\",\"mono_to_real_ns\":%lld,"
		"\"port\":%d,\"mode\":\"%s\",\"probes\":[", HT_VERSION, offset, env.port,
		env.rinci ? "rinci" : "ringkas");
	for (int i = HT_P1_NET, first = 1; i <= HT_P8_IOCTL; i++) {
		if (!env.on[i])
			continue;
		fprintf(out, "%s\"P%d\"", first ? "" : ",", i);
		first = 0;
	}
	fputs("]}\n", out);
}

/* ------------------------------------------------------------------ */
/* Pemuatan dan pemasangan program eBPF                               */
/* ------------------------------------------------------------------ */

static bool kernel_func_exists(struct btf *vmlinux, const char *name)
{
	return vmlinux && btf__find_by_name_kind(vmlinux, name, BTF_KIND_FUNC) >= 0;
}

static void set_autoload(struct bpf_program *p, bool on)
{
	bpf_program__set_autoload(p, on);
}

/* Program fentry gagal dimuat jika fungsi kernelnya tidak ada atau di-inline. */
static void configure_net(void)
{
	struct btf *vmlinux = btf__load_vmlinux_btf();
	struct {
		struct bpf_program *prog;
		const char *fn;
	} net[] = {
		{ skel->progs.on_tcp_send, "tcp_sendmsg" },
		{ skel->progs.on_tcp_recv, "tcp_cleanup_rbuf" },
		{ skel->progs.on_tcp_close, "tcp_close" },
	};

	for (size_t i = 0; i < sizeof(net) / sizeof(net[0]); i++) {
		bool ok = env.on[HT_P1_NET] && kernel_func_exists(vmlinux, net[i].fn);

		if (env.on[HT_P1_NET] && !ok)
			fprintf(stderr, "[heideltrace] fungsi kernel %s tidak ditemukan, "
				"bagian P1 ini dimatikan\n", net[i].fn);
		set_autoload(net[i].prog, ok);
	}
	btf__free(vmlinux);
}

static int attach_static(struct bpf_link **links, int *n)
{
	struct bpf_program *progs[] = {
		skel->progs.on_switch, skel->progs.on_wakeup,
		skel->progs.on_proc_fork, skel->progs.on_proc_exit,
		skel->progs.on_tcp_send, skel->progs.on_tcp_recv, skel->progs.on_tcp_close,
		skel->progs.on_ioctl_enter, skel->progs.on_ioctl_exit,
	};

	for (size_t i = 0; i < sizeof(progs) / sizeof(progs[0]); i++) {
		struct bpf_link *l;

		if (!bpf_program__autoload(progs[i]))
			continue;
		l = bpf_program__attach(progs[i]);
		if (!l) {
			fprintf(stderr, "[heideltrace] gagal memasang %s: %s\n",
				bpf_program__name(progs[i]), strerror(errno));
			return -1;
		}
		links[(*n)++] = l;
	}
	return 0;
}

static void write_control(void)
{
	int fd = bpf_map__fd(skel->maps.control);

	for (__u32 k = HT_P1_NET; k <= HT_P8_IOCTL; k++) {
		__u32 v = env.on[k];

		bpf_map_update_elem(fd, &k, &v, BPF_ANY);
	}
	__u32 k = HT_MODE, v = env.rinci;

	bpf_map_update_elem(fd, &k, &v, BPF_ANY);
}

int main(int argc, char **argv)
{
	struct bpf_link *static_links[16] = {};
	struct ring_buffer *rb = NULL;
	__u64 last_scan = 0, last_report, deadline = 0;
	int n_static = 0, err;

	if (parse_args(argc, argv))
		return 1;
	if (geteuid() != 0) {
		fprintf(stderr, "heideltrace harus dijalankan sebagai root (sudo).\n");
		return 1;
	}
	libbpf_set_print(libbpf_print_fn);

	skel = heideltrace_bpf__open();
	if (!skel) {
		fprintf(stderr, "Gagal membuka program eBPF\n");
		return 1;
	}
	skel->rodata->net_port = env.port;
	if (!in_init_pidns()) {
		struct stat st;

		if (stat("/proc/self/ns/pid", &st)) {
			fprintf(stderr, "Tidak dapat membaca namespace PID agen\n");
			err = -errno;
			goto cleanup;
		}
		pidns_ino = st.st_ino;
		skel->rodata->pidns_ino = pidns_ino;
	}

	/* Program yang tidak diminta tidak dimuat dan tidak dipasang sama sekali. */
	configure_net();
	set_autoload(skel->progs.on_switch, env.on[HT_P5_SCHED]);
	set_autoload(skel->progs.on_wakeup, env.on[HT_P5_SCHED]);
	set_autoload(skel->progs.on_proc_fork, env.on[HT_P6_PROC]);
	set_autoload(skel->progs.on_ioctl_enter, env.on[HT_P8_IOCTL]);
	set_autoload(skel->progs.on_ioctl_exit, env.on[HT_P8_IOCTL]);

	err = heideltrace_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Program eBPF ditolak oleh kernel: %s\n", strerror(-err));
		goto cleanup;
	}
	if (env.check) {
		fprintf(stderr, "[heideltrace] semua program eBPF lolos verifier, "
			"tidak ada probe yang dipasang\n");
		goto cleanup;
	}
	if (pidns_ino) {
		xlate_link = bpf_program__attach_iter(skel->progs.xlate_pid, NULL);
		if (!xlate_link) {
			err = -errno;
			fprintf(stderr, "Gagal membuat task iterator untuk penerjemahan PID\n");
			goto cleanup;
		}
		fprintf(stderr, "[heideltrace] agen berada di namespace PID non-host, "
			"PID akan diterjemahkan\n");
	}

	out = stdout;
	if (env.output && strcmp(env.output, "-")) {
		out = fopen(env.output, "w");
		if (!out) {
			fprintf(stderr, "Tidak dapat membuka %s: %s\n", env.output, strerror(errno));
			err = -errno;
			goto cleanup;
		}
	}

	write_control();
	for (int i = 0; i < env.npids; i++) {
		char path[64];

		snprintf(path, sizeof(path), "/proc/%d", env.pids[i]);
		if (access(path, F_OK)) {
			fprintf(stderr, "PID %d tidak ditemukan\n", env.pids[i]);
			err = -ESRCH;
			goto cleanup;
		}
		if (!target_add(env.pids[i], 0)) {
			err = -ESRCH;
			goto cleanup;
		}
	}

	if (attach_static(static_links, &n_static)) {
		err = -1;
		goto cleanup;
	}
	/* Proses anak dicari setelah P6 terpasang agar tidak ada yang terlewat. */
	add_descendants();

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		err = -errno;
		fprintf(stderr, "Gagal membuat ring buffer\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGUSR1, sig_handler);

	write_meta();
	last_report = now_ms();
	if (env.duration > 0)
		deadline = now_ms() + env.duration * 1000;
	fprintf(stderr, "[heideltrace] berjalan, tekan Ctrl-C untuk berhenti\n");

	while (!exiting) {
		__u64 t;

		err = ring_buffer__poll(rb, 200);
		if (err == -EINTR)
			err = 0;
		if (err < 0) {
			fprintf(stderr, "Gagal membaca ring buffer: %d\n", err);
			break;
		}

		t = now_ms();
		if (t - last_scan >= SCAN_MS) {
			scan_targets();
			last_scan = t;
		}
		if (toggle_mode) {
			__u32 k = HT_MODE, v;

			toggle_mode = 0;
			env.rinci = !env.rinci;
			v = env.rinci;
			bpf_map_update_elem(bpf_map__fd(skel->maps.control), &k, &v, BPF_ANY);
			fprintf(stderr, "[heideltrace] mode %s\n", env.rinci ? "rinci" : "ringkas");
		}
		if (t - last_report >= REPORT_MS) {
			fflush(out);
			fprintf(stderr, "[heideltrace] kejadian=%llu hilang=%llu\n",
				(unsigned long long)n_events, (unsigned long long)read_dropped());
			last_report = t;
		}
		if (deadline && t >= deadline)
			break;
	}
	err = 0;
	/* Kejadian yang masih tersisa di ring buffer ikut ditulis. */
	ring_buffer__consume(rb);
	fprintf(stderr, "[heideltrace] selesai: kejadian=%llu hilang=%llu\n",
		(unsigned long long)n_events, (unsigned long long)read_dropped());

cleanup:
	ring_buffer__free(rb);
	for (int i = 0; i < HT_MAX_TARGETS; i++)
		if (tgts[i].used)
			target_detach(&tgts[i]);
	for (int i = 0; i < n_static; i++)
		bpf_link__destroy(static_links[i]);
	bpf_link__destroy(xlate_link);
	heideltrace_bpf__destroy(skel);
	if (out && out != stdout)
		fclose(out);
	else if (out)
		fflush(out);
	return err != 0;
}
