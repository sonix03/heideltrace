// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Aplikasi tiruan yang meniru pola satu langkah inferensi:
 * 20 peluncuran kernel, 1 peluncuran graf, salinan host -> GPU,
 * sinkronisasi, lalu salinan GPU -> host. Proses ini juga membuat satu
 * proses anak untuk menguji P6.
 */
#include <stddef.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

typedef int CUresult;
typedef unsigned long long CUdeviceptr;

CUresult cuLaunchKernel(void *f, unsigned int gx, unsigned int gy, unsigned int gz,
			unsigned int bx, unsigned int by, unsigned int bz,
			unsigned int shmem, void *stream, void **params, void **extra);
CUresult cuGraphLaunch(void *exec, void *stream);
CUresult cuStreamSynchronize(void *stream);
CUresult cuMemcpyHtoDAsync_v2(CUdeviceptr dst, const void *src, size_t n, void *stream);
CUresult cuMemcpyDtoH_v2(void *dst, CUdeviceptr src, size_t n);
CUresult cuMemAlloc_v2(CUdeviceptr *ptr, size_t n);
CUresult cuMemFree_v2(CUdeviceptr ptr);

static char buf[8192];

static void run_steps(int steps)
{
	CUdeviceptr d;

	cuMemAlloc_v2(&d, 1 << 20);
	for (int s = 0; s < steps; s++) {
		for (int k = 0; k < 20; k++) {
			cuLaunchKernel((void *)0x1000, 4, 2, 1, 128, 2, 1, 0, NULL, NULL, NULL);
			usleep(50);
		}
		cuGraphLaunch((void *)0x2000, NULL);
		cuMemcpyHtoDAsync_v2(d, buf, 4096, NULL);
		cuStreamSynchronize(NULL);
		cuMemcpyDtoH_v2(buf, d, sizeof(buf));
	}
	cuMemFree_v2(d);
}

int main(void)
{
	pid_t child;

	/* Beri waktu agar heideltrace selesai memasang probe. */
	sleep(2);

	child = fork();
	if (child == 0) {
		sleep(2);	/* menunggu probe dipasang pada proses anak */
		run_steps(3);
		return 0;
	}

	run_steps(10);
	waitpid(child, NULL, 0);
	printf("fake_app selesai\n");
	return 0;
}
