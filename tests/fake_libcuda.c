// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Pustaka tiruan bernama libcuda.so.1 dengan nama fungsi CUDA Driver API.
 * Dipakai untuk menguji heideltrace tanpa GPU. Fungsi sinkronisasi dan
 * penyalinan hanya tidur sebentar agar durasinya terukur.
 */
#include <stddef.h>
#include <time.h>

typedef int CUresult;
typedef unsigned long long CUdeviceptr;

static void sleep_us(long us)
{
	struct timespec ts = { 0, us * 1000 };

	nanosleep(&ts, NULL);
}

CUresult cuLaunchKernel(void *f, unsigned int gx, unsigned int gy, unsigned int gz,
			unsigned int bx, unsigned int by, unsigned int bz,
			unsigned int shmem, void *stream, void **params, void **extra)
{
	(void)f; (void)gx; (void)gy; (void)gz; (void)bx; (void)by; (void)bz;
	(void)shmem; (void)stream; (void)params; (void)extra;
	return 0;
}

CUresult cuGraphLaunch(void *exec, void *stream)
{
	(void)exec; (void)stream;
	return 0;
}

CUresult cuStreamSynchronize(void *stream)
{
	(void)stream;
	sleep_us(2000);
	return 0;
}

CUresult cuMemcpyHtoDAsync_v2(CUdeviceptr dst, const void *src, size_t n, void *stream)
{
	(void)dst; (void)src; (void)n; (void)stream;
	return 0;
}

CUresult cuMemcpyDtoH_v2(void *dst, CUdeviceptr src, size_t n)
{
	(void)dst; (void)src; (void)n;
	sleep_us(100);
	return 0;
}

CUresult cuMemAlloc_v2(CUdeviceptr *ptr, size_t n)
{
	(void)n;
	*ptr = 0xdead0000ULL;
	return 0;
}

CUresult cuMemFree_v2(CUdeviceptr ptr)
{
	(void)ptr;
	return 0;
}
