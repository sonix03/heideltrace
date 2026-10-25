package abi

// CUDASymbol is one CUDA Driver API function that gets a uprobe.
type CUDASymbol struct {
	Name  string
	Func  Func
	Async bool
	Probe Probe
}

// Cookie returns the BPF cookie for the symbol at the given index of
// CUDASymbols.
func (s CUDASymbol) Cookie(index int) uint64 {
	var flags uint8
	if s.Async {
		flags |= FlagAsync
	}
	return Cookie(index, flags, s.Func)
}

// ReturnProbe reports whether the symbol also needs a uretprobe. Launches
// (P2) only count calls, so an entry probe is enough and much cheaper.
func (s CUDASymbol) ReturnProbe() bool { return s.Probe != P2Launch }

// CUDASymbols lists every function that is probed. A symbol missing from a
// given libcuda.so version is skipped at attach time.
//
// Run scripts/count_cuda_calls.sh on the target machine to confirm which
// variants are actually called before relying on this list.
var CUDASymbols = []CUDASymbol{
	// P2: kernel and graph launches
	{"cuLaunchKernel", FuncLaunchKernel, false, P2Launch},
	{"cuLaunchKernel_ptsz", FuncLaunchKernel, false, P2Launch},
	{"cuLaunchKernelEx", FuncLaunchEx, false, P2Launch},
	{"cuLaunchKernelEx_ptsz", FuncLaunchEx, false, P2Launch},
	{"cuGraphLaunch", FuncGraphLaunch, false, P2Launch},
	{"cuGraphLaunch_ptsz", FuncGraphLaunch, false, P2Launch},
	// P3: synchronization
	{"cuStreamSynchronize", FuncSync, false, P3Sync},
	{"cuStreamSynchronize_ptsz", FuncSync, false, P3Sync},
	{"cuEventSynchronize", FuncSync, false, P3Sync},
	{"cuCtxSynchronize", FuncSync, false, P3Sync},
	// P4: memory copies
	{"cuMemcpyHtoD_v2", FuncMemcpyHtoD, false, P4Memcpy},
	{"cuMemcpyHtoD_v2_ptds", FuncMemcpyHtoD, false, P4Memcpy},
	{"cuMemcpyHtoDAsync_v2", FuncMemcpyHtoD, true, P4Memcpy},
	{"cuMemcpyHtoDAsync_v2_ptsz", FuncMemcpyHtoD, true, P4Memcpy},
	{"cuMemcpyDtoH_v2", FuncMemcpyDtoH, false, P4Memcpy},
	{"cuMemcpyDtoH_v2_ptds", FuncMemcpyDtoH, false, P4Memcpy},
	{"cuMemcpyDtoHAsync_v2", FuncMemcpyDtoH, true, P4Memcpy},
	{"cuMemcpyDtoHAsync_v2_ptsz", FuncMemcpyDtoH, true, P4Memcpy},
	{"cuMemcpyDtoD_v2", FuncMemcpyDtoD, false, P4Memcpy},
	{"cuMemcpyDtoD_v2_ptds", FuncMemcpyDtoD, false, P4Memcpy},
	{"cuMemcpyDtoDAsync_v2", FuncMemcpyDtoD, true, P4Memcpy},
	{"cuMemcpyDtoDAsync_v2_ptsz", FuncMemcpyDtoD, true, P4Memcpy},
	{"cuMemcpy", FuncMemcpyAny, false, P4Memcpy},
	{"cuMemcpy_ptds", FuncMemcpyAny, false, P4Memcpy},
	{"cuMemcpyAsync", FuncMemcpyAny, true, P4Memcpy},
	{"cuMemcpyAsync_ptsz", FuncMemcpyAny, true, P4Memcpy},
	// P7: GPU memory allocation (optional)
	{"cuMemAlloc_v2", FuncMemAlloc, false, P7Alloc},
	{"cuMemAllocAsync", FuncMemAlloc, true, P7Alloc},
	{"cuMemAllocAsync_ptsz", FuncMemAlloc, true, P7Alloc},
	{"cuMemFree_v2", FuncMemFree, false, P7Alloc},
	{"cuMemFreeAsync", FuncMemFree, true, P7Alloc},
	{"cuMemFreeAsync_ptsz", FuncMemFree, true, P7Alloc},
}

// CUDASymbolName returns the function name encoded in a cookie, or "?".
func CUDASymbolName(cookie uint64) string {
	if i := CookieSym(cookie); i < len(CUDASymbols) {
		return CUDASymbols[i].Name
	}
	return "?"
}
