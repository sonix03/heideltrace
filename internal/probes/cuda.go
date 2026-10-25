//go:build linux

package probes

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf/link"

	"github.com/sonix03/heideltrace/internal/abi"
	"github.com/sonix03/heideltrace/internal/config"
	"github.com/sonix03/heideltrace/internal/loader"
)

// CUDAResult reports what AttachCUDA did.
type CUDAResult struct {
	Links    Links
	Attached int      // probes attached (entry and return counted separately)
	Missing  []string // symbols this libcuda.so does not export
	Failed   []error  // symbols that exist but could not be probed
}

// AttachCUDA attaches the CUDA uprobes of every enabled probe to one PID.
// lib is the libcuda.so path as seen by the agent (see FindLibCUDA). A
// symbol that cannot be probed is reported in the result and skipped; only
// failing to open the library is an error.
func AttachCUDA(o *loader.Objects, pid int, lib string, probes config.ProbeSet) (*CUDAResult, error) {
	ex, err := link.OpenExecutable(lib)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", lib, err)
	}

	res := &CUDAResult{}
	for i, sym := range abi.CUDASymbols {
		if !probes.Enabled(sym.Probe) {
			continue
		}
		opts := &link.UprobeOptions{PID: pid, Cookie: sym.Cookie(i)}

		entry := o.CUDAEnter
		if !sym.ReturnProbe() {
			entry = o.CUDALaunch
		}
		l, err := ex.Uprobe(sym.Name, entry, opts)
		if errors.Is(err, link.ErrNoSymbol) {
			res.Missing = append(res.Missing, sym.Name)
			continue
		}
		if err != nil {
			res.Failed = append(res.Failed, fmt.Errorf("uprobe %s: %w", sym.Name, err))
			continue
		}
		res.Links = append(res.Links, l)
		res.Attached++

		if !sym.ReturnProbe() {
			continue
		}
		l, err = ex.Uretprobe(sym.Name, o.CUDAExit, opts)
		if err != nil {
			res.Failed = append(res.Failed, fmt.Errorf("uretprobe %s: %w", sym.Name, err))
			continue
		}
		res.Links = append(res.Links, l)
		res.Attached++
	}
	return res, nil
}
