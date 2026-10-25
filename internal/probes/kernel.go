//go:build linux

// Package probes attaches the loaded eBPF programs to their hooks.
//
// Kernel hooks (P1, P5, P6, P8) are attached once for the whole run. CUDA
// uprobes (P2, P3, P4, P7) are attached per target PID, so other processes
// that use libcuda.so never pay the uprobe cost.
package probes

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/sonix03/heideltrace/internal/loader"
)

// Links is a set of attached hooks.
type Links []link.Link

// Close detaches every hook.
func (l Links) Close() {
	for _, k := range l {
		k.Close()
	}
}

// AttachKernel attaches every kernel hook that was loaded.
func AttachKernel(o *loader.Objects) (Links, error) {
	// BTF-enabled tracepoints (tp_btf) and fentry programs know their own
	// attach point; classic tracepoints need the group and name.
	tracing := []*ebpf.Program{
		o.SchedSwitch, o.SchedWakeup,
		o.ProcFork, o.ProcExit,
		o.TCPSend, o.TCPRecv, o.TCPClose,
	}
	tracepoints := []struct {
		prog        *ebpf.Program
		group, name string
	}{
		{o.IoctlEnter, "syscalls", "sys_enter_ioctl"},
		{o.IoctlExit, "syscalls", "sys_exit_ioctl"},
	}

	var links Links
	for _, p := range tracing {
		if p == nil {
			continue
		}
		l, err := link.AttachTracing(link.TracingOptions{Program: p})
		if err != nil {
			links.Close()
			return nil, fmt.Errorf("attach %s: %w", progName(p), err)
		}
		links = append(links, l)
	}
	for _, tp := range tracepoints {
		if tp.prog == nil {
			continue
		}
		l, err := link.Tracepoint(tp.group, tp.name, tp.prog, nil)
		if err != nil {
			links.Close()
			return nil, fmt.Errorf("attach tracepoint %s/%s: %w", tp.group, tp.name, err)
		}
		links = append(links, l)
	}
	return links, nil
}

func progName(p *ebpf.Program) string {
	if info, err := p.Info(); err == nil {
		return info.Name
	}
	return p.String()
}
