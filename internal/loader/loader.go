//go:build linux

// Package loader loads the eBPF objects into the kernel.
//
// Every bpf/*.bpf.c file is a separate object (a "module"). The maps from
// bpf/lib/maps.h are created once here and shared with every module through
// MapReplacements. A module or program that is not needed is never loaded,
// so disabled probes cost nothing in the kernel.
package loader

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	"github.com/sonix03/heideltrace/internal/abi"
	"github.com/sonix03/heideltrace/internal/bpf"
	"github.com/sonix03/heideltrace/internal/config"
)

// sharedMaps must match the maps declared in bpf/lib/maps.h.
var sharedMaps = []string{"targets", "control", "events", "dropped", "inflight", "tstats"}

// Options selects what gets loaded.
type Options struct {
	Probes     config.ProbeSet
	Port       uint16 // P1 port filter, 0 = all
	PIDNSInode uint64 // agent PID namespace, 0 = initial namespace
	// Warn receives non-fatal problems, such as a missing kernel function.
	Warn func(format string, args ...any)
}

// Objects holds every loaded map and program. A program that was not
// loaded is nil.
type Objects struct {
	Targets *ebpf.Map
	Control *ebpf.Map
	Events  *ebpf.Map
	Dropped *ebpf.Map
	Xlate   *ebpf.Map

	// P2-P4, P7. Attached per target by internal/probes.
	CUDALaunch, CUDAEnter, CUDAExit *ebpf.Program

	// P5
	SchedSwitch, SchedWakeup *ebpf.Program
	// P6 and the PID namespace iterator
	ProcFork, ProcExit, XlatePID *ebpf.Program
	// P1
	TCPSend, TCPRecv, TCPClose *ebpf.Program
	// P8
	IoctlEnter, IoctlExit *ebpf.Program

	shared map[string]*ebpf.Map
	colls  []*ebpf.Collection
}

// Load loads every module that opts needs. The caller must Close the result.
func Load(opts Options) (*Objects, error) {
	if opts.Warn == nil {
		opts.Warn = func(string, ...any) {}
	}
	o := &Objects{shared: map[string]*ebpf.Map{}}
	if err := o.load(opts); err != nil {
		o.Close()
		return nil, err
	}
	return o, nil
}

func (o *Objects) load(opts Options) error {
	cuda, err := bpf.CUDASpec()
	if err != nil {
		return err
	}
	for _, name := range sharedMaps {
		m, err := ebpf.NewMap(cuda.Maps[name])
		if err != nil {
			return fmt.Errorf("create map %s: %w", name, err)
		}
		o.shared[name] = m
	}
	o.Targets, o.Control = o.shared["targets"], o.shared["control"]
	o.Events, o.Dropped = o.shared["events"], o.shared["dropped"]

	// P2-P4 and P7 share one module; which symbols get probes is decided
	// at attach time.
	c, err := o.loadModule("cuda", cuda, nil)
	if err != nil {
		return err
	}
	o.CUDALaunch, o.CUDAEnter, o.CUDAExit =
		c.Programs["cuda_launch"], c.Programs["cuda_enter"], c.Programs["cuda_exit"]

	// The exit handler is always loaded so the maps never keep processes
	// that are gone.
	proc, err := bpf.ProcSpec()
	if err != nil {
		return err
	}
	if err := proc.Variables["pidns_ino"].Set(opts.PIDNSInode); err != nil {
		return err
	}
	drop := []string{}
	if !opts.Probes.Enabled(abi.P6Proc) {
		drop = append(drop, "on_proc_fork")
	}
	if opts.PIDNSInode == 0 {
		drop = append(drop, "xlate_pid")
	}
	if c, err = o.loadModule("proc", proc, drop); err != nil {
		return err
	}
	o.ProcFork, o.ProcExit, o.XlatePID =
		c.Programs["on_proc_fork"], c.Programs["on_proc_exit"], c.Programs["xlate_pid"]
	o.Xlate = c.Maps["xlate"]

	if opts.Probes.Enabled(abi.P5Sched) {
		spec, err := bpf.SchedSpec()
		if err != nil {
			return err
		}
		if c, err = o.loadModule("sched", spec, nil); err != nil {
			return err
		}
		o.SchedSwitch, o.SchedWakeup = c.Programs["on_switch"], c.Programs["on_wakeup"]
	}

	if opts.Probes.Enabled(abi.P1Net) {
		if err := o.loadNet(opts); err != nil {
			return err
		}
	}

	if opts.Probes.Enabled(abi.P8Ioctl) {
		spec, err := bpf.IoctlSpec()
		if err != nil {
			return err
		}
		if c, err = o.loadModule("ioctl", spec, nil); err != nil {
			return err
		}
		o.IoctlEnter, o.IoctlExit = c.Programs["on_ioctl_enter"], c.Programs["on_ioctl_exit"]
	}
	return nil
}

// loadNet loads P1. An fentry program fails to load when its kernel
// function does not exist or is inlined, so such programs are skipped.
func (o *Objects) loadNet(opts Options) error {
	spec, err := bpf.NetSpec()
	if err != nil {
		return err
	}
	if err := spec.Variables["net_port"].Set(opts.Port); err != nil {
		return err
	}
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		return fmt.Errorf("load kernel BTF: %w", err)
	}
	hooks := map[string]string{
		"on_tcp_send":  "tcp_sendmsg",
		"on_tcp_recv":  "tcp_cleanup_rbuf",
		"on_tcp_close": "tcp_close",
	}
	var drop []string
	for prog, fn := range hooks {
		var f *btf.Func
		if err := kernel.TypeByName(fn, &f); err != nil {
			opts.Warn("kernel function %s not found, this part of P1 is disabled", fn)
			drop = append(drop, prog)
		}
	}
	c, err := o.loadModule("net", spec, drop)
	if err != nil {
		return err
	}
	o.TCPSend, o.TCPRecv, o.TCPClose =
		c.Programs["on_tcp_send"], c.Programs["on_tcp_recv"], c.Programs["on_tcp_close"]
	return nil
}

// loadModule loads spec without the programs in drop, reusing the shared maps.
func (o *Objects) loadModule(name string, spec *ebpf.CollectionSpec, drop []string) (*ebpf.Collection, error) {
	for _, p := range drop {
		delete(spec.Programs, p)
	}
	repl := map[string]*ebpf.Map{}
	for n, m := range o.shared {
		if _, ok := spec.Maps[n]; ok {
			repl[n] = m
		}
	}
	c, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: repl})
	if err != nil {
		return nil, fmt.Errorf("load %s programs: %w", name, err)
	}
	o.colls = append(o.colls, c)
	return c, nil
}

// SetControl switches a control map entry (a probe index or abi.ControlMode).
func (o *Objects) SetControl(index uint32, on bool) error {
	var v uint32
	if on {
		v = 1
	}
	return o.Control.Put(index, v)
}

// WriteControl writes the initial state of every probe and the mode.
func (o *Objects) WriteControl(probes config.ProbeSet, detailed bool) error {
	for _, p := range abi.Probes {
		if err := o.SetControl(uint32(p), probes.Enabled(p)); err != nil {
			return fmt.Errorf("write control map: %w", err)
		}
	}
	return o.SetControl(abi.ControlMode, detailed)
}

// DroppedEvents returns how many events did not fit in the ring buffer.
func (o *Objects) DroppedEvents() (uint64, error) {
	var perCPU []uint64
	if err := o.Dropped.Lookup(uint32(0), &perCPU); err != nil {
		return 0, err
	}
	var sum uint64
	for _, v := range perCPU {
		sum += v
	}
	return sum, nil
}

// Close unloads everything. Attached links must be closed first.
func (o *Objects) Close() {
	for _, c := range o.colls {
		c.Close()
	}
	for _, m := range o.shared {
		m.Close()
	}
}

// VerifierLog returns the full verifier output contained in err, if any.
func VerifierLog(err error) (string, bool) {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		return fmt.Sprintf("%+v", ve), true
	}
	return "", false
}
