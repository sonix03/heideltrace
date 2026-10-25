//go:build linux

// Package target keeps track of the processes being observed.
//
// The tracker owns the filter map, follows child processes reported by P6,
// attaches CUDA uprobes once a process has loaded libcuda.so, and rewrites
// event PIDs into the agent's PID namespace. It is not safe for concurrent
// use; the agent calls it from a single goroutine.
package target

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/sonix03/heideltrace/internal/abi"
	"github.com/sonix03/heideltrace/internal/config"
	"github.com/sonix03/heideltrace/internal/event"
	"github.com/sonix03/heideltrace/internal/loader"
	"github.com/sonix03/heideltrace/internal/probes"
)

// Logger is satisfied by *log.Logger.
type Logger interface {
	Printf(format string, args ...any)
}

// Options configures a Tracker.
type Options struct {
	Probes     config.ProbeSet
	LibCUDA    string // libcuda.so path override, "" = find it in /proc/PID/maps
	PIDNSInode uint64 // see PIDNamespaceInode
	Verbose    bool
	Log        Logger
}

// Target is one observed process.
type Target struct {
	PID  int    // PID in the agent's namespace (for /proc and uprobes)
	KPID uint32 // kernel PID (key of the filter map)
	Comm string

	cuda     probes.Links
	cudaDone bool // CUDA attach was attempted
}

// Tracker manages the set of targets.
type Tracker struct {
	objs   *loader.Objects
	opts   Options
	byPID  map[int]*Target
	byKPID map[uint32]*Target
	xlate  *link.Iter
}

// New creates a tracker. Close it to detach every CUDA probe.
func New(objs *loader.Objects, opts Options) (*Tracker, error) {
	t := &Tracker{
		objs:   objs,
		opts:   opts,
		byPID:  map[int]*Target{},
		byKPID: map[uint32]*Target{},
	}
	if opts.PIDNSInode != 0 {
		it, err := link.AttachIter(link.IterOptions{Program: objs.XlatePID})
		if err != nil {
			return nil, fmt.Errorf("create task iterator for PID translation: %w", err)
		}
		t.xlate = it
		opts.Log.Printf("agent runs in a non-host PID namespace, PIDs will be translated")
	}
	return t, nil
}

// Len returns the number of targets.
func (t *Tracker) Len() int { return len(t.byPID) }

// Add starts observing pid. kpid is its kernel PID, or 0 to look it up.
func (t *Tracker) Add(pid int, kpid uint32) (*Target, error) {
	if tg := t.byPID[pid]; tg != nil {
		return tg, nil
	}
	if len(t.byPID) >= abi.MaxTargets {
		return nil, fmt.Errorf("limit of %d targets reached, PID %d ignored", abi.MaxTargets, pid)
	}
	if kpid == 0 {
		var err error
		if kpid, err = t.kernelPID(pid); err != nil {
			return nil, fmt.Errorf("translate PID %d to a kernel PID: %w", pid, err)
		}
	}
	if err := t.objs.Targets.Put(kpid, uint32(1)); err != nil {
		return nil, fmt.Errorf("add PID %d to the filter map: %w", pid, err)
	}

	tg := &Target{PID: pid, KPID: kpid, Comm: readComm(pid)}
	t.byPID[pid] = tg
	t.byKPID[kpid] = tg
	if kpid != uint32(pid) {
		t.opts.Log.Printf("watching PID %d (%s), kernel PID %d", pid, tg.Comm, kpid)
	} else {
		t.opts.Log.Printf("watching PID %d (%s)", pid, tg.Comm)
	}
	return tg, nil
}

func (t *Tracker) remove(tg *Target) {
	tg.cuda.Close()
	if err := t.objs.Targets.Delete(tg.KPID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.opts.Log.Printf("remove PID %d from the filter map: %v", tg.PID, err)
	}
	delete(t.byPID, tg.PID)
	delete(t.byKPID, tg.KPID)
	t.opts.Log.Printf("PID %d exited, probes detached", tg.PID)
}

// AddDescendants adds every existing descendant of the current targets.
// Call it after P6 is attached so that no new child is missed.
func (t *Tracker) AddDescendants() {
	for added := true; added; {
		added = false
		for _, pid := range listPIDs() {
			if t.byPID[pid] != nil || t.byPID[readPPID(pid)] == nil {
				continue
			}
			if _, err := t.Add(pid, 0); err != nil {
				t.opts.Log.Printf("%v", err)
				continue
			}
			added = true
		}
	}
}

// Scan drops targets that are gone and attaches CUDA probes to targets that
// have loaded libcuda.so since the last scan.
func (t *Tracker) Scan() {
	for _, tg := range t.byPID {
		if !exists(tg.PID) {
			t.remove(tg)
			continue
		}
		if !tg.cudaDone {
			t.attachCUDA(tg)
		}
	}
}

func (t *Tracker) attachCUDA(tg *Target) {
	lib := t.opts.LibCUDA
	if lib == "" {
		var ok bool
		var err error
		if lib, ok, err = probes.FindLibCUDA(tg.PID); err != nil || !ok {
			return // not loaded yet, try again on the next scan
		}
	}
	tg.cudaDone = true

	res, err := probes.AttachCUDA(t.objs, tg.PID, lib, t.opts.Probes)
	if err != nil {
		t.opts.Log.Printf("PID %d: %v", tg.PID, err)
		return
	}
	tg.cuda = res.Links
	t.opts.Log.Printf("PID %d: %d probes attached to %s (%d symbols missing)",
		tg.PID, res.Attached, lib, len(res.Missing))
	if t.opts.Verbose && len(res.Missing) > 0 {
		t.opts.Log.Printf("PID %d: missing symbols: %v", tg.PID, res.Missing)
	}
	for _, err := range res.Failed {
		t.opts.Log.Printf("PID %d: %v", tg.PID, err)
	}
}

// Observe updates the targets from an event and rewrites its PIDs into the
// agent's namespace. Call it for every event before writing it out.
func (t *Tracker) Observe(ev event.Event) {
	h := ev.Base()
	switch e := ev.(type) {
	case *event.ProcStart:
		h.PID = e.ChildPID
		if parent := t.byKPID[e.ParentTGID]; parent != nil {
			e.PPID = parent.PID
		}
		if e.ChildPID > 0 {
			if _, err := t.Add(e.ChildPID, h.TGID); err != nil {
				t.opts.Log.Printf("%v", err)
			}
		}
	case *event.ProcExit:
		if tg := t.byKPID[h.TGID]; tg != nil {
			h.PID = tg.PID
			t.remove(tg)
		}
	default:
		if tg := t.byKPID[h.TGID]; tg != nil {
			h.PID = tg.PID
		}
	}
}

// Close detaches every CUDA probe and the PID iterator.
func (t *Tracker) Close() {
	for _, tg := range t.byPID {
		tg.cuda.Close()
	}
	if t.xlate != nil {
		t.xlate.Close()
	}
}
