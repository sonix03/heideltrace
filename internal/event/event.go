// Package event defines the typed events the agent emits.
//
// Decode turns a raw ring buffer record into one of these types. Every type
// marshals to one JSON Lines record, and the same types are meant to be read
// back by later stages (correlator, analyzer). All timestamps are
// CLOCK_MONOTONIC nanoseconds; Meta.MonoToRealNs converts them to wall time.
package event

import (
	"fmt"
	"strconv"
	"strings"
)

// Event is implemented by every event type.
type Event interface {
	Base() *Header
}

// Header is common to every event. PID is the process ID as seen by the
// agent; TGID and TID are kernel IDs. They differ only when the agent runs
// in a non-initial PID namespace.
type Header struct {
	TsNs uint64 `json:"ts_ns"`
	PID  int    `json:"pid"`
	TGID uint32 `json:"tgid"`
	TID  uint32 `json:"tid"`
	Comm string `json:"comm"`
	Type string `json:"type"`
}

func (h *Header) Base() *Header { return h }

// Event type names, the "type" field of each record.
const (
	TypeMeta      = "meta"
	TypeStep      = "step"
	TypeLaunch    = "launch"
	TypeMemcpy    = "memcpy"
	TypeAlloc     = "alloc"
	TypeNet       = "net"
	TypeProcStart = "proc_start"
	TypeProcExit  = "proc_exit"
	TypeIoctl     = "ioctl"
	TypeUnknown   = "unknown"
)

// Step summarizes the launcher thread between two step boundaries (P2, P3,
// P5). A boundary is the return of a synchronization call or of a
// synchronous GPU -> host copy.
type Step struct {
	Header
	Fn       string `json:"fn"`      // function that ended the step
	WaitNs   uint64 `json:"wait_ns"` // time the CPU waited for the GPU
	Handle   Hex    `json:"handle"`  // stream or event handle
	Ret      int32  `json:"ret"`
	Launches uint64 `json:"launches"`
	Graphs   uint64 `json:"graphs"`
	LeadNs   uint64 `json:"lead_ns"` // previous boundary -> first launch
	GapSumNs uint64 `json:"gap_sum_ns"`
	GapMaxNs uint64 `json:"gap_max_ns"`
	RunqNs   uint64 `json:"runq_ns"`   // runnable, waiting for a CPU
	OffcpuNs uint64 `json:"offcpu_ns"` // sleeping or stopped
	Preempt  uint32 `json:"preempt"`
	Switches uint32 `json:"switches"`
}

// KernelLaunch is one cuLaunchKernel(Ex) call, detailed mode only (P2).
type KernelLaunch struct {
	Header
	Fn    string `json:"fn"`
	Func  Hex    `json:"func"`  // CUfunction handle
	Grid  uint64 `json:"grid"`  // blocks in the grid
	Block uint64 `json:"block"` // threads per block (blockZ not read)
}

// GraphLaunch is one cuGraphLaunch call, detailed mode only (P2).
type GraphLaunch struct {
	Header
	Fn     string `json:"fn"`
	Graph  Hex    `json:"graph"`
	Stream Hex    `json:"stream"`
}

// Memcpy is one memory copy call (P4). For Async variants DurNs is the CPU
// call time, not the transfer time on the GPU.
type Memcpy struct {
	Header
	Fn     string `json:"fn"`
	Dir    string `json:"dir"` // htod, dtoh, dtod or any
	Async  bool   `json:"async"`
	Bytes  uint64 `json:"bytes"`
	DurNs  uint64 `json:"dur_ns"`
	Stream Hex    `json:"stream"`
	Ret    int32  `json:"ret"`
}

// Alloc is one GPU memory allocation or free (P7).
type Alloc struct {
	Header
	Fn    string `json:"fn"`
	Op    string `json:"op"` // alloc or free
	Bytes uint64 `json:"bytes"`
	Ptr   Hex    `json:"ptr"`
	DurNs uint64 `json:"dur_ns"`
	Ret   int32  `json:"ret"`
}

// Net is one TCP receive, send or close on the API server port (P1).
type Net struct {
	Header
	Dir   string `json:"dir"` // recv, send or close
	Bytes uint64 `json:"bytes"`
	Sock  Hex    `json:"sock"` // identifies the connection
}

// ProcStart is a new child process of a target (P6). The header carries
// the child; PPID is the parent as seen by the agent.
type ProcStart struct {
	Header
	PPID int `json:"ppid"`

	ParentTGID uint32 `json:"-"` // parent kernel tgid
	ChildPID   int    `json:"-"` // child PID in the agent's namespace
}

// ProcExit is a target process that exited (P6).
type ProcExit struct {
	Header
}

// Ioctl is one ioctl call of a target (P8).
type Ioctl struct {
	Header
	FD    uint64 `json:"fd"`
	Cmd   Hex    `json:"cmd"`
	DurNs uint64 `json:"dur_ns"`
	Ret   int32  `json:"ret"`
}

// Unknown is a record with a type this version does not know.
type Unknown struct {
	Header
	RawType uint32 `json:"raw_type"`
}

// Meta is the first record of every output file.
type Meta struct {
	Type         string   `json:"type"`
	Version      string   `json:"version"`
	MonoToRealNs int64    `json:"mono_to_real_ns"`
	Port         int      `json:"port"`
	Mode         string   `json:"mode"`
	Probes       []string `json:"probes"`
}

// Hex is a handle or address printed as a "0x..." string.
type Hex uint64

func (h Hex) String() string { return fmt.Sprintf("0x%x", uint64(h)) }

func (h Hex) MarshalJSON() ([]byte, error) {
	return []byte(`"` + h.String() + `"`), nil
}

func (h *Hex) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	v, err := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 64)
	if err != nil {
		return fmt.Errorf("invalid hex value %s: %w", b, err)
	}
	*h = Hex(v)
	return nil
}
