// Package abi mirrors bpf/lib/common.h: the constants and the event layout
// shared by the eBPF programs and user space.
//
// Change this file together with bpf/lib/common.h. TestEventLayout in
// internal/bpf compares RawEvent with the layout bpf2go generates from the C
// struct and fails if the two drift apart.
package abi

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Map size limits, see HT_MAX_* in common.h.
const (
	MaxTargets   = 64
	MaxThreads   = 16384
	RingbufBytes = 4 * 1024 * 1024
)

// Probe is an observation point P1-P8. Its value is the index of its switch
// in the control map (enum ht_ctrl).
type Probe uint32

const (
	P1Net    Probe = 1 // TCP traffic of the API server
	P2Launch Probe = 2 // kernel and graph launches
	P3Sync   Probe = 3 // synchronization
	P4Memcpy Probe = 4 // host <-> GPU memory copies
	P5Sched  Probe = 5 // thread scheduling
	P6Proc   Probe = 6 // process creation and exit
	P7Alloc  Probe = 7 // GPU memory allocation (optional)
	P8Ioctl  Probe = 8 // ioctl to the driver (optional)
)

// ControlMode is the control map index that selects the mode:
// 0 = summary, 1 = detailed (every kernel launch is sent).
const ControlMode uint32 = 9

// Probes lists every probe in order.
var Probes = []Probe{P1Net, P2Launch, P3Sync, P4Memcpy, P5Sched, P6Proc, P7Alloc, P8Ioctl}

func (p Probe) String() string { return fmt.Sprintf("P%d", uint32(p)) }

// Valid reports whether p is one of P1-P8.
func (p Probe) Valid() bool { return p >= P1Net && p <= P8Ioctl }

// Func is the kind of CUDA function carried in the uprobe cookie (enum ht_func).
type Func uint8

const (
	FuncLaunchKernel Func = 1
	FuncLaunchEx     Func = 2
	FuncGraphLaunch  Func = 3
	FuncSync         Func = 4
	FuncMemcpyHtoD   Func = 5
	FuncMemcpyDtoH   Func = 6
	FuncMemcpyDtoD   Func = 7
	FuncMemcpyAny    Func = 8
	FuncMemAlloc     Func = 9
	FuncMemFree      Func = 10
)

// FlagAsync marks the asynchronous variant of a CUDA function (HT_FLAG_ASYNC).
const FlagAsync uint8 = 0x1

// Cookie packs a symbol index, flags and function kind:
// (index << 16) | (flags << 8) | kind.
func Cookie(index int, flags uint8, f Func) uint64 {
	return uint64(index)<<16 | uint64(flags)<<8 | uint64(f)
}

// CookieFunc, CookieFlags and CookieSym unpack a cookie.
func CookieFunc(c uint64) Func   { return Func(c & 0xff) }
func CookieFlags(c uint64) uint8 { return uint8(c >> 8) }
func CookieSym(c uint64) int     { return int(c >> 16) }

// EventType is enum ht_event_type.
type EventType uint32

const (
	EvStep      EventType = 1
	EvLaunch    EventType = 2
	EvMemcpy    EventType = 3
	EvAlloc     EventType = 4
	EvNet       EventType = 5
	EvProcStart EventType = 6
	EvProcExit  EventType = 7
	EvIoctl     EventType = 8
)

// NetDir is enum ht_net_dir, carried in RawEvent.Cookie for EvNet.
type NetDir uint64

const (
	NetRecv  NetDir = 1
	NetSend  NetDir = 2
	NetClose NetDir = 3
)

// RawStep mirrors struct ht_step.
type RawStep struct {
	Launches  uint64
	Graphs    uint64
	LeadNs    uint64
	GapSumNs  uint64
	GapMaxNs  uint64
	RunqNs    uint64
	OffcpuNs  uint64
	NrPreempt uint32
	NrSwitch  uint32
}

// RawEvent mirrors struct ht_event, one record of the events ring buffer.
type RawEvent struct {
	TsNs   uint64
	DurNs  uint64
	Arg    uint64
	Arg2   uint64
	Cookie uint64
	Tgid   uint32
	Tid    uint32
	Type   uint32
	Ret    int32
	Step   RawStep
	Comm   [16]byte
}

// XlateReq mirrors struct xlate_req, the value of the xlate map.
type XlateReq struct {
	Want uint32 // PID in the agent's namespace
	Got  uint32 // kernel PID, 0 if not found
}

// RawEventSize is sizeof(struct ht_event).
var RawEventSize = binary.Size(RawEvent{})

// DecodeRaw parses one ring buffer record. The kernel writes it in host
// byte order.
func DecodeRaw(b []byte) (RawEvent, error) {
	var e RawEvent
	if len(b) < RawEventSize {
		return e, fmt.Errorf("short event: %d bytes, want %d", len(b), RawEventSize)
	}
	err := binary.Read(bytes.NewReader(b[:RawEventSize]), binary.NativeEndian, &e)
	return e, err
}

// CommString returns the NUL-terminated task name.
func (e *RawEvent) CommString() string {
	if i := bytes.IndexByte(e.Comm[:], 0); i >= 0 {
		return string(e.Comm[:i])
	}
	return string(e.Comm[:])
}
