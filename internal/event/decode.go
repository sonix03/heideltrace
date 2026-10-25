package event

import "github.com/sonix03/heideltrace/internal/abi"

// Decode converts a raw ring buffer record into a typed event. Header.PID
// starts as the kernel tgid; the target tracker rewrites it when the agent
// runs in another PID namespace.
//
// How RawEvent.Arg and Arg2 are used per type:
//
//	step:       arg = stream/event handle
//	launch:     arg = CUfunction, arg2 = grid << 24 | block
//	            (graph: arg = CUgraphExec, arg2 = stream)
//	memcpy:     arg = bytes, arg2 = stream (async only)
//	alloc:      arg = bytes, arg2 = device pointer
//	net:        arg = bytes, arg2 = struct sock address, cookie = direction
//	proc_start: arg = parent tgid, arg2 = child PID in the agent's namespace
//	ioctl:      arg = cmd, arg2 = fd
func Decode(r *abi.RawEvent) Event {
	h := Header{
		TsNs: r.TsNs,
		PID:  int(r.Tgid),
		TGID: r.Tgid,
		TID:  r.Tid,
		Comm: r.CommString(),
	}
	fn := abi.CUDASymbolName(r.Cookie)
	kind := abi.CookieFunc(r.Cookie)
	async := abi.CookieFlags(r.Cookie)&abi.FlagAsync != 0

	switch abi.EventType(r.Type) {
	case abi.EvStep:
		h.Type = TypeStep
		s := r.Step
		return &Step{
			Header: h, Fn: fn, WaitNs: r.DurNs, Handle: Hex(r.Arg), Ret: r.Ret,
			Launches: s.Launches, Graphs: s.Graphs, LeadNs: s.LeadNs,
			GapSumNs: s.GapSumNs, GapMaxNs: s.GapMaxNs,
			RunqNs: s.RunqNs, OffcpuNs: s.OffcpuNs,
			Preempt: s.NrPreempt, Switches: s.NrSwitch,
		}
	case abi.EvLaunch:
		h.Type = TypeLaunch
		if kind == abi.FuncGraphLaunch {
			return &GraphLaunch{Header: h, Fn: fn, Graph: Hex(r.Arg), Stream: Hex(r.Arg2)}
		}
		return &KernelLaunch{
			Header: h, Fn: fn, Func: Hex(r.Arg),
			Grid: r.Arg2 >> 24, Block: r.Arg2 & 0xffffff,
		}
	case abi.EvMemcpy:
		h.Type = TypeMemcpy
		return &Memcpy{
			Header: h, Fn: fn, Dir: memcpyDir(kind), Async: async,
			Bytes: r.Arg, DurNs: r.DurNs, Stream: Hex(r.Arg2), Ret: r.Ret,
		}
	case abi.EvAlloc:
		h.Type = TypeAlloc
		op := "free"
		if kind == abi.FuncMemAlloc {
			op = "alloc"
		}
		return &Alloc{Header: h, Fn: fn, Op: op, Bytes: r.Arg, Ptr: Hex(r.Arg2), DurNs: r.DurNs, Ret: r.Ret}
	case abi.EvNet:
		h.Type = TypeNet
		return &Net{Header: h, Dir: netDir(abi.NetDir(r.Cookie)), Bytes: r.Arg, Sock: Hex(r.Arg2)}
	case abi.EvProcStart:
		h.Type = TypeProcStart
		return &ProcStart{Header: h, PPID: int(r.Arg), ParentTGID: uint32(r.Arg), ChildPID: int(r.Arg2)}
	case abi.EvProcExit:
		h.Type = TypeProcExit
		return &ProcExit{Header: h}
	case abi.EvIoctl:
		h.Type = TypeIoctl
		return &Ioctl{Header: h, FD: r.Arg2, Cmd: Hex(r.Arg), DurNs: r.DurNs, Ret: r.Ret}
	default:
		h.Type = TypeUnknown
		return &Unknown{Header: h, RawType: r.Type}
	}
}

func memcpyDir(f abi.Func) string {
	switch f {
	case abi.FuncMemcpyHtoD:
		return "htod"
	case abi.FuncMemcpyDtoH:
		return "dtoh"
	case abi.FuncMemcpyDtoD:
		return "dtod"
	default:
		return "any"
	}
}

func netDir(d abi.NetDir) string {
	switch d {
	case abi.NetRecv:
		return "recv"
	case abi.NetSend:
		return "send"
	default:
		return "close"
	}
}
