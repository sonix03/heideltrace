package event_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/sonix03/heideltrace/internal/abi"
	"github.com/sonix03/heideltrace/internal/event"
	"github.com/sonix03/heideltrace/internal/output"
)

func cookieOf(name string) uint64 {
	for i, s := range abi.CUDASymbols {
		if s.Name == name {
			return s.Cookie(i)
		}
	}
	panic("unknown symbol " + name)
}

func raw(typ abi.EventType) abi.RawEvent {
	r := abi.RawEvent{TsNs: 81234567890, Tgid: 4021, Tid: 4021, Type: uint32(typ)}
	copy(r.Comm[:], "VLLM::EngineCor")
	return r
}

// The JSON field order is part of the output format, so compare whole lines.
func encode(t *testing.T, ev any) string {
	t.Helper()
	var buf bytes.Buffer
	w := output.New(&buf)
	if err := w.Write(ev); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestDecodeStep(t *testing.T) {
	r := raw(abi.EvStep)
	r.Cookie = cookieOf("cuStreamSynchronize")
	r.DurNs = 18234011
	r.Step = abi.RawStep{Launches: 412, Graphs: 3, LeadNs: 152331, GapSumNs: 2210554,
		GapMaxNs: 95012, NrSwitch: 1}

	want := `{"ts_ns":81234567890,"pid":4021,"tgid":4021,"tid":4021,"comm":"VLLM::EngineCor",` +
		`"type":"step","fn":"cuStreamSynchronize","wait_ns":18234011,"handle":"0x0","ret":0,` +
		`"launches":412,"graphs":3,"lead_ns":152331,"gap_sum_ns":2210554,"gap_max_ns":95012,` +
		`"runq_ns":0,"offcpu_ns":0,"preempt":0,"switches":1}` + "\n"
	if got := encode(t, event.Decode(&r)); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestDecodeLaunch(t *testing.T) {
	r := raw(abi.EvLaunch)
	r.Cookie = cookieOf("cuLaunchKernel")
	r.Arg = 0x1000
	r.Arg2 = 8<<24 | 256

	ev, ok := event.Decode(&r).(*event.KernelLaunch)
	if !ok {
		t.Fatalf("decoded %T, want *event.KernelLaunch", event.Decode(&r))
	}
	if ev.Grid != 8 || ev.Block != 256 || ev.Func != 0x1000 || ev.Type != event.TypeLaunch {
		t.Fatalf("unexpected launch %+v", ev)
	}

	r.Cookie = cookieOf("cuGraphLaunch")
	if _, ok := event.Decode(&r).(*event.GraphLaunch); !ok {
		t.Fatalf("graph launch decoded as %T", event.Decode(&r))
	}
}

func TestDecodeMemcpy(t *testing.T) {
	r := raw(abi.EvMemcpy)
	r.Cookie = cookieOf("cuMemcpyHtoDAsync_v2")
	r.Arg = 4096
	r.Arg2 = 0xbeef

	ev := event.Decode(&r).(*event.Memcpy)
	if ev.Dir != "htod" || !ev.Async || ev.Bytes != 4096 || ev.Stream != 0xbeef {
		t.Fatalf("unexpected memcpy %+v", ev)
	}
}

func TestDecodeNet(t *testing.T) {
	for dir, want := range map[abi.NetDir]string{abi.NetRecv: "recv", abi.NetSend: "send", abi.NetClose: "close"} {
		r := raw(abi.EvNet)
		r.Cookie = uint64(dir)
		r.Arg = 512
		if ev := event.Decode(&r).(*event.Net); ev.Dir != want || ev.Bytes != 512 {
			t.Errorf("dir %d: got %+v", dir, ev)
		}
	}
}

func TestDecodeProcStart(t *testing.T) {
	r := raw(abi.EvProcStart)
	r.Tgid, r.Arg, r.Arg2 = 5000, 4021, 77

	ev := event.Decode(&r).(*event.ProcStart)
	if ev.ParentTGID != 4021 || ev.ChildPID != 77 {
		t.Fatalf("unexpected proc_start %+v", ev)
	}
	// Internal fields stay out of the output.
	var m map[string]any
	if err := json.Unmarshal([]byte(encode(t, ev)), &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["ParentTGID"]; ok {
		t.Fatal("ParentTGID leaked into JSON")
	}
}

func TestDecodeUnknown(t *testing.T) {
	r := raw(99)
	if ev := event.Decode(&r).(*event.Unknown); ev.RawType != 99 {
		t.Fatalf("unexpected %+v", ev)
	}
}

func TestHexRoundTrip(t *testing.T) {
	var h event.Hex
	if err := json.Unmarshal([]byte(`"0xdead0000"`), &h); err != nil || h != 0xdead0000 {
		t.Fatalf("got %v, %v", h, err)
	}
}
