package abi

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestRawEventSize(t *testing.T) {
	if RawEventSize != 136 {
		t.Fatalf("sizeof(struct ht_event) = %d, want 136", RawEventSize)
	}
}

func TestCookieRoundTrip(t *testing.T) {
	c := Cookie(17, FlagAsync, FuncMemcpyDtoH)
	if CookieSym(c) != 17 || CookieFlags(c) != FlagAsync || CookieFunc(c) != FuncMemcpyDtoH {
		t.Fatalf("cookie %#x decoded to sym=%d flags=%d func=%d",
			c, CookieSym(c), CookieFlags(c), CookieFunc(c))
	}
}

func TestCUDASymbolCookies(t *testing.T) {
	for i, s := range CUDASymbols {
		c := s.Cookie(i)
		if got := CUDASymbolName(c); got != s.Name {
			t.Errorf("symbol %d: name %q, want %q", i, got, s.Name)
		}
		if async := CookieFlags(c)&FlagAsync != 0; async != s.Async {
			t.Errorf("%s: async flag %v, want %v", s.Name, async, s.Async)
		}
		if !s.Probe.Valid() {
			t.Errorf("%s: invalid probe %v", s.Name, s.Probe)
		}
	}
	if got := CUDASymbolName(Cookie(len(CUDASymbols), 0, 0)); got != "?" {
		t.Errorf("out-of-range cookie named %q", got)
	}
}

func TestDecodeRaw(t *testing.T) {
	in := RawEvent{TsNs: 42, Tgid: 7, Tid: 8, Type: uint32(EvStep), Ret: -1}
	in.Step.Launches = 20
	copy(in.Comm[:], "VLLM::EngineCor")

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.NativeEndian, in); err != nil {
		t.Fatal(err)
	}
	out, err := DecodeRaw(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("decoded %+v, want %+v", out, in)
	}
	if out.CommString() != "VLLM::EngineCor" {
		t.Fatalf("comm %q", out.CommString())
	}
	if _, err := DecodeRaw(buf.Bytes()[:10]); err == nil {
		t.Fatal("short record accepted")
	}
}
