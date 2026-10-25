package probes

import (
	"strings"
	"testing"
)

func TestLibCUDAFromMaps(t *testing.T) {
	maps := `55d0c0a00000-55d0c0a01000 r--p 00000000 08:01 1234 /usr/bin/python3.12
7f1a20000000-7f1a20400000 r--p 00000000 08:01 5678 /usr/lib/x86_64-linux-gnu/libcudart.so.12
7f1a30000000-7f1a30800000 r-xp 00000000 08:01 9012 /usr/lib/x86_64-linux-gnu/libcuda.so.550.54.15
7ffd1c000000-7ffd1c021000 rw-p 00000000 00:00 0 [stack]
`
	got := libCUDAFromMaps(strings.NewReader(maps))
	if want := "/usr/lib/x86_64-linux-gnu/libcuda.so.550.54.15"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got := libCUDAFromMaps(strings.NewReader("7ffd 0 [vdso]\n")); got != "" {
		t.Fatalf("found %q in a listing without libcuda", got)
	}
}
