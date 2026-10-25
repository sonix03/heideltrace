package target

import "testing"

func TestParsePPID(t *testing.T) {
	cases := map[string]int{
		"4021 (python3) S 1 4021 4021 0 -1":            1,
		"4100 (VLLM::EngineCor) R 4021 4021 4021 0 -1": 4021,
		"4200 (weird ) name) S 77 4200 4200 0 -1":      77,
		"garbage": -1,
		"1 (x)":   -1,
	}
	for stat, want := range cases {
		if got := parsePPID(stat); got != want {
			t.Errorf("parsePPID(%q) = %d, want %d", stat, got, want)
		}
	}
}
