package config

import (
	"errors"
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/sonix03/heideltrace/internal/abi"
)

func parse(t *testing.T, args ...string) *Config {
	t.Helper()
	cfg, err := Parse(args, io.Discard)
	if err != nil {
		t.Fatalf("Parse(%q): %v", args, err)
	}
	return cfg
}

func TestDefaults(t *testing.T) {
	cfg := parse(t, "-p", "1234")
	if cfg.Port != 8000 || cfg.Detailed || cfg.Duration != 0 {
		t.Fatalf("unexpected defaults %+v", cfg)
	}
	want := []abi.Probe{abi.P1Net, abi.P2Launch, abi.P3Sync, abi.P4Memcpy, abi.P5Sched, abi.P6Proc}
	if got := cfg.Probes.List(); !reflect.DeepEqual(got, want) {
		t.Fatalf("default probes %v, want %v", got, want)
	}
}

func TestFlags(t *testing.T) {
	cfg := parse(t, "--pid", "10,11", "-p", "12", "-o", "out.jsonl", "--port", "8080",
		"--enable", "P7,8", "--disable", "p1", "--detailed", "-d", "120", "-v")
	if !reflect.DeepEqual(cfg.PIDs, []int{10, 11, 12}) {
		t.Errorf("PIDs %v", cfg.PIDs)
	}
	if cfg.Output != "out.jsonl" || cfg.Port != 8080 || !cfg.Detailed || !cfg.Verbose {
		t.Errorf("unexpected %+v", cfg)
	}
	if cfg.Duration != 120*time.Second {
		t.Errorf("duration %v", cfg.Duration)
	}
	if cfg.Probes.Enabled(abi.P1Net) || !cfg.Probes.Enabled(abi.P7Alloc) || !cfg.Probes.Enabled(abi.P8Ioctl) {
		t.Errorf("probes %v", cfg.Probes.List())
	}
}

func TestDurationForms(t *testing.T) {
	if cfg := parse(t, "-p", "1", "--duration", "2m"); cfg.Duration != 2*time.Minute {
		t.Fatalf("duration %v", cfg.Duration)
	}
}

func TestCheckNeedsNoPID(t *testing.T) {
	if cfg := parse(t, "--check"); !cfg.Check {
		t.Fatal("check not set")
	}
}

func TestErrors(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"-p", "abc"},
		{"-p", "1", "--enable", "P9"},
		{"-p", "1", "--port", "70000"},
		{"-p", "1", "-d", "soon"},
		{"-p", "1", "extra"},
	} {
		if _, err := Parse(args, io.Discard); err == nil {
			t.Errorf("Parse(%q) succeeded", args)
		}
	}
	if _, err := Parse([]string{"-h"}, io.Discard); !errors.Is(err, ErrHelp) {
		t.Errorf("-h returned %v", err)
	}
}
