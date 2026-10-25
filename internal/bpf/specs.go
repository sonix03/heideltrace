//go:build linux

package bpf

import "github.com/cilium/ebpf"

// Each function returns a fresh CollectionSpec that the caller may modify
// before loading it.

// CUDASpec holds P2, P3, P4 and P7 (bpf/cuda.bpf.c).
func CUDASpec() (*ebpf.CollectionSpec, error) { return loadCuda() }

// SchedSpec holds P5 (bpf/sched.bpf.c).
func SchedSpec() (*ebpf.CollectionSpec, error) { return loadSched() }

// ProcSpec holds P6 and the PID namespace iterator (bpf/proc.bpf.c).
func ProcSpec() (*ebpf.CollectionSpec, error) { return loadProc() }

// NetSpec holds P1 (bpf/net.bpf.c).
func NetSpec() (*ebpf.CollectionSpec, error) { return loadNet() }

// IoctlSpec holds P8 (bpf/ioctl.bpf.c).
func IoctlSpec() (*ebpf.CollectionSpec, error) { return loadIoctl() }
