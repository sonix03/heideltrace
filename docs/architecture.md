# Architecture

This document maps the design in Chapter III of the proposal to the code.

## Components

The proposal describes six agent components. Each one lives in its own package:

| Component (proposal) | Package | Status |
|---|---|---|
| Loader | [`internal/loader`](../internal/loader), [`internal/probes`](../internal/probes), [`internal/target`](../internal/target) | done |
| eBPF programs | [`bpf/`](../bpf) | done (P1–P8) |
| Collector | [`internal/collector`](../internal/collector) | done |
| Correlator | `internal/correlator` | planned |
| Analyzer | `internal/analyzer` | planned |
| Exporter | [`internal/output`](../internal/output) | raw events only; diagnosis reports planned |

The loader from the proposal is split in three: `loader` loads the programs into the kernel,
`probes` attaches them to their hooks, and `target` decides which processes are observed.

## Main loop

[`internal/agent`](../internal/agent/agent.go) wires everything together:

```
config.Parse
   │
loader.Load ──────────────► kernel: programs + shared maps
   │
target.New / Add ─────────► filter map (targets)
probes.AttachKernel ──────► P1, P5, P6, P8 hooks
   │
loop (one goroutine):
   collector.Next ──► event.Event ──► tracker.Observe ──► output.Write
   every 500 ms: tracker.Scan   (drop dead targets, attach CUDA uprobes)
   every 10 s:   flush output, print event and drop counters
   SIGUSR1:      toggle summary/detailed mode in the control map
```

Everything after the collector runs in one goroutine, so the tracker needs no locks.
The correlator and analyzer will consume the same `event.Event` values, either in this loop
or offline from a JSON Lines file (the types in `internal/event` unmarshal as well as marshal).

## Kernel / user space contract

Three files describe the contract and must change together:

| Kernel side | User side | What |
|---|---|---|
| [`bpf/lib/common.h`](../bpf/lib/common.h) | [`internal/abi/abi.go`](../internal/abi/abi.go) | constants, `struct ht_event`, `struct ht_step` |
| `COOKIE_*` macros in `common.h` | [`internal/abi/cuda.go`](../internal/abi/cuda.go) | CUDA symbol table and cookie encoding |
| [`bpf/lib/maps.h`](../bpf/lib/maps.h) | `sharedMaps` in [`internal/loader`](../internal/loader/loader.go) | names of the shared maps |

`TestEventLayout` in `internal/bpf` compares `abi.RawEvent` with the layout bpf2go
derives from the compiled object, so a struct that drifts fails the tests.

## One object per probe group

Each `bpf/*.bpf.c` file is compiled into its own object:

| Object | Probes | Loaded when |
|---|---|---|
| `cuda` | P2, P3, P4, P7 | always (attach is per symbol and per PID) |
| `proc` | P6, PID iterator | always (`on_proc_exit` keeps the maps clean) |
| `sched` | P5 | P5 enabled |
| `net` | P1 | P1 enabled; each fentry only if its kernel function exists |
| `ioctl` | P8 | P8 enabled |

Every object includes `bpf/lib/maps.h` and so declares its own copy of the shared maps.
`loader.Load` creates a single instance of each shared map and passes it to every object with
`ebpf.CollectionOptions.MapReplacements`. All programs therefore read and write the same
filter, control, per-thread, and ring buffer maps, while a disabled probe group is never loaded.

## Why Go and cilium/ebpf

The proposal states that the eBPF programs are written in C with libbpf for lower overhead than BCC.
That still holds: the programs are C compiled with CO-RE and BTF, and they run in the kernel
exactly as before. Only the user-space loader moved from libbpf (C) to cilium/ebpf (Go):

- The result is one static binary with the objects embedded, with no libelf or libbpf on the server.
- Correlation, statistics, and reports are much easier to write and test in Go than in C.
- The layout follows common Go eBPF projects (Cilium, Tetragon, the cilium/ebpf examples).

The per-event cost in the kernel does not depend on the loader library. The user-space cost
(decoding events in Go) is part of the overhead measurement planned in the evaluation.
