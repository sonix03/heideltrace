# Development guide

## Toolchain

| Task | Needs |
|---|---|
| `make`, `make test` | Go ≥ 1.24 |
| `make generate` (after changing `bpf/`) | plus `clang` and `llvm-strip` ≥ 11 |
| `make headers` (refresh `bpf/headers/`) | plus `curl` and `bpftool` |
| Running the agent or the smoke tests | Linux ≥ 5.15 with BTF, root |

On Ubuntu: `sudo apt install golang clang llvm`. On Windows, build and unit test with Go directly
(`go test ./...`, `GOOS=linux go build ./cmd/heideltrace`) and use WSL 2 for anything that needs root.

## Typical workflow

```bash
make generate        # only if bpf/ changed
make vet test        # vet for linux and run the unit tests
make                 # build/heideltrace
sudo ./tests/smoke.sh && sudo ./tests/net_smoke.sh
```

`make check` also fails when `bpf/` was changed without regenerating `internal/bpf/`.
Commit the regenerated `internal/bpf/*_bpfel.{go,o}` files together with the C change.

## Adding a CUDA function to an existing probe

Only [`internal/abi/cuda.go`](../internal/abi/cuda.go) changes. Add a row to `CUDASymbols`
with the symbol name, its kind, whether it is asynchronous, and its probe. Append new rows at
the end: the index of a symbol is part of its cookie, so reordering changes the meaning of old
output files.

## Adding a new observation point

Example: a P9 that observes something in the kernel.

1. **ABI.** Add `HT_P9_...` to `enum ht_ctrl` and, if it emits events, a new `EV_...` type
   (and any struct) in [`bpf/lib/common.h`](../bpf/lib/common.h). Mirror both in
   [`internal/abi/abi.go`](../internal/abi/abi.go). Bump `HT_CTRL_MAX` and move `HT_MODE` if needed,
   and update `ControlMode`, `Probes`, and `Probe.Valid`.
2. **Program.** Create `bpf/<name>.bpf.c`. Include `helpers.h`, check `is_target()` and
   `enabled(HT_P9_...)` first, and use `ev_new()` / `bpf_ringbuf_submit()` to emit events.
   Never use helpers that write to user memory or change control flow.
3. **Build.** Add a `//go:generate` line for the new object in
   [`internal/bpf/gen.go`](../internal/bpf/gen.go) and a `<Name>Spec()` function in
   [`internal/bpf/specs.go`](../internal/bpf/specs.go). Run `make generate`.
4. **Load.** In [`internal/loader/loader.go`](../internal/loader/loader.go), load the module when
   the probe is enabled and store its programs in `Objects`.
5. **Attach.** Add the programs to `AttachKernel` in
   [`internal/probes/kernel.go`](../internal/probes/kernel.go), or write a per-target attach
   function next to `AttachCUDA` for uprobes.
6. **Decode.** Add a typed event to [`internal/event/event.go`](../internal/event/event.go)
   and a case in `Decode`, with a test in `event_test.go`.
7. **Options and docs.** Decide the default in `config.DefaultProbes`, and add the probe to the
   tables in `README.md` and `docs/architecture.md`.

## Adding a processing stage (correlator, analyzer)

Create a package under `internal/` that consumes `event.Event` values. Keep it free of eBPF
imports so it can be unit tested on any OS with recorded events, then call it from the loop in
[`internal/agent/agent.go`](../internal/agent/agent.go) between `tracker.Observe` and `out.Write`.
Offline tools (for example a report generator that reads a `.jsonl` file) belong in their own
`cmd/<tool>/` directory.

## Conventions

- Code, comments, and docs are in English.
- Kernel C follows the Linux kernel style (tabs, `/* */` comments). Go code is `gofmt`-ed.
- Files that import `github.com/cilium/ebpf` carry `//go:build linux`. Pure logic (parsing,
  decoding) stays untagged so its tests run everywhere.
- Commit messages follow Conventional Commits (`feat(bpf): ...`, `fix(loader): ...`, `docs: ...`).
