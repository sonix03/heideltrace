# heideltrace

An eBPF *observability* agent for LLM inference servers (vLLM) on a single NVIDIA T4 GPU.
It observes the interaction between CPU and GPU **without modifying the inference engine, the CUDA libraries, or the GPU driver**,
so that TTFT and TPOT spikes can be attributed to the CPU side or the GPU side.

This repository implements the undergraduate thesis *Observability Kinerja GPU Berbasis eBPF pada Server Inferensi Large Language Model*
(Ahmad Wicaksono, 13523121, Informatics, Institut Teknologi Bandung).
Probe codes P1–P8 and the diagnosis categories follow Chapter III of the proposal.

> **Status:** early prototype. The eBPF programs compile and the Go unit tests pass, but the agent has not yet been run against vLLM on a T4 server.
> Confirm the list of CUDA functions with `scripts/count_cuda_calls.sh` first (see [Usage](#usage)).

## Architecture

```
bpf/                    eBPF programs (C, CO-RE)
  lib/                  shared by every program: common.h (ABI), maps.h, helpers.h
  cuda.bpf.c            P2 P3 P4 P7  uprobes on libcuda.so
  sched.bpf.c           P5           sched_switch, sched_wakeup
  proc.bpf.c            P6           fork/exit, PID namespace iterator
  net.bpf.c             P1           TCP send/receive of the API server
  ioctl.bpf.c           P8           ioctl syscalls
  headers/              vendored libbpf headers and vmlinux.h
cmd/heideltrace/        entry point
internal/
  abi/                  Go mirror of bpf/lib/common.h and the CUDA symbol table
  bpf/                  bpf2go output (compiled objects, committed)
  loader/               loads the objects, shares the maps between them
  probes/               attaches kernel hooks and per-PID CUDA uprobes
  target/               tracks target processes, children, PID namespaces
  collector/            reads and decodes the ring buffer
  event/                typed events (the JSON Lines schema)
  output/               JSON Lines writer
  agent/                wires the components together and runs the main loop
  config/               command line options
scripts/                machine check and CUDA call counting
tests/                  smoke tests without a GPU
docs/                   architecture and development guide
```

Data flows from the kernel to user space:

```
libcuda.so / scheduler / TCP ──► eBPF programs ──► ring buffer ──► collector ──► target tracker ──► output (JSON Lines)
                                     │  ▲
                        per-thread summary + control maps
```

User space is written in Go with [cilium/ebpf](https://github.com/cilium/ebpf). The eBPF programs are compiled with
`bpf2go` and embedded in the binary, so the result is **one static binary** with no runtime dependencies.
See [docs/architecture.md](docs/architecture.md) for how the packages map to the components in the proposal,
and [docs/development.md](docs/development.md) for how to extend the agent.

## Observation points

| Code | Probe type | Target | What it records | Default |
|---|---|---|---|---|
| **P1** | `fentry` | `tcp_sendmsg`, `tcp_cleanup_rbuf`, `tcp_close` of the target, on the API server port (default 8000) | When a request arrives, when every token is sent, when the connection closes. Used to compute TTFT and TPOT on the server side | on |
| **P2** | `uprobe` | `cuLaunchKernel`, `cuLaunchKernelEx`, `cuGraphLaunch` (and `_ptsz` variants) in `libcuda.so` | Number of kernel and graph launches, gaps between launches, longest gap | on |
| **P3** | `uprobe` + `uretprobe` | `cuStreamSynchronize(_ptsz)`, `cuEventSynchronize`, `cuCtxSynchronize` | How long the CPU waits for the GPU; step boundaries | on |
| **P4** | `uprobe` + `uretprobe` | `cuMemcpy{HtoD,DtoH,DtoD}[Async]_v2`, `cuMemcpy[Async]` (and `_ptds`/`_ptsz` variants) | Direction, size, and call duration of memory copies | on |
| **P5** | `tp_btf` | `sched_switch`, `sched_wakeup` | Time runnable but waiting for a CPU (`runq_ns`), time off the CPU (`offcpu_ns`), preemptions | on |
| **P6** | `tp_btf` | `sched_process_fork`, `sched_process_exit` | New child processes (for example EngineCore) are followed automatically; probes are detached when a process exits | on |
| **P7** | `uprobe` + `uretprobe` | `cuMemAlloc_v2`, `cuMemAllocAsync(_ptsz)`, `cuMemFree_v2`, `cuMemFreeAsync(_ptsz)` | Time, size, and address of GPU memory allocations | off (`--enable P7`) |
| **P8** | `tracepoint` | `syscalls:sys_enter_ioctl`, `sys_exit_ioctl` | Rough driver activity (fd, command, duration) | off (`--enable P8`) |

What is **not** observed:
- Start and end of kernel execution on the GPU, because the agent does not use CUPTI. GPU time is inferred from the wait in P3.
- State inside the GPU (warp divergence, memory access).
- Request and token contents. P1 only records sizes and times.
- Network delay after `send()` returns on the server.

### Step boundaries and summary mode

Kernel launches (P2) can happen thousands of times per inference step, and one in-kernel uprobe costs about 2.56 µs.
P2 is therefore **not sent one by one** to user space.
P2 and P5 data are summarized in a per-thread map and sent as one `step` event at every **step boundary**:
the return of a synchronization call (P3) or of a blocking `cuMemcpyDtoH` (P4).

| Mode | Behavior | How |
|---|---|---|
| summary (default) | P2 is only counted in the kernel and reported inside `step` events | — |
| detailed | every kernel launch is also sent as a `launch` event | `--detailed`, or send `SIGUSR1` to heideltrace while it runs |

## Safety

The agent is designed to be safe on a shared server:

1. **Read-only.** No eBPF program uses `bpf_probe_write_user`, `bpf_override_return`, or `bpf_send_signal`. The agent cannot change memory, return values, or control flow of the observed process.
2. **Checked by the kernel verifier.** Every program is verified before it runs, so it cannot crash the kernel. `--check` runs this check without attaching anything.
3. **Target processes only.** Uprobes are attached to the target PID and its children, not system-wide. Other processes that use `libcuda.so` (for example other users) **do not pay** the uprobe cost. Every program also returns immediately for events from other processes.
4. **Bounded memory.** Every map has a size limit (64 processes, 16,384 threads, 4 MB ring buffer). Per-thread maps are LRU so they cannot fill up. Events that do not fit are counted as `dropped` and never block the application.
5. **Detached automatically.** All probes are tied to file descriptors owned by heideltrace. The kernel removes them when heideltrace exits, including on `kill -9` or a crash.
6. **No network egress.** Results are only written to a local file or stdout.
7. **Unused probes are not loaded.** The P5, P1, and P8 programs are not loaded into the kernel at all unless enabled.
8. **No vLLM restart needed.** The agent attaches to and detaches from a running vLLM.

Things to keep in mind:
- The agent needs **root**. Ask the lab server administrator before running it.
- P2 adds about 2.56 µs per kernel launch **in the target process**. Measure the overhead before using it outside of experiments.
- P1 and P5 hook kernel functions used by the whole system. Other processes only pay a very short PID check, but that cost exists.
- `scripts/count_cuda_calls.sh` attaches uprobes to **every** `cu*` function. Only run it when nobody else is using the test server.
- This repository does **not** contain the fault injector. It will be a separate tool and only run with the administrator's permission.

## Requirements

| Component | Requirement |
|---|---|
| Linux kernel | ≥ 5.15 (BPF cookies on uprobes), with `CONFIG_DEBUG_INFO_BTF=y` |
| Architecture | x86_64 |
| NVIDIA driver | any driver that ships `libcuda.so` |
| To build | Go ≥ 1.24 |
| To change `bpf/` | additionally `clang` and `llvm-strip` (≥ 11) |
| Optional | `bpftrace` for `scripts/count_cuda_calls.sh` |

## Build

```bash
git clone https://github.com/sonix03/heideltrace.git
cd heideltrace
make            # -> build/heideltrace, a static binary
make test       # unit tests, run on any OS
```

The compiled eBPF objects are committed under `internal/bpf/`, so building only needs Go.
The binary can be built on a laptop (even on Windows with `GOOS=linux`) and copied to the GPU server as is.
Thanks to CO-RE, the same binary runs on other kernel versions that have BTF.

After editing anything under `bpf/`, regenerate the objects with `make generate` (needs clang) and commit the result.

## Usage

```bash
# 1. Check the machine (read-only, changes nothing)
./scripts/check_env.sh            # or: ./scripts/check_env.sh <vLLM PID>

# 2. Find the PIDs. The vLLM parent process for P1, the GPU process for P2-P4.
pgrep -f "vllm serve"
nvidia-smi --query-compute-apps=pid,process_name --format=csv

# 3. Confirm which CUDA functions are really called (once, while sending load)
sudo ./scripts/count_cuda_calls.sh <GPU PID> 30

# 4. Run the verifier without attaching any probe
sudo ./build/heideltrace --check

# 5. Run the agent. The parent PID is enough; child processes are followed.
sudo ./build/heideltrace -p <vLLM PID> -o result.jsonl -d 120
```

More examples:

```bash
sudo ./build/heideltrace -p 1234 --disable P1             # no network observation
sudo ./build/heideltrace -p 1234 --enable P7,P8           # add the optional probes
sudo ./build/heideltrace -p 1234 --port 8080 --detailed   # other port, detailed mode
sudo kill -USR1 $(pgrep heideltrace)                      # switch mode while running
```

If vLLM runs in a container, pass the PID as seen by heideltrace (usually the host PID). `libcuda.so` is found through `/proc/<PID>/root`, so it is still detected.
If it is not, pass its location with `--libcuda`.

eBPF programs always see kernel PIDs. If heideltrace itself runs in another PID namespace (inside a container or WSL), the given PIDs are translated automatically with a task iterator.
In the output, `pid` is the PID as seen by heideltrace, while `tgid` and `tid` are kernel PIDs.

Probes can also be switched off at runtime by writing to the control map (index = probe number, index 9 = mode):

```bash
sudo bpftool map update name control key 2 0 0 0 value 0 0 0 0   # turn P2 off
```

## Tests without a GPU

Two smoke tests run on any Linux machine without a GPU:

```bash
make
sudo ./tests/smoke.sh       # P2-P4, P6, P7 with a fake libcuda.so
sudo ./tests/net_smoke.sh   # P1 with a local Python HTTP server (needs python3 and curl)
```

`smoke.sh` builds a fake `libcuda.so.1` (`tests/fake_libcuda.c`) and an application that mimics 13 inference steps (`tests/fake_app.c`).
It checks the number of `step`, `memcpy`, and `alloc` events and that the child process is followed.

## Output format

Every line is one JSON object. All `ts_ns` values are `CLOCK_MONOTONIC`.
The first line (`meta`) holds `mono_to_real_ns` to convert them to wall-clock time, so they can be matched with the load generator's records.
The Go types in [`internal/event`](internal/event/event.go) define the schema.

| `type` | Source | Main fields |
|---|---|---|
| `meta` | — | version, port, mode, enabled probes |
| *(all)* | — | `ts_ns`, `pid`, `tgid`, `tid`, `comm` |
| `step` | P3/P4 (+P2, P5) | `fn`, `wait_ns` (time waiting for the GPU), `launches`, `graphs`, `lead_ns`, `gap_sum_ns`, `gap_max_ns`, `runq_ns`, `offcpu_ns`, `preempt`, `switches` |
| `launch` | P2, detailed mode | `fn`, `func` (CUfunction handle), `grid`, `block`, or `graph` and `stream` for CUDA Graphs |
| `memcpy` | P4 | `fn`, `dir` (`htod`/`dtoh`/`dtod`/`any`), `async`, `bytes`, `dur_ns`, `stream` |
| `alloc` | P7 | `op` (`alloc`/`free`), `bytes`, `ptr`, `dur_ns` |
| `net` | P1 | `dir` (`recv`/`send`/`close`), `bytes`, `sock` (connection id) |
| `proc_start` / `proc_exit` | P6 | `ppid` |
| `ioctl` | P8 | `fd`, `cmd`, `dur_ns` |

A sample `step` event:

```json
{"ts_ns":81234567890,"pid":4021,"tgid":4021,"tid":4021,"comm":"VLLM::EngineCor","type":"step","fn":"cuStreamSynchronize","wait_ns":18234011,"handle":"0x0","ret":0,"launches":412,"graphs":3,"lead_ns":152331,"gap_sum_ns":2210554,"gap_max_ns":95012,"runq_ns":0,"offcpu_ns":0,"preempt":0,"switches":1}
```

Quick reading, following the diagnosis rules in the proposal:
- `gap_*` grows, `wait_ns` small, `runq_ns` large → CPU contention from other processes (category 1).
- `gap_*` grows, `wait_ns` small, `offcpu_ns` large, `runq_ns` small → other host-side stall (category 2).
- `gap_*` normal, `wait_ns` far above the baseline → GPU contention or slowdown (category 3).

## Known limitations

- **`memcpy` duration for `Async` variants** is the CPU call time, not the transfer time on the GPU.
- **Kernels inside a CUDA Graph** are not visible individually. `graphs` counts graph launches, not their kernels.
- **Block size of `cuLaunchKernel`** is only `blockX × blockY`, because `blockZ` is on the stack.
- **Kernel names** are not available yet. Detailed mode only records the `CUfunction` handle.
- **P1 assumes one connection = one streaming request.** Receives are detected via `tcp_cleanup_rbuf`. If that function is missing in the kernel, that part is disabled with a warning.
- **`offcpu_ns` includes sleeping inside a blocking synchronization**, so the correlator must separate off-CPU time inside and outside P3 calls.
- **A full restart of vLLM is not followed.** Child processes are followed, but a new `vllm serve` with a new PID needs a new run (NF2 in the proposal is not complete yet).
- **Aliased symbols:** if two symbol names in `libcuda.so` point to the same address, a launch may be counted twice. Check with `count_cuda_calls.sh`.
- **libcudart internal calls:** libcudart may call the driver through internal function pointers. If `count_cuda_calls.sh` shows that an expected function is never called, adjust `CUDASymbols` in [`internal/abi/cuda.go`](internal/abi/cuda.go).

## Roadmap

- [ ] Run `count_cuda_calls.sh` against vLLM on the T4 server and adjust the symbol list.
- [ ] Correlator: build step and request timelines from `step` and `net` events.
- [ ] Analyzer: anomaly detection (99th percentile, TTFT regression) and the six cause categories.
- [ ] Load generator (Poisson arrivals, streaming) that records client-side TTFT and TPOT.
- [ ] Fault injector G1–G6, test environment only.
- [ ] Overhead measurement per group of probes.
- [ ] Re-attach automatically when vLLM is restarted (NF2).

## License

The eBPF programs are licensed `Dual BSD/GPL` because some eBPF helpers are only available to GPL programs.
The vendored libbpf headers in `bpf/headers/` are `LGPL-2.1 OR BSD-2-Clause`.
The license of the rest of the repository has not been decided yet.
