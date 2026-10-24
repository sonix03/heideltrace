# heideltrace

Agen *observability* berbasis eBPF untuk server inferensi LLM (vLLM) pada satu GPU NVIDIA T4.
Agen ini mengamati interaksi CPU dan GPU **tanpa mengubah kode mesin inferensi, pustaka CUDA, maupun driver GPU**.
Data yang dikumpulkan dipakai untuk menentukan apakah lonjakan TTFT dan TPOT berasal dari sisi CPU atau dari sisi GPU.

Repositori ini adalah implementasi Tugas Akhir *Observability Kinerja GPU Berbasis eBPF pada Server Inferensi Large Language Model* (Ahmad Wicaksono, 13523121, Teknik Informatika ITB).
Kode titik pengamatan P1–P8 dan kategori diagnosis mengikuti Bab III proposal.

> **Status:** prototipe awal. Kode sudah dikompilasi, lolos verifier kernel, dan lolos uji asap tanpa GPU (`tests/`), tetapi belum dijalankan terhadap vLLM pada server T4.
> Daftar fungsi CUDA harus dipastikan dulu dengan `scripts/count_cuda_calls.sh` (lihat [Langkah pemakaian](#langkah-pemakaian)).

## Titik pengamatan yang di-*trace*

| Kode | Jenis probe | Sasaran | Informasi yang diperoleh | Bawaan |
|---|---|---|---|---|
| **P1** | `fentry` | `tcp_sendmsg`, `tcp_cleanup_rbuf`, `tcp_close` pada proses sasaran dengan port lokal API server (bawaan 8000) | Waktu permintaan diterima, waktu setiap token dikirim, dan koneksi ditutup. Dipakai untuk menghitung TTFT dan TPOT dari sisi server | Nyala |
| **P2** | `uprobe` | `cuLaunchKernel`, `cuLaunchKernelEx`, `cuGraphLaunch` (beserta varian `_ptsz`) di `libcuda.so` | Jumlah peluncuran kernel dan graf, celah antarpeluncuran, celah terpanjang | Nyala |
| **P3** | `uprobe` + `uretprobe` | `cuStreamSynchronize(_ptsz)`, `cuEventSynchronize`, `cuCtxSynchronize` | Lama CPU menunggu GPU dan batas langkah inferensi | Nyala |
| **P4** | `uprobe` + `uretprobe` | `cuMemcpy{HtoD,DtoH,DtoD}[Async]_v2`, `cuMemcpy[Async]` (beserta varian `_ptds`/`_ptsz`) | Arah, ukuran, dan lama pemanggilan penyalinan memori | Nyala |
| **P5** | `tp_btf` | `sched_switch`, `sched_wakeup` | Lama *thread* siap berjalan tetapi belum mendapat giliran (`runq_ns`), lama tidak berjalan (`offcpu_ns`), jumlah disela paksa | Nyala |
| **P6** | `tp_btf` | `sched_process_fork`, `sched_process_exit` | Proses anak baru (misalnya EngineCore) otomatis ikut diamati, probe dilepas ketika proses berhenti | Nyala |
| **P7** | `uprobe` + `uretprobe` | `cuMemAlloc_v2`, `cuMemAllocAsync(_ptsz)`, `cuMemFree_v2`, `cuMemFreeAsync(_ptsz)` | Waktu, ukuran, dan alamat alokasi memori GPU | Mati (`--enable P7`) |
| **P8** | `tracepoint` | `syscalls:sys_enter_ioctl`, `sys_exit_ioctl` | Perkiraan kasar aktivitas driver (fd, nomor perintah, lama) | Mati (`--enable P8`) |

Hal yang **tidak** diamati:
- Waktu mulai dan selesai eksekusi kernel di GPU, karena agen tidak memakai CUPTI. Lama eksekusi di GPU disimpulkan dari lama menunggu pada P3.
- Keadaan di dalam GPU (percabangan *warp*, akses memori).
- Isi permintaan dan isi token. P1 hanya mencatat ukuran data dan waktu.
- Keterlambatan jaringan setelah `send()` selesai di server.

### Batas langkah dan mode ringkas

Peluncuran kernel (P2) bisa terjadi ribuan kali per langkah inferensi, padahal satu *uprobe* di kernel butuh sekitar 2,56 µs.
Karena itu P2 **tidak dikirim satu per satu** ke ruang pengguna.
Data P2 dan P5 diringkas di dalam map per *thread*, lalu dikirim sebagai satu kejadian `step` setiap kali ada **batas langkah**.
Batas langkah adalah kembalinya fungsi sinkronisasi (P3) atau `cuMemcpyDtoH` yang sinkron (P4).

| Mode | Perilaku | Cara memakai |
|---|---|---|
| ringkas (bawaan) | P2 hanya dihitung di kernel dan dikirim di dalam kejadian `step` | — |
| rinci | Setiap peluncuran kernel juga dikirim sebagai kejadian `launch` | `--rinci`, atau kirim `SIGUSR1` ke heideltrace saat berjalan |

## Keamanan

Agen ini dirancang untuk aman dijalankan di server bersama:

1. **Hanya membaca.** Program eBPF tidak memakai `bpf_probe_write_user`, `bpf_override_return`, atau `bpf_send_signal`. Agen tidak dapat mengubah memori, nilai kembali, maupun alur proses yang diamati.
2. **Lolos verifier kernel.** Setiap program diperiksa verifier sebelum berjalan sehingga tidak dapat merusak kernel. `--check` menjalankan pemeriksaan ini tanpa memasang probe apa pun.
3. **Hanya proses sasaran.** Uprobe dipasang khusus pada PID sasaran dan proses anaknya, bukan pada seluruh sistem. Proses lain yang memakai `libcuda.so` (misalnya milik pengguna lain) **tidak terkena** biaya uprobe. Setiap program juga langsung berhenti jika kejadian bukan dari proses sasaran.
4. **Memori terbatas.** Semua map punya batas ukuran (64 proses, 16.384 *thread*, ring buffer 4 MB). Map per *thread* memakai LRU sehingga tidak bisa penuh. Kejadian yang tidak muat dihitung sebagai `hilang` dan tidak membuat aplikasi tertahan.
5. **Lepas otomatis.** Semua probe terikat pada *file descriptor* milik heideltrace. Probe otomatis dilepas oleh kernel ketika heideltrace berhenti, termasuk jika dimatikan paksa (`kill -9`) atau *crash*.
6. **Tidak ada jaringan keluar.** Hasil hanya ditulis ke berkas lokal atau stdout.
7. **Probe opsional tidak dimuat.** P7 dan P8 tidak dimuat ke kernel sama sekali kecuali diminta. Probe lain dapat dimatikan dengan `--disable`.
8. **Tidak perlu menghentikan vLLM.** Agen dipasang dan dilepas ketika vLLM sedang berjalan.

Yang tetap perlu diperhatikan:
- Agen butuh **root**. Minta izin pengelola server lab sebelum menjalankannya.
- P2 menambah sekitar 2,56 µs per peluncuran kernel **pada proses sasaran**. Ukur dulu *overhead*-nya sebelum dipakai di luar pengujian.
- P1 dan P5 memasang probe pada fungsi kernel yang dipakai seluruh sistem. Proses lain hanya terkena pemeriksaan PID yang sangat singkat, tetapi biaya ini tetap ada.
- `scripts/count_cuda_calls.sh` memasang uprobe pada **semua** fungsi `cu*`. Jalankan hanya saat server uji tidak dipakai orang lain.
- Repositori ini **tidak** berisi penyuntik gangguan (*fault injector*). Penyuntik gangguan akan dibuat terpisah dan hanya dijalankan dengan izin pengelola server.

## Kebutuhan sistem

| Komponen | Kebutuhan |
|---|---|
| Kernel Linux | ≥ 5.15 (BPF cookie pada uprobe), dengan `CONFIG_DEBUG_INFO_BTF=y` |
| Arsitektur | x86_64 (yang sudah diuji) |
| Driver NVIDIA | Driver apa pun yang menyediakan `libcuda.so` |
| Build | `clang` ≥ 11, `make`, `gcc`, `libelf-dev`, `zlib1g-dev`, `libssl-dev`, `pkg-config` |
| Opsional | `bpftrace` untuk `scripts/count_cuda_calls.sh` |

libbpf (v1.8.0) dan bpftool (v7.8.0) diambil dari submodule, jadi tidak perlu dipasang di sistem.

## Build

```bash
git clone --recursive https://github.com/sonix03/heideltrace.git
cd heideltrace
# jika sudah di-clone tanpa --recursive:
git submodule update --init --recursive

sudo apt install clang llvm make gcc libelf-dev zlib1g-dev libssl-dev pkg-config
make
```

Hasilnya `build/heideltrace`. `vmlinux.h` dibuat otomatis dari `/sys/kernel/btf/vmlinux` mesin build.
Berkat CO-RE, biner yang sama dapat dijalankan pada versi kernel lain yang punya BTF.

## Langkah pemakaian

```bash
# 1. Periksa kesiapan mesin (hanya membaca, tidak mengubah apa pun)
./scripts/check_env.sh            # atau: ./scripts/check_env.sh <PID vLLM>

# 2. Cari PID. Proses induk vLLM untuk P1, proses yang memakai GPU untuk P2-P4.
pgrep -f "vllm serve"
nvidia-smi --query-compute-apps=pid,process_name --format=csv

# 3. Pastikan fungsi CUDA yang benar-benar dipanggil (sekali saja, sambil memberi beban)
sudo ./scripts/count_cuda_calls.sh <PID GPU> 30

# 4. Uji verifier tanpa memasang probe
sudo ./build/heideltrace --check

# 5. Jalankan agen. Cukup PID induk; proses anak ikut diamati otomatis.
sudo ./build/heideltrace -p <PID vLLM> -o hasil.jsonl -d 120
```

Contoh opsi lain:

```bash
sudo ./build/heideltrace -p 1234 --disable P1          # tanpa pengamatan jaringan
sudo ./build/heideltrace -p 1234 --enable P7,P8        # tambah probe opsional
sudo ./build/heideltrace -p 1234 --port 8080 --rinci   # port lain, mode rinci
sudo kill -USR1 $(pgrep heideltrace)                    # pindah mode saat berjalan
```

Jika vLLM berjalan di dalam kontainer, gunakan PID yang terlihat oleh heideltrace (biasanya PID dari sisi host). `libcuda.so` dicari lewat `/proc/<PID>/root`, jadi tetap terdeteksi.
Jika tidak terdeteksi, berikan lokasinya dengan `--libcuda`.

Program eBPF selalu melihat PID versi kernel. Jika heideltrace sendiri berjalan di namespace PID lain (di dalam kontainer atau WSL), PID yang diberikan otomatis diterjemahkan dengan *task iterator*.
Pada keluaran, `pid` adalah PID yang terlihat oleh heideltrace, sedangkan `tgid` dan `tid` adalah PID versi kernel.

Titik pengamatan juga dapat dimatikan saat berjalan dengan menulis ke map kendali (indeks = nomor P, indeks 9 = mode):

```bash
sudo bpftool map update name control key 2 0 0 0 value 0 0 0 0   # matikan P2
```

## Uji tanpa GPU

Dua uji asap dapat dijalankan pada mesin Linux mana pun tanpa GPU:

```bash
make
sudo ./tests/smoke.sh       # P2-P4, P6, P7 dengan libcuda.so tiruan
sudo ./tests/net_smoke.sh   # P1 dengan server HTTP Python lokal (butuh python3 dan curl)
```

`smoke.sh` membuat `libcuda.so.1` tiruan (`tests/fake_libcuda.c`) dan aplikasi yang meniru 13 langkah inferensi (`tests/fake_app.c`).
Uji ini memeriksa jumlah kejadian `step`, `memcpy`, `alloc`, serta proses anak yang ikut diamati.

## Format keluaran

Setiap baris adalah satu objek JSON. Semua `ts_ns` memakai `CLOCK_MONOTONIC`.
Baris pertama (`meta`) berisi `mono_to_real_ns` untuk mengubahnya ke waktu nyata agar dapat dicocokkan dengan catatan pembangkit beban.

| `type` | Asal | Isi utama |
|---|---|---|
| `meta` | — | versi, port, mode, daftar probe aktif |
| *(semua)* | — | `ts_ns`, `pid`, `tgid`, `tid`, `comm` |
| `step` | P3/P4 (+P2, P5) | `fn`, `wait_ns` (lama menunggu GPU), `launches`, `graphs`, `lead_ns`, `gap_sum_ns`, `gap_max_ns`, `runq_ns`, `offcpu_ns`, `preempt`, `switches` |
| `launch` | P2, mode rinci | `fn`, `func` (handle CUfunction), `grid`, `block`, atau `graph` dan `stream` untuk CUDA Graph |
| `memcpy` | P4 | `fn`, `dir` (`htod`/`dtoh`/`dtod`/`any`), `async`, `bytes`, `dur_ns`, `stream` |
| `alloc` | P7 | `op` (`alloc`/`free`), `bytes`, `ptr`, `dur_ns` |
| `net` | P1 | `dir` (`recv`/`send`/`close`), `bytes`, `sock` (penanda koneksi) |
| `proc_start` / `proc_exit` | P6 | `ppid` |
| `ioctl` | P8 | `fd`, `cmd`, `dur_ns` |

Contoh satu kejadian `step`:

```json
{"ts_ns":81234567890,"pid":4021,"tgid":4021,"tid":4021,"comm":"VLLM::EngineCor","type":"step","fn":"cuStreamSynchronize","wait_ns":18234011,"handle":"0x0","ret":0,"launches":412,"graphs":3,"lead_ns":152331,"gap_sum_ns":2210554,"gap_max_ns":95012,"runq_ns":0,"offcpu_ns":0,"preempt":0,"switches":1}
```

Pembacaan cepat yang sesuai dengan aturan diagnosis pada proposal:
- `gap_*` membesar, `wait_ns` kecil, `runq_ns` besar → perebutan CPU oleh proses lain (kategori 1).
- `gap_*` membesar, `wait_ns` kecil, `offcpu_ns` besar, `runq_ns` kecil → hambatan lain di sisi host (kategori 2).
- `gap_*` normal, `wait_ns` jauh di atas data acuan → perebutan atau perlambatan GPU (kategori 3).

## Keterbatasan yang diketahui

- **Durasi `memcpy` varian `Async`** adalah lama pemanggilan di CPU, bukan lama transfer di GPU.
- **Kernel di dalam CUDA Graph** tidak terlihat satu per satu. `graphs` menghitung peluncuran graf, bukan jumlah kernelnya.
- **Ukuran blok pada `cuLaunchKernel`** hanya `blockX × blockY` karena `blockZ` ada di *stack*.
- **Nama kernel** belum tersedia. Mode rinci baru mencatat handle `CUfunction`.
- **P1 menganggap satu koneksi = satu permintaan dengan mode *streaming***. Penerimaan dideteksi lewat `tcp_cleanup_rbuf`. Jika fungsi ini tidak ada di kernel, bagian tersebut dimatikan otomatis dengan peringatan.
- **Simbol beralias ganda:** jika dua nama simbol di `libcuda.so` menunjuk alamat yang sama, peluncuran bisa terhitung dua kali. Periksa dengan `count_cuda_calls.sh`.
- **Panggilan internal libcudart:** `libcudart` bisa memanggil driver lewat penunjuk fungsi internal. Jika `count_cuda_calls.sh` menunjukkan fungsi yang diharapkan tidak pernah dipanggil, daftar `cuda_syms` di `src/heideltrace.c` perlu disesuaikan.

## Struktur repositori

```
src/heideltrace.bpf.c       program eBPF (P1-P8)
src/heideltrace.c           pemuat, pemasangan uprobe per PID, keluaran JSON Lines
src/heideltrace.h           struktur data bersama kernel <-> ruang pengguna
scripts/check_env.sh        pemeriksaan kesiapan mesin (hanya membaca)
scripts/count_cuda_calls.sh penghitungan frekuensi fungsi cu* dengan bpftrace
tests/                      uji asap tanpa GPU (libcuda.so tiruan, server HTTP lokal)
libbpf/, bpftool/           submodule
```

## Rencana berikutnya

- [ ] Menjalankan `count_cuda_calls.sh` pada vLLM di server T4 dan menyesuaikan daftar simbol.
- [ ] Pengorelasi: menyusun kejadian `step` dan `net` menjadi lini masa langkah dan permintaan.
- [ ] Penganalisis: deteksi anomali (persentil ke-99, regresi TTFT) dan enam kategori penyebab.
- [ ] Pembangkit beban (kedatangan Poisson) di repositori atau direktori terpisah.
- [ ] Penyuntik gangguan G1–G6, hanya untuk lingkungan uji.
- [ ] Pengukuran *overhead* per kelompok titik pengamatan.

## Lisensi

Program eBPF memakai lisensi `Dual BSD/GPL` karena beberapa helper eBPF hanya tersedia untuk program berlisensi GPL.
Lisensi repositori belum ditentukan.
