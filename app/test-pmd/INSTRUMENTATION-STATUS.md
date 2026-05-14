# testpmd Jitter Instrumentation — Current Implementation Status

Last updated: 2026-05-14

## Overview

Per-iteration jitter detection and attribution for testpmd's forwarding engines. Detects loop iterations that exceed a configurable threshold and captures hardware/software telemetry to attribute the delay.

## Architecture

### Hot Path (every iteration)
Runs inline in each forwarding engine (iofwd.c, macfwd.c, etc.):

1. **`jitter_iter_begin()`**: Records TSC start, reads rx_ring_depth via `rte_eth_rx_queue_count()`
2. **`jitter_mark_rx()`**: Records TSC after `rte_eth_rx_burst()` returns
3. **`jitter_mark_process()`**: Records TSC after packet processing
4. **`jitter_iter_end()`**: 
   - Reads TSC end
   - Reads all PMC end values via rdpmc (8 reads)
   - Computes PMC deltas from previous iteration's end values (rollover-safe, 48-bit)
   - Updates ctx->last_pmc_* baselines
   - Checks for anomaly triggers:
     - TSC delta >= threshold → `JITTER_FLAG_THRESHOLD`
     - eBPF cs ring seq changed → `JITTER_FLAG_CS_EVENT`
     - eBPF irq ring head changed → `JITTER_FLAG_IRQ_EVENT`
   - If any flag set: reads NIC stats (`rte_eth_stats_get`), then calls cold path
   - Warmup: first N iterations (default 3M) are skipped

### Cold Path (only on anomaly)
`jitter_record_anomaly()` — called only when an anomaly is detected:

1. Stores TSC timestamps, phase deltas, PMC deltas (pre-computed in hot path)
2. Reads rx_ring_depth_after via `rte_eth_rx_queue_count()`
3. Reads PMD rx_burst phase timing from shared global array (`rte_ethdev_rx_burst_tsc`)
4. Reads eBPF IRQ/CS data from mmap'd BPF maps
5. Reads context switch counters via `getrusage()` (if eBPF not available)
6. Reads MSR counters (SMI, APERF/MPERF) if `--jitter-msr` enabled
7. Reads PCIe AER registers if `--jitter-aer` enabled
8. Reads NIC xstats if `--jitter-xstats` enabled
9. Inserts record into per-lcore ring buffer and worst-N buffer

### PMC Counters (via perf_event_open + rdpmc)
Read in the hot path on every iteration. Uses `perf_event_open()` for setup, `rdpmc` for reading.
Deltas computed per-iteration from previous end values (no begin reads needed).

Current counters:
- **instructions retired** (all) — fixed counter
- **instructions retired** (user only, exclude_kernel=1) — programmable
- **cycles unhalted** — fixed counter
- **ref cycles** — fixed counter

### PMC Counters (via direct MSR programming)
Programmed via `wrmsr` to `IA32_PERFEVTSELx`, read via `rdpmc(index)`.
Bypasses perf_event_open to avoid PMI interrupt storm on isolated CPUs.
INT bit (20) is NOT set — no overflow interrupts generated.

Current counters (slots 6-7):
- **mem_bound_stalls_load.all** (event=0x34, umask=0x7F) — total cycles stalled on loads
- **mem_bound_stalls_load.l2_hit** (event=0x34, umask=0x01) — cycles stalled on L2 hits

Previous counters (removed after confirming near-zero values):
- ocr.demand_data_rd.l3_hit.snoop_hitm — cross-core modified line contention
- ocr.demand_data_rd.l3_hit.snoop_hit_with_fwd — cross-core shared forwarding
- LLC misses, branch misses, LLC refs — all near-zero under contention

### eBPF Programs
Attached to kernel tracepoints for zero-syscall interrupt and context switch detection.
Programs are in `app/test-pmd/jitter_ebpf_progs/jitter.bpf.c`.
Pre-compiled skeleton in `jitter.skel.h`.

**IMPORTANT**: The `.bpf.o` and `vmlinux.h` must be regenerated on each target host:
```bash
cd app/test-pmd/jitter_ebpf_progs
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -target bpf -O2 -g -I. -I.. -c jitter.bpf.c -o jitter.bpf.o
bpftool gen skeleton jitter.bpf.o > jitter.skel.h
```

Tracepoints attached (15 total):
- `sched/sched_switch` — context switch tracking
- `irq/irq_handler_entry` — device IRQ tracking
- `irq_vectors/local_timer_entry` — LOC timer
- `irq_vectors/reschedule_entry` — RES IPI
- `irq_vectors/call_function_entry` — CAL IPI
- `irq_vectors/call_function_single_entry` — CAL single
- `irq_vectors/irq_work_entry` — IWI workqueue
- `irq_vectors/thermal_apic_entry`, `threshold_apic_entry`, etc.
- `irq/softirq_entry` — softirq processing
- `nmi/nmi_handler` — NMI

**Note on eBPF IRQ detection**: Brief interrupts (CAL, IWI) that don't exceed the TSC threshold are consumed on normal iterations and won't appear in anomaly records. Only interrupts that coincide with threshold anomalies are reported. See `feedback_ebpf_irq_detection.md` in memory.

### PMD rx_burst Phase Timing
The mlx5 driver writes TSC values to a shared global array (`rte_ethdev_rx_burst_tsc[][]`)
defined in `lib/ethdev/rte_ethdev_jitter.c`. This avoids struct offset dependencies between
the driver and testpmd.

Instrumented in both `mlx5_rx_burst()` (scalar) and `mlx5_rx_burst_vec()` (vectorized):
- **start**: TSC at rx_burst entry
- **poll**: time in `rxq_cq_process_v()` / `mlx5_rx_poll_len()` — CQE memory reads (NIC DMA data)
- **alloc**: time in `mlx5_rx_replenish_bulk_mbuf()` / `rte_mbuf_raw_alloc()` — mbuf allocation
- **wqe**: time in CQ/RQ doorbell writes

testpmd reads these in the cold path and reports as "rx_burst detail" in the anomaly dump.

### NIC Stats
`rte_eth_stats_get()` is called in the hot path (only on anomaly detection, before cold path).
Reports `rx_missed_delta` (NIC hardware drops) per anomaly iteration.
Hardware stats are reset at forwarding start via `rte_eth_stats_reset()`.

## Classification
Applied at dump time by `jitter_classify()`:

1. **KERNEL_PREEMPTION**: `inst_retired > inst_user` (any kernel instructions detected)
2. **SMI**: `smi_count_delta > 0`
3. **FREQ_THROTTLE**: APERF/MPERF ratio < 0.8
4. **CSTATE**: TSC delta > 2× cycles_unhalted (CPU halted, no kernel work)
5. **NIC_OVERFLOW**: `rx_missed_delta > 0 && rx_ring_depth_before > 0`
6. **MEMPOOL_STARVED**: `rx_nombuf_delta > 0`
7. **APP_BACKLOG**: `rx_ring_depth_before > 512 && inst_retired > 1000`
8. **MEMORY_STALL**: `inst_retired × 4 < cycles_unhalted` (high cycles/inst)
9. **UNKNOWN**: none of the above

## Output
At shutdown, testpmd dumps:
- **Summary table**: per-lcore iteration count, anomaly count, trigger breakdown, max jitter
- **Top-N anomalies** (default 50, sorted by TSC delta): full record with phase breakdown,
  PMC values, NIC stats, eBPF data, rx_burst phase detail

## CLI Options
```
--jitter-enable          Enable jitter instrumentation
--jitter-threshold-us=N  Anomaly threshold in microseconds (default 100)
--jitter-record-count=N  Per-lcore ring buffer size (default 1024)
--jitter-warmup=N        Skip first N iterations (default 1000000)
--jitter-ebpf            Enable eBPF context switch/interrupt tracking
--jitter-msr             Enable MSR reads (SMI count, APERF/MPERF)
--jitter-aer             Enable PCIe AER register reads
--jitter-interrupts      Track per-CPU interrupt counts (syscall-based)
--jitter-cs              Track context switches via getrusage (syscall-based)
--jitter-xstats          Capture PMD-specific xstat deltas
```

## Runtime Commands
```
jitter show              Print summary stats
jitter dump              Write all captured records
jitter reset             Clear all ring buffers and counters
jitter threshold <us>    Change threshold at runtime
jitter top [N]           Show top N anomalies by duration
```

## Files
```
app/test-pmd/
  jitter.h               Public API, inline hot-path functions, record/ctx structs
  jitter.c               Init/fini, cold-path anomaly recording
  jitter_pmc.c            PMC setup (perf_event_open + direct MSR)
  jitter_msr.c            MSR read helpers (SMI, APERF/MPERF)
  jitter_pcie.c           PCIe AER capability read helpers
  jitter_report.c         Classification, text/CSV dump, top-N reporting
  jitter_ebpf.c           eBPF program lifecycle (load/attach/register/detach)
  jitter_ebpf.h           eBPF shared struct definitions
  jitter_ebpf_progs/
    jitter.bpf.c          eBPF program source (15 tracepoint handlers)
    jitter.skel.h         Pre-generated skeleton (must regenerate per-host)
    vmlinux.h             BTF header (must regenerate per-host)
    jitter.bpf.o          Pre-compiled BPF object
    check_ebpf_prereqs.sh Prerequisite checker

lib/ethdev/
  rte_ethdev_jitter.h     Shared rx_burst timing struct and global array declaration
  rte_ethdev_jitter.c     Global array definition

drivers/net/mlx5/
  mlx5_rx.c               Scalar rx_burst TSC instrumentation
  mlx5_rxtx_vec.c         Vectorized rx_burst TSC instrumentation (rxq_burst_v)
```

## Key Lessons Learned

1. **perf_event_open with PERF_TYPE_RAW generates PMI interrupt storms** on isolated CPUs. Use direct MSR programming (wrmsr to PERFEVTSELx with INT bit clear) for raw events.

2. **PMC reads must be in the hot path**, immediately after TSC read, to align with tsc_delta. Cold-path PMC reads include cold-path work and produce cycles_unhalted > tsc_delta.

3. **"Read only at end" approach**: PMC deltas are computed from previous iteration's end values, not begin/end within one iteration. This halves rdpmc count (8 vs 16 per iteration). Rollover handled with 48-bit wrapping.

4. **The mlx5 driver may use vectorized rx path** (`mlx5_rx_burst_vec`), not the scalar `mlx5_rx_burst`. Both must be instrumented.

5. **Shared global array** (`rte_ethdev_rx_burst_tsc`) is needed to pass timing data between the mlx5 driver and testpmd, because `mlx5_rxq_data` struct offsets differ between compilation units.

6. **eBPF skeleton must be regenerated per-host** — the pre-compiled `.bpf.o` uses `vmlinux.h` from the build host, and tracepoint struct layouts are kernel-version-specific.

7. **isolcpus=managed_irq** is required to prevent kernel-managed MSI-X vectors from landing on isolated CPUs. The `cpu-partitioning` tuned profile does NOT add this.

8. **rdpmc permission**: Direct rdpmc reads (for MSR-programmed counters) require `/sys/bus/event_source/devices/cpu/rdpmc` set to 2.

## Investigation Findings (Sierra Forest / Xeon 6780E)

Using gc-stress (280 workers, GOGC=1) to generate memory pressure on all CPUs except testpmd's:

- **Anomaly rate**: ~30K/min on the traffic-handling lcore, ~20/min on idle lcore
- **Anomaly duration**: 40-90 us (vs <5 us baseline)
- **Phase**: >95% of stall time is in `rx` phase (inside `rte_eth_rx_burst`)
- **rx_burst sub-phase**: >95% of rx time is in `poll` (CQE processing / `rxq_cq_process_v`)
- **LLC/cache**: Near-zero LLC misses, near-zero snoop_hitm/fwd — NOT cache eviction or cross-core contention
- **Memory stalls**: `mem_bound_stalls_load.all` accounts for 10-30% of anomaly cycles
- **Root cause hypothesis**: Memory/mesh interconnect bandwidth saturation causing elevated latency for all memory accesses (including NIC CQE reads), even when data is in cache
