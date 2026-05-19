# DPDK Forwarding Jitter: Instrumentation, Analysis, and Noisy-Neighbor Mitigations

## Executive Summary

We developed per-iteration jitter instrumentation for DPDK testpmd to detect and attribute forwarding loop latency spikes at microsecond granularity. Using this instrumentation alongside a purpose-built Go GC stress tool, we investigated how memory-intensive co-located workloads cause packet forwarding jitter on isolated CPUs.

**Key findings:**
- Noisy-neighbor jitter is caused by **mesh interconnect contention from cross-core cache coherency traffic**, not by cache eviction or memory bandwidth saturation alone
- **NUMA isolation** completely eliminates jitter (cross-NUMA workloads cause zero impact)
- **Intel CAT** (Cache Allocation Technology) eliminates worst-case tail latency but has limits — DDIO LLC ways must be included in the allocation, and residual mesh contention remains
- **Intel MBA** (Memory Bandwidth Allocation) is ineffective against GC-style bursty workloads
- **DDIO must stay enabled** — disabling it doubles jitter by forcing NIC DMA through the congested memory controller
- **Aggressive GC** (small heap) is paradoxically less disruptive than lazy GC (large heap) to co-located latency-sensitive workloads

---

## 1. Instrumentation Architecture

### 1.1 Design Goals

Detect forwarding loop iterations exceeding a configurable threshold (default 5-15 us) and capture enough telemetry to attribute the delay to a specific cause: kernel preemption, C-state entry, memory stalls, NIC/PCIe delays, or application backlog.

### 1.2 Hot Path (every iteration)

The instrumentation runs inline in each testpmd forwarding engine with minimal overhead:

- **TSC timestamps** at iteration boundaries and phase markers (rx, process, tx)
- **PMC counters** via rdpmc: instructions (total + user-only), cycles, ref_cycles — read once per iteration at the end, with deltas computed from the previous iteration's values
- **Platform-specific counters** via direct MSR programming (bypasses perf_event_open to avoid PMI interrupt storms on isolated CPUs): mem_bound_stalls, OCR snoop events
- **eBPF detection**: mmap'd BPF ring buffers checked for interrupt and context switch events without any syscalls
- **Conditional PMC reads**: inside the mlx5 rx_burst poll path, additional PMC counters are read only when the CQ poll exceeds a threshold

When jitter is not enabled (`--jitter-enable` not passed), the overhead is zero — a single NULL pointer check per iteration.

### 1.3 Cold Path (only on anomaly)

When an anomaly is detected, a detailed record is captured:

- Phase timing breakdown (rx, process, tx) and mlx5 rx_burst sub-phases (poll, alloc, wqe)
- NIC stats (rx_missed, rx_nombuf) captured in the hot path for timing accuracy
- eBPF interrupt details (which interrupt types, from ring buffer)
- Optional: MSR reads (SMI count, APERF/MPERF), PCIe AER registers, PMD xstats

### 1.4 Key Design Decisions

**PMC read placement**: All PMC end-reads must be in the hot path immediately after the TSC read. Early designs placed PMC reads in the cold path, which contaminated cycles_unhalted with cold-path work (causing cycles_unhalted > tsc_delta — an impossibility that revealed the measurement error).

**Single-read delta approach**: Rather than reading PMCs at both iteration begin and end (18 rdpmc per iteration), we read only at the end (8 rdpmc) and compute deltas from the previous iteration's values. This halves the PMC overhead. Rollover is handled with 48-bit wrapping arithmetic.

**Direct MSR programming for raw events**: Intel's `perf_event_open()` with `PERF_TYPE_RAW` generates Performance Monitoring Interrupts (PMIs) that land on isolated CPUs — ~6K interrupts/second, corrupting the measurements. We bypass perf entirely by writing `IA32_PERFEVTSELx` MSRs directly with the INT bit clear, then reading via `rdpmc`. This requires `/sys/bus/event_source/devices/cpu/rdpmc` set to 2.

**Shared global array for PMD timing**: The mlx5 driver and testpmd are compiled as separate translation units with different struct layouts. Passing rx_burst phase timing via struct fields in `mlx5_rxq_data` failed due to offset mismatches. We solved this with a shared global array (`rte_ethdev_rx_burst_tsc[][]`) in lib/ethdev that both sides access without header dependencies.

**eBPF skeleton regeneration**: The pre-compiled BPF object uses `vmlinux.h` from the build host. Tracepoint struct layouts (especially `irq_vectors/*`) are kernel-version-specific. The skeleton must be regenerated on each target host using `bpftool btf dump` + `clang` + `bpftool gen skeleton`.

---

## 2. Test Environment

### 2.1 Traffic Path

- **Traffic generator** sends ~4.2 Mpps unidirectional to testpmd
- **testpmd** runs in io forwarding mode on 2 isolated CPUs, forwarding packets between two NIC ports
- **NIC**: Mellanox ConnectX-6 Lx (mlx5_core driver, bifurcated/RDMA mode)

### 2.2 CPU Configuration

- **Tuned profile**: cpu-partitioning with `isolcpus=managed_irq`
- **testpmd**: 2 forwarding lcores + 1 housekeeping lcore
- **Hugepages**: 16x 1GB
- **irqbalance**: enabled with banned CPU list matching isolated cores

### 2.3 Noisy-Neighbor Workload

A custom Go program (`gc-stress`) runs on all CPUs except testpmd's cores. It continuously allocates and discards object trees, maps, and slices across many goroutines, generating intensive GC pressure and memory thrashing. Configurable via GOGC (GC frequency vs heap size tradeoff).

---

## 3. Root Cause Analysis

### 3.1 What It's NOT

Through systematic elimination using PMC counters and uncore events:

| Hypothesis | Evidence | Verdict |
|-----------|----------|---------|
| LLC cache eviction | Near-zero LLC misses on testpmd PMCs | Eliminated (with CAT) |
| Cross-core cache contention (snoop_hitm) | Near-zero per-iteration snoop_hitm deltas on testpmd | Not the primary cause |
| Kernel preemption | Zero context switches, zero kernel instructions on isolated CPUs | Eliminated |
| SMI (System Management Interrupt) | Zero SMI count delta | Eliminated |
| Frequency throttling | APERF/MPERF ratio = 1.0 | Eliminated |
| Memory bandwidth saturation (DRAM) | mem_bound_stalls_load accounts for only 10-30% of anomaly cycles | Partial contributor |

### 3.2 What It IS

**Mesh interconnect contention from cross-core cache coherency (snoop) traffic.**

The gc-stress workers generate massive snoop_hitm traffic among themselves — 10M+ snoop_hitm events per 5 seconds from Go GC's mark phase and allocator sharing modified cache lines across 136 cores. This traffic floods the mesh fabric that connects LLC slices (CHAs).

Testpmd's memory accesses — even to data in its own exclusive LLC ways — must traverse this congested mesh to reach the CHA that owns the target address. The mesh queuing delays cause all memory operations to take 3-15x longer than normal.

**Evidence:**
- External `perf stat` on testpmd CPUs shows 10M snoop_hitm/5s (accumulated), even though per-iteration deltas are near zero (each iteration sees 0-2, but billions of iterations accumulate)
- Same-NUMA gc-stress causes 118 anomalies; cross-NUMA causes 0 — the mesh is per-NUMA
- IMC bandwidth increases ~1000x during gc-stress, but MBA throttling has no effect — the stalls are from mesh/snoop traffic, not memory controller bandwidth
- CHA LLC victim counters show 2-74M modified-line evictions/5s depending on heap size

### 3.3 Stall Distribution

Using mlx5 rx_burst phase timing instrumentation, we identified that stalls are distributed across ALL memory access paths, not localized to one operation:

| Stall location | Fraction of worst anomalies | What it accesses |
|---------------|---------------------------|-----------------|
| CQE processing (`rxq_cq_process_v`) | ~50% | NIC-DMA'd completion queue entries |
| Outside rx_burst (`rte_eth_rx_queue_count`) | ~15% | MMIO read to NIC |
| tx_burst (`rte_eth_tx_burst`) | ~15% | Descriptor writes, doorbell MMIO |
| mbuf allocation (`mlx5_rx_replenish_bulk_mbuf`) | ~10% | Mempool ring access |
| Mixed/split across phases | ~10% | Various |

This confirms the systemic nature of the contention — every memory access is slower, regardless of what data is being accessed.

---

## 4. Mitigation Evaluation

### 4.1 NUMA Isolation

| Placement | Workers | Anomalies | Max jitter |
|-----------|---------|-----------|------------|
| Same NUMA, 10 workers | 0 | 3.0 us |
| Same NUMA, 50 workers | 2 | 21.6 us |
| Same NUMA, 136 workers | 118 | 101.6 us |
| **Cross NUMA, 140 workers** | **0** | **3.2 us** |

**NUMA isolation completely eliminates jitter** because each NUMA node has its own mesh fabric, LLC, and memory controllers. Cross-NUMA traffic goes through UPI links but doesn't affect the local mesh.

**Recommendation**: For workloads requiring deterministic latency, ensure DPDK and noisy neighbors are on different NUMA nodes. This is the most effective mitigation.

### 4.2 Cache Allocation Technology (CAT)

CAT gives testpmd exclusive LLC ways that noisy neighbors cannot evict from.

| Config | testpmd ways | gc-stress ways | Anomalies | Max jitter |
|--------|-------------|---------------|-----------|------------|
| No CAT (shared) | 12 | 12 | 118 | 101.6 us |
| 4 exclusive ways | 4 | 8 | 77 | 41.6 us |
| **6 ways + DDIO** | **6 (0-3,10-11)** | **6 (4-9)** | **66** | **33.8 us** |
| 10 ways + DDIO | 10 | 2 | 55 | 33.8 us |

**CAT eliminates "Pattern A" anomalies** (full RX ring, moderate cycles/inst from LLC eviction) but cannot eliminate "Pattern B" anomalies (empty ring, high cycles/inst from mesh contention). The max jitter plateaus at ~34 us regardless of how many ways testpmd gets.

**Important: Squeezing gc-stress into fewer ways backfires** — with only 2 ways, gc-stress generates 6.4M modified-line evictions/5s (vs 2.3M with 6 ways), increasing mesh traffic and partially offsetting the benefit.

### 4.3 DDIO Interaction with CAT

Intel Data Direct I/O (DDIO) allows NICs to DMA data directly into LLC. DDIO uses specific LLC ways defined by the `shareable_bits` field in `/sys/fs/resctrl/info/L3/shareable_bits`.

**Critical finding**: If the DDIO ways are in the noisy neighbor's CAT allocation (not testpmd's), NIC-DMA'd CQE data gets evicted by the noisy neighbor. Testpmd must then fetch CQEs from DRAM through the congested memory controller.

| DDIO config | Anomalies | Max jitter |
|-------------|-----------|------------|
| DDIO ways in gc-stress allocation | 77 | 41.6 us |
| **DDIO ways in testpmd allocation** | **66** | **33.8 us** |
| DDIO disabled entirely | 127 | 49.9 us |

**Recommendation**: Always check `shareable_bits` and include those LLC ways in the DPDK application's CAT bitmask. Disabling DDIO is counterproductive.

### 4.4 Memory Bandwidth Allocation (MBA)

MBA throttles memory bandwidth by inserting delays in memory controller requests.

| MBA setting | gc-stress bandwidth | Anomalies | Max jitter |
|-------------|-------------------|-----------|------------|
| 100% (no throttle) | ~27 GB/s | 113 | 38.2 us |
| 70% | ~27 GB/s | 135 | 46.1 us |
| 50% | ~27 GB/s | 103 | 48.7 us |
| 30% | ~27 GB/s | 73 | 37.9 us |
| 10% | ~27 GB/s | 85 | 39.5 us |

**MBA is completely ineffective** against Go GC workloads. We verified MBA works correctly with steady-state `membw` (from intel-cmt-cat): 58% bandwidth reduction at the 10% setting. The Go GC's bursty, multi-threaded access pattern evades MBA's delay-insertion mechanism.

The root cause is that the jitter comes from mesh/snoop contention, not memory controller bandwidth. MBA throttles the memory controller but cannot throttle the mesh interconnect or snoop traffic.

### 4.5 Go GC Tuning

The GOGC parameter controls GC frequency vs heap size, which dramatically affects the TYPE of cache pressure:

| GOGC | GC rate | Heap | LLC victims/5s | Anomalies | Max jitter |
|------|---------|------|---------------|-----------|------------|
| **1** | **312/s** | **9 MB** | **2.3M** | **18** | **23.1 us** |
| 10 | 290/s | 10 MB | 2.7M | 137 | 45.7 us |
| 100 | 234/s | 50 MB | 7.4M | 624 | 29.5 us |
| 1000 | 20/s | 432 MB | 74M | 1,593 | 52.9 us |
| off | 3/s | 3.6 GB | 62M | 1,742 | 33.7 us |

**Counterintuitive finding**: The most aggressive GC (GOGC=1) is the least disruptive to co-located DPDK because frequent small GC cycles keep the heap tiny (~9 MB) and entirely within LLC. Lazy GC allows the heap to grow to hundreds of MB or GB, causing massive LLC eviction churn (up to 74M evictions/5s).

**Implication for Kubernetes/cloud**: Go applications with high GOGC or GOGC=off can be significantly more disruptive to co-located latency-sensitive workloads than applications with aggressive GC, even though aggressive GC uses more CPU.

### 4.6 Combined Mitigations

Best achievable with same-NUMA placement (136 gc-stress workers):

| Mitigations | Anomalies | Max jitter | Reduction |
|-------------|-----------|------------|-----------|
| None | 118 | 101.6 us | baseline |
| CAT 6-way + DDIO | 66 | 33.8 us | 67% max jitter reduction |
| CAT 6-way + DDIO + GOGC=1 | 18 | 23.1 us | 77% max jitter, 85% anomaly reduction |
| **NUMA isolation** | **0** | **3.2 us** | **100%** |

---

## 5. Anomaly Patterns

Two distinct patterns were identified:

### Pattern A: LLC Eviction (eliminated by CAT)

- **rx_ring_before ≈ 2000** (ring nearly full — core is busy processing)
- **cycles/inst: 2-5x** (moderate stall)
- **rx_missed > 0** (NIC drops packets while core is slow)
- **~46K instructions per iteration** — code is running but slowly
- **Cause**: gc-stress evicts testpmd's working set from LLC, every memory access goes to DRAM through the congested memory controller

### Pattern B: Mesh Contention (persists with CAT)

- **rx_ring_before < 100** (ring nearly empty — waiting for NIC completions)
- **cycles/inst: 10-40x** (severe stall)
- **rx_missed: 0 or variable**
- **~5K instructions per iteration** — CPU mostly idle, waiting
- **Cause**: mesh interconnect congested by gc-stress snoop traffic, CQE data access delayed even when in LLC

---

## 6. Instrumentation Lessons Learned

1. **Observer effect is real**: Adding TSC reads inside `mlx5_rx_burst_vec` (the vectorized RX path) increased anomalies 10x. Instrumentation must be conditional — only activate detailed measurements when a stall is already detected.

2. **perf_event_open with PERF_TYPE_RAW generates interrupts**: Even in counting mode with no sampling, raw PMC events via perf_event_open cause PMI storms (~6K LOC/IWI interrupts per second on isolated CPUs). The fix is direct MSR writes with the INT bit clear.

3. **Generic PMC events may not measure what you expect**: `PERF_COUNT_HW_CACHE_MISSES` mapped to L2 misses, not LLC misses, on some architectures. Platform-specific raw event codes are necessary for accurate LLC measurement.

4. **PMC read ordering matters**: Reading PMCs in the cold path (after anomaly detection) includes cold-path work in the measurements. All PMC end-reads must be in the hot path, immediately after the TSC read, to align with `tsc_delta`.

5. **The mlx5 driver may use vectorized RX**: `mlx5_rx_burst_vec` is selected over `mlx5_rx_burst` when the platform supports SIMD. Both paths must be instrumented.

6. **eBPF tracepoint structs are kernel-specific**: Pre-compiled BPF programs silently fail to attach if the tracepoint format doesn't match the running kernel. Always regenerate `vmlinux.h` and recompile on the target host.

7. **Brief interrupts below threshold are invisible**: The eBPF IRQ detection fires on every interrupt, but if the testpmd iteration completes under threshold, the event is consumed without recording. Only interrupts that coincide with threshold-exceeding iterations appear in anomaly records.

---

## 7. Repositories

- **Instrumented DPDK**: https://github.com/atheurer/dpdk (branch: `jitter-instrumentation`)
  - 44 commits on top of DPDK 24.11.0
  - `app/test-pmd/INSTRUMENTATION-STATUS.md` for current implementation details
- **GC stress tool**: https://github.com/atheurer/gc-stress

---

## 8. Future Work

- **Kubernetes integration**: Test with real Kubernetes pod scheduling to see if `isolcpus` + CAT can be managed via device plugins or resource classes
- **Other noisy-neighbor workloads**: Java GC, database buffer pool churn, ML training memory patterns
- **Uncore counter integration**: Read IMC and CHA counters from within testpmd for per-anomaly memory bandwidth and snoop correlation
- **ARM platform**: Extend instrumentation to ARM64 PMU (no rdpmc — use different counter access)
- **Upstream DPDK**: Propose jitter detection as an optional testpmd feature
