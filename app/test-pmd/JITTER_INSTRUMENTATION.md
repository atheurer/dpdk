# testpmd Jitter Instrumentation

Per-iteration jitter detection and attribution for testpmd forwarding engines.
Detects loop iterations that exceed a configurable time threshold and captures
diagnostic data to attribute the delay to a specific root cause.

## Quick Start

```bash
# Set up perf counter access
sudo sysctl kernel.perf_event_paranoid=-1

# Run testpmd with jitter enabled (interactive mode)
sudo ./build/app/dpdk-testpmd -- -i --jitter-enable --jitter-threshold-us=50

# At the testpmd prompt:
testpmd> start
# ... let it run ...
testpmd> jitter show
testpmd> jitter top 5
testpmd> jitter dump
testpmd> stop
```

## Build Requirements

Standard DPDK build dependencies:

- Fedora/RHEL: `sudo dnf install meson ninja-build gcc python3-pyelftools numactl-devel`
- Ubuntu/Debian: `sudo apt install meson ninja-build gcc python3-pyelftools libnuma-dev`
- Python >= 3.6

Build:
```bash
cd dpdk
meson setup build
ninja -C build app/dpdk-testpmd
```

## System Configuration

### Required: perf_event_paranoid

The jitter subsystem uses `perf_event_open()` and `rdpmc` to read hardware
performance counters (instructions retired, CPU cycles, reference cycles).
This requires:

```bash
sudo sysctl kernel.perf_event_paranoid=-1
```

Or more conservatively (allows per-process counters only):
```bash
sudo sysctl kernel.perf_event_paranoid=1
```

If this is not set, PMC setup will fail and `inst_retired`, `cycles_unhalted`,
and `ref_cycles` will be zero. TSC-based threshold detection still works.

### Recommended: CPU isolation

For best results, isolate the forwarding CPUs from the scheduler and
disable power management:

```bash
# Kernel command line (grub):
isolcpus=2,3 nohz_full=2,3 rcu_nocbs=2,3

# Disable frequency scaling:
sudo cpupower frequency-set -g performance

# Disable deep C-states:
sudo cpupower idle-set -d 2
```

## Command-Line Options

### Core options (no syscall noise)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--jitter-enable` | flag | off | Enable jitter instrumentation |
| `--jitter-threshold-us=N` | uint | 100 | Anomaly threshold in microseconds |
| `--jitter-record-count=N` | uint | 1024 | Per-lcore anomaly ring buffer size |
| `--jitter-output=PATH` | string | stderr | Output file for anomaly dump |
| `--jitter-output-format=FMT` | string | text | Output format: `text` or `csv` |

### Cold-path options (cause syscalls — introduce measurement noise)

These options enable additional diagnostic data collection on the cold path
(only when an anomaly is detected). Each causes one or more syscalls, which
may trigger context switches or interrupts that contaminate subsequent
measurements. Use selectively when investigating specific issues.

| Option | Type | Syscall | Description |
|--------|------|---------|-------------|
| `--jitter-cs` | flag | `getrusage()` | Track context switches per anomaly |
| `--jitter-xstats` | flag | PMD-dependent | Read PMD-specific xstats (ethtool ioctl on mlx5, userspace MMIO on ice) |
| `--jitter-interrupts` | flag | `fopen`/`fread` | Track per-CPU interrupt counts from `/proc/interrupts` |
| `--jitter-msr` | flag | `pread()` | Read MSRs: SMI_COUNT, APERF, MPERF. Requires `sudo modprobe msr` |
| `--jitter-aer` | flag | `rte_pci_read_config()` | Read PCIe AER error registers |

**Note:** Running with only `--jitter-enable` gives noise-free hot-path PMC
data (TSC, instructions, cycles, ref_cycles, phase timing) plus basic NIC
stats via `rte_eth_stats_get()` (userspace MMIO on most PMDs), without any
cold-path syscalls.

## Runtime Commands

At the `testpmd>` prompt:

| Command | Description |
|---------|-------------|
| `jitter show` | Print per-lcore summary (iterations, anomalies, max latency) |
| `jitter dump` | Write all captured anomaly records to output |
| `jitter top` | Show the single longest anomaly |
| `jitter top N` | Show the N longest anomalies, sorted by duration |
| `jitter reset` | Clear all per-lcore ring buffers and counters |
| `jitter threshold <us>` | Change anomaly threshold at runtime |
| `jitter set output <path>` | Change output file path |

## How It Works

### Hot Path (every iteration — no syscalls)

These measurements run on every forwarding loop iteration:

- `rte_rdtsc()` at iteration start and end (TSC timestamps)
- `rdpmc` x3 at iteration start (instructions retired, unhalted CPU cycles,
  reference cycles)
- `rte_eth_rx_queue_count()` at iteration start (RX ring depth)
- Per-phase timestamps: after RX burst, after processing, after TX burst
- One branch comparing TSC delta to threshold

Estimated overhead: ~150-200 cycles per iteration when no anomaly occurs.

### Cold Path (anomaly only)

When the iteration time exceeds the threshold, additional data is captured.
Some cold-path reads are always-on (no syscall), others require opt-in flags:

**Always-on (no syscall):**
- PMC end-of-iteration values (rdpmc — userspace instruction)
- RX queue depth after iteration (MMIO)
- NIC stats deltas: imissed, rx_nombuf, ierrors (`rte_eth_stats_get()` —
  userspace MMIO on most PMDs)
- Mempool available count (userspace memory read)

**Opt-in (causes syscalls):**
- Context switches via `getrusage()` (`--jitter-cs`)
- PMD xstats via `rte_eth_xstats_get_by_id()` (`--jitter-xstats`)
- Interrupt counts from `/proc/interrupts` (`--jitter-interrupts`)
- MSR reads: SMI_COUNT, APERF, MPERF (`--jitter-msr`)
- PCIe AER registers (`--jitter-aer`)

### Per-Phase Timing

Each forwarding engine records intermediate timestamps:
- **rx**: time from iteration start through `rte_eth_rx_burst()`
- **process**: time for packet processing (MAC swap, checksum, etc.)
- **tx**: time for `rte_eth_tx_burst()` to completion

This shows immediately whether a spike was caused by a slow RX (NIC/DMA
stall), slow processing (CPU-bound), or slow TX (back-pressure).

### PMD-Specific xstats (--jitter-xstats)

Automatically discovers jitter-relevant counters by pattern-matching all
available xstats against positive patterns (error, drop, miss, xon/xoff,
pci, stall, overflow, crc, timeout, etc.) and excluding false positives
(ipsec, crypto, filter management, tso, security policy).

Works across all PMD drivers without driver-specific code. Discovered
counters are listed at startup.

**Note:** On mlx5, xstats_get uses an ethtool ioctl (syscall). On ice,
xstats_get is pure MMIO (no syscall). Check your PMD.

## Anomaly Classification

Each anomaly record is classified at dump time using heuristics in
priority order:

| Classification | Detection Method |
|---------------|-----------------|
| `SMI` | SMI_COUNT MSR incremented (requires `--jitter-msr`, Intel only) |
| `KERNEL_PREEMPTION` | Context switch detected (requires `--jitter-cs`) |
| `FREQ_THROTTLE` | Hot-path: cycles_unhalted/ref_cycles < 0.80. Fallback: APERF/MPERF < 0.80 |
| `CSTATE` | TSC delta > 2x unhalted cycles (CPU was halted) |
| `PCIE_REPLAY` | AER error delta > 0 (requires `--jitter-aer`) |
| `MEMPOOL_STARVED` | rx_nombuf counter incremented |
| `NIC_OVERFLOW` | rx_missed incremented with non-empty RX ring |
| `APP_BACKLOG` | High RX ring depth with significant instructions retired |
| `MEMORY_STALL` | Many cycles but few instructions retired (IPC < 0.25) |
| `UNKNOWN` | None of the above heuristics matched |

### Key Metrics

- **cycles/inst (CPI)**: ~1-2 = CPU efficient, >4 = memory-bound,
  very high + low inst = CPU halted
- **freq ratio** (cycles_unhalted / ref_cycles): >1.0 = turbo boost,
  1.0 = base clock, <1.0 = throttled

## Output Format

### Text Format

```
=== Anomaly #42 lcore=3 port=0 queue=0 ===
  TSC start:    0x000019b3a4f12000
  TSC delta:    150.3 us  (450900 cycles)
  Phase breakdown:
    rx:           148.1 us  (444300 cycles)
    process:        0.1 us  (300 cycles)
    tx:             2.1 us  (6300 cycles)
  Classification: CSTATE
  Hot-path:
    inst_retired:    200
    cycles_unhalted: 50000
    ref_cycles:      50000
    cycles/inst:     250.00
    freq ratio:      1.00
    rx_ring_before:  32  rx_ring_after: 0  nb_rx: 32
  Cold-path:
    Scheduling:
      voluntary_cs_delta:     0
      nonvoluntary_cs_delta:  0
    CPU/Power:
      smi_count_delta:        0
      aperf/mperf ratio:      N/A
    PCIe/AER:
      correctable delta:      0
      uncorrectable delta:    0
    NIC stats:
      rx_missed_delta:        0
      rx_nombuf_delta:        0
      ierrors_delta:           0
      mempool_avail:          8128
    Interrupts:
      LOC      1
    PMD xstats:
      rx_out_of_buffer                 2
```

### CSV Format

One row per anomaly, suitable for analysis with pandas, R, etc.
Use `--jitter-output-format=csv --jitter-output=/tmp/jitter.csv`.

## Platform-Specific Notes

### AMD Systems

- **PMC (rdpmc)**: Supported. Instructions retired, unhalted cycles, and
  reference cycles counters work on AMD.
- **APERF/MPERF**: Supported. Frequency throttle detection works via
  `--jitter-msr`.
- **SMI_COUNT (MSR 0x34)**: Intel-specific. Reads return 0 on AMD.
  `JITTER_CLASS_SMI` will never trigger on AMD.

### Intel Systems

All features are fully supported.

### ARM Systems

Not supported in this version. PMC and MSR code is gated behind
`RTE_ARCH_X86_64 && RTE_EXEC_ENV_LINUX`. TSC-based threshold detection,
NIC stats, and mempool tracking still work, but `inst_retired`,
`cycles_unhalted`, and `ref_cycles` will be zero.

## Instrumented Forwarding Engines

All testpmd forwarding engines are instrumented with per-phase timing:

| Engine | File | Phases |
|--------|------|--------|
| io | iofwd.c | rx / (none) / tx |
| mac | macfwd.c | rx / mac rewrite / tx |
| macswap | macswap.c | rx / mac swap / tx |
| 5tswap | 5tswap.c | rx / 5-tuple swap / tx |
| csum | csumonly.c | rx / checksum offload / tx |
| rxonly | rxonly.c | rx only |
| txonly | txonly.c | packet generation / tx |
| flowgen | flowgen.c | rx (discard) / flow generation / tx |
| icmpecho | icmpecho.c | rx / ICMP processing / tx |
| noisy_vnf | noisy_vnf.c | rx / (varies by sub-mode) / tx |
| recycle_mbufs | recycle_mbufs.c | rx / (none) / tx |
| shared_rxq | shared_rxq_fwd.c | rx / shared queue forward |

## Troubleshooting

### inst_retired and cycles_unhalted are zero

- Check `cat /proc/sys/kernel/perf_event_paranoid` is `-1` or `1`
- Look for "PMC setup OK" or "PMC setup failed" in testpmd startup output
- On VMs, hardware PMC passthrough may not be available

### MSR open failed

- Ensure the `msr` kernel module is loaded: `sudo modprobe msr`
- Verify `/dev/cpu/N/msr` exists for the CPUs used by forwarding lcores
- testpmd must run as root or with `CAP_SYS_RAWIO`

### AER cap not found

- The NIC may not have PCIe AER capability (virtual devices, some NICs)
- The device bus type may not be PCI (e.g., vdev)
- Informational only; jitter detection works without AER

### Seeing too much measurement noise

- Run with only `--jitter-enable` (no cold-path syscall options)
- Hot-path data (PMC, TSC, phase timing) is noise-free
- Add cold-path options selectively: `--jitter-cs`, `--jitter-xstats`, etc.
- Each cold-path option causes syscalls that may trigger additional context
  switches or interrupts visible in subsequent measurements

### Too many anomalies recorded

- Increase the threshold: `jitter threshold 500` (500 us)
- The ring buffer overwrites oldest records when full; increase capacity
  with `--jitter-record-count=4096`

## Cross-Validation

To validate jitter measurements against external tools:

```bash
# Compare with perf stat
perf stat -e cycles,instructions,context-switches -p $(pgrep testpmd) sleep 10

# Check SMI counts (Intel only)
turbostat --show SMI -i 1

# Check PCIe errors
dmesg | grep -i aer
```

## Future Work: eBPF-Based Detection

The current cold-path approach has inherent limitations: any syscall-based
measurement (context switches, interrupts, xstats on some PMDs) introduces
noise that can contaminate subsequent measurements. A planned eBPF-based
approach would use kernel tracepoints (`sched:sched_switch`,
`irq:irq_handler_entry`) to log events into BPF maps that testpmd reads
via mmap — zero syscalls, zero noise. See `JITTER_EBPF_DESIGN.md` for the
full design.
