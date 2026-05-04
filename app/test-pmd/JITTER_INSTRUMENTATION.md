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
performance counters (instructions retired, CPU cycles). This requires:

```bash
sudo sysctl kernel.perf_event_paranoid=-1
```

Or more conservatively (allows per-process counters only):
```bash
sudo sysctl kernel.perf_event_paranoid=1
```

If this is not set, PMC setup will fail and the `inst_retired` and
`cycles_unhalted` fields in anomaly records will be zero. The TSC-based
threshold detection still works without PMC access.

### Optional: MSR access (--jitter-msr)

Enables reading APERF/MPERF (frequency ratio) and SMI_COUNT MSRs.

```bash
sudo modprobe msr
```

testpmd must be run as root or with read access to `/dev/cpu/N/msr`.

### Optional: PCIe AER (--jitter-aer)

Enables reading PCIe Advanced Error Reporting registers on anomaly.
No additional setup beyond standard DPDK device binding (vfio-pci).

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

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--jitter-enable` | flag | off | Enable jitter instrumentation |
| `--jitter-threshold-us=N` | uint | 100 | Anomaly threshold in microseconds |
| `--jitter-record-count=N` | uint | 1024 | Per-lcore anomaly ring buffer size |
| `--jitter-msr` | flag | off | Enable MSR reads (APERF/MPERF, SMI count) |
| `--jitter-aer` | flag | off | Enable PCIe AER register reads on anomaly |
| `--jitter-output=PATH` | string | stderr | Output file for anomaly dump |
| `--jitter-output-format=FMT` | string | text | Output format: `text` or `csv` |

## Runtime Commands

At the `testpmd>` prompt:

| Command | Description |
|---------|-------------|
| `jitter show` | Print per-lcore summary (iterations, anomalies, max latency) |
| `jitter dump` | Write all captured anomaly records to output |
| `jitter reset` | Clear all per-lcore ring buffers and counters |
| `jitter threshold <us>` | Change anomaly threshold at runtime |
| `jitter set output <path>` | Change output file path |

## How It Works

### Hot Path (every iteration)

These measurements run on every forwarding loop iteration, regardless of
whether an anomaly is detected:

- `rte_rdtsc()` at iteration start and end (TSC timestamps)
- `rdpmc` x2 at iteration start (instructions retired, unhalted CPU cycles)
- `rte_eth_rx_queue_count()` at iteration start (RX ring depth)
- One branch comparing TSC delta to threshold

Estimated overhead: ~100-150 cycles per iteration when no anomaly occurs.

### Cold Path (anomaly only)

When the iteration time exceeds the threshold, additional diagnostic data
is captured:

- Per-thread context switch counters (`/proc/self/task/<tid>/status`)
- NIC stats deltas (imissed, rx_nombuf, ierrors) via `rte_eth_stats_get()`
- Mempool available count
- MSR reads: SMI_COUNT, APERF, MPERF (if `--jitter-msr`)
- PCIe AER correctable/uncorrectable status (if `--jitter-aer`)

All cold-path data is written to a per-lcore ring buffer (oldest records
are overwritten when full).

## Anomaly Classification

Each anomaly record is classified at dump time using heuristics applied
in priority order:

| Classification | Detection Method |
|---------------|-----------------|
| `SMI` | SMI_COUNT MSR incremented during the iteration |
| `KERNEL_PREEMPTION` | Voluntary or involuntary context switch detected |
| `FREQ_THROTTLE` | APERF/MPERF ratio below 80% |
| `CSTATE` | TSC delta > 2x unhalted cycles (CPU was halted) |
| `PCIE_REPLAY` | AER correctable or uncorrectable error delta > 0 |
| `MEMPOOL_STARVED` | rx_nombuf counter incremented |
| `NIC_OVERFLOW` | rx_missed incremented with non-empty RX ring |
| `APP_BACKLOG` | High RX ring depth with significant instructions retired |
| `MEMORY_STALL` | Many cycles but few instructions retired (IPC < 0.25) |
| `UNKNOWN` | None of the above heuristics matched |

## Output Formats

### Text Format

Human-readable, one block per anomaly:

```
=== Anomaly #42 lcore=3 port=0 queue=0 ===
  TSC start:    0x000019b3a4f12000
  TSC delta:    150.3 us  (450900 cycles)
  Classification: KERNEL_PREEMPTION
  Hot-path:
    inst_retired:    1234
    cycles_unhalted: 250000
    rx_ring_before:  32  rx_ring_after: 0  nb_rx: 32
  Cold-path:
    smi_count_delta:        0
    voluntary_cs_delta:     0
    nonvoluntary_cs_delta:  1
    aperf/mperf ratio:      0.99
    AER correctable delta:  0
    AER uncorrectable delta: 0
    rx_missed_delta:        0
    rx_nombuf_delta:        0
    ierrors_delta:           0
    mempool_avail:          8128
```

### CSV Format

One row per anomaly, suitable for analysis with pandas, R, etc.
Use `--jitter-output-format=csv --jitter-output=/tmp/jitter.csv`.

## Platform-Specific Notes

### AMD Systems

- **APERF/MPERF**: Supported. Frequency throttle detection works.
- **SMI_COUNT (MSR 0x34)**: This MSR is Intel-specific. On AMD, reads
  return 0 and SMI events will not be detected. The `JITTER_CLASS_SMI`
  classification will never trigger on AMD.
- **PMC (rdpmc)**: Supported. Instructions retired and unhalted cycles
  counters work on AMD.

### Intel Systems

All features are fully supported.

### ARM Systems

Not supported in this version. PMC and MSR code is gated behind
`RTE_ARCH_X86_64 && RTE_EXEC_ENV_LINUX`. The TSC-based threshold
detection, NIC stats, and context switch attribution still work, but
`inst_retired` and `cycles_unhalted` will be zero.

## Instrumented Forwarding Engines

Currently instrumented:
- `io` (iofwd.c)

Remaining engines will be instrumented in subsequent commits:
macfwd, macswap, csumonly, rxonly, txonly, 5tswap, flowgen, icmpecho,
noisy_vnf, recycle_mbufs, shared_rxq_fwd.

## Troubleshooting

### inst_retired and cycles_unhalted are zero

- Check `cat /proc/sys/kernel/perf_event_paranoid` is `-1` or `1`.
- Look for "PMC setup failed" or "PMC setup OK" in testpmd startup output.
- On VMs, hardware PMC passthrough may not be available.

### MSR open failed

- Ensure the `msr` kernel module is loaded: `sudo modprobe msr`
- Verify `/dev/cpu/N/msr` exists for the CPUs used by forwarding lcores.
- testpmd must run as root or with `CAP_SYS_RAWIO`.

### AER cap not found

- The NIC may not have PCIe AER capability (virtual devices, some NICs).
- The device bus type may not be PCI (e.g., vdev).
- This is informational; jitter detection works without AER.

### Too many anomalies recorded

- Increase the threshold: `jitter threshold 500` (500 us).
- The ring buffer overwrites oldest records when full; increase capacity
  with `--jitter-record-count=4096`.

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
