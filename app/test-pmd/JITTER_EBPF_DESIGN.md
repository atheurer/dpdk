# testpmd Jitter eBPF Instrumentation — Design Document

## 1. Problem Statement

The current jitter cold-path uses syscalls (`getrusage`, `/proc/interrupts`,
ethtool ioctl for mlx5 xstats) to gather diagnostic data when an anomaly is
detected. Each syscall can trigger context switches and interrupts that
contaminate subsequent measurements, creating a feedback loop: measuring
jitter causes jitter.

This document describes an eBPF-based approach that eliminates cold-path
syscalls entirely. eBPF programs run in kernel context at tracepoint fire
time, write to shared-memory maps, and testpmd reads those maps from
userspace via `mmap` — no syscalls, no interrupts, no measurement noise.

## 2. Architecture Overview

```
+------------------+       +-------------------+
|   testpmd        |       |   Linux Kernel     |
|   (userspace)    |       |                   |
|                  |       |  eBPF programs     |
|  jitter_iter_end |       |  attached to:      |
|    |             |       |   sched_switch     |
|    v             |       |   irq_handler_entry|
|  anomaly?        |       |   irq_handler_exit |
|    |             |       |   softirq_entry    |
|    v             |       |                   |
|  read BPF maps   |<----->|  BPF maps          |
|  (mmap, no       |  mmap |  (per-CPU arrays)  |
|   syscall)       |       |                   |
+------------------+       +-------------------+
```

### Key Properties

- eBPF programs fire synchronously at kernel events — no sampling, no delay
- BPF array maps can be `mmap`'d into userspace (Linux >= 5.5)
- Reading an mmap'd BPF map is a plain memory load — no syscall, no interrupt
- eBPF programs are JIT-compiled and run with near-zero overhead
- Programs are loaded/attached at testpmd startup, detached at exit

## 3. BPF Programs

### 3.1 Context Switch Tracker

Attached to `sched:sched_switch` tracepoint.

```
tracepoint/sched/sched_switch
```

**Purpose:** Record when the forwarding thread is switched out and back in.

**Logic:**
```c
struct jitter_cs_event {
    u64 timestamp;      /* ktime_get_ns() when switch happened */
    u32 prev_pid;       /* PID switched away from */
    u32 next_pid;       /* PID switched to */
    u32 prev_state;     /* previous task state (TASK_RUNNING, etc.) */
    u8  voluntary;      /* 1 if prev_state != TASK_RUNNING */
};

SEC("tracepoint/sched/sched_switch")
int trace_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    u32 cpu = bpf_get_smp_processor_id();
    u32 *target_pids;  /* array of forwarding thread PIDs to watch */

    /* Only record if prev_pid or next_pid is a forwarding thread */
    if (!is_target_pid(ctx->prev_pid) && !is_target_pid(ctx->next_pid))
        return 0;

    struct jitter_cs_event *event = get_per_cpu_slot(cpu);
    event->timestamp = bpf_ktime_get_ns();
    event->prev_pid = ctx->prev_pid;
    event->next_pid = ctx->next_pid;
    event->prev_state = ctx->prev_state;
    event->voluntary = (ctx->prev_state != TASK_RUNNING);

    increment_per_cpu_counter(cpu);  /* bump a sequence counter */
    return 0;
}
```

**BPF Map:** `BPF_MAP_TYPE_ARRAY`, per-CPU indexed. Each CPU slot holds
the most recent context switch event and a monotonic counter. testpmd
reads the counter to detect changes, then reads the event data.

### 3.2 Interrupt Tracker

Attached to `irq:irq_handler_entry` tracepoint.

```
tracepoint/irq/irq_handler_entry
```

**Purpose:** Record which interrupt fired on the forwarding CPU.

**Logic:**
```c
struct jitter_irq_event {
    u64 timestamp;
    u32 irq;            /* IRQ number */
    char name[16];      /* IRQ name from tracepoint args */
};

#define JITTER_IRQ_RING_SIZE 16  /* per-CPU ring of recent IRQs */

struct jitter_irq_ring {
    u32 head;           /* write index (monotonic) */
    struct jitter_irq_event events[JITTER_IRQ_RING_SIZE];
};

SEC("tracepoint/irq/irq_handler_entry")
int trace_irq_entry(struct trace_event_raw_irq_handler_entry *ctx)
{
    u32 cpu = bpf_get_smp_processor_id();

    /* Only track CPUs that are running forwarding threads */
    if (!is_target_cpu(cpu))
        return 0;

    struct jitter_irq_ring *ring = get_per_cpu_ring(cpu);
    u32 idx = ring->head % JITTER_IRQ_RING_SIZE;
    ring->events[idx].timestamp = bpf_ktime_get_ns();
    ring->events[idx].irq = ctx->irq;
    bpf_probe_read_str(ring->events[idx].name, 16, ctx->name);
    ring->head++;

    return 0;
}
```

**BPF Map:** `BPF_MAP_TYPE_ARRAY`, per-CPU indexed. Each slot is a small
ring buffer of recent IRQ events. testpmd reads the ring on the cold path
to see which interrupts fired since the last read.

### 3.3 Softirq Tracker (optional)

Attached to `irq:softirq_entry` tracepoint.

**Purpose:** Detect softirq processing on the forwarding CPU (network RX
softirq, timer softirq, RCU callbacks, etc.).

**Logic:** Similar to the IRQ tracker but records the softirq vector
(NET_RX, TIMER, RCU, etc.).

## 4. BPF Map Design

### 4.1 Map Types

Use `BPF_MAP_TYPE_ARRAY` for all maps. Array maps support `mmap` (since
Linux 5.5) and have O(1) lookup by index. Each map is indexed by CPU
number.

```
Map: jitter_cs_map
  Type: BPF_MAP_TYPE_ARRAY
  Key size: 4 (u32 cpu)
  Value size: sizeof(struct jitter_cs_percpu)
  Max entries: number of forwarding CPUs
  Flags: BPF_F_MMAPABLE

Map: jitter_irq_map
  Type: BPF_MAP_TYPE_ARRAY
  Key size: 4 (u32 cpu)
  Value size: sizeof(struct jitter_irq_ring)
  Max entries: number of forwarding CPUs
  Flags: BPF_F_MMAPABLE

Map: jitter_config_map
  Type: BPF_MAP_TYPE_ARRAY
  Key size: 4
  Value size: sizeof(struct jitter_bpf_config)
  Max entries: 1
  Flags: BPF_F_MMAPABLE
```

### 4.2 Per-CPU Context Switch State

```c
struct jitter_cs_percpu {
    u64 seq;            /* monotonic counter, bumped on each event */
    u64 last_switch_out; /* ktime_ns when forwarding thread was switched out */
    u64 last_switch_in;  /* ktime_ns when forwarding thread was switched back */
    u64 total_preemptions; /* total count of involuntary switches */
    u64 total_voluntary;   /* total count of voluntary switches */
    u32 last_preempt_pid;  /* PID of task that preempted us */
};
```

testpmd saves `seq` after each cold-path read. On the next anomaly, if
`seq` changed, context switches happened since the last check. The delta
of `total_preemptions` gives the count without any syscall noise.

### 4.3 Configuration Map

```c
struct jitter_bpf_config {
    u32 target_pids[RTE_MAX_LCORE];  /* PIDs of forwarding threads */
    u32 target_cpus[RTE_MAX_LCORE];  /* CPUs to monitor */
    u32 num_targets;
    u8  enabled;
};
```

Written by testpmd at init and updated when forwarding starts/stops.
Read by eBPF programs to filter events.

## 5. Userspace Integration

### 5.1 File Layout

```
app/test-pmd/
  jitter_ebpf.c       # loader, map setup, mmap, cold-path readers
  jitter_ebpf.h       # shared structures between BPF programs and userspace
  jitter_ebpf_progs/   # BPF program source (compiled separately)
    sched_switch.bpf.c
    irq_entry.bpf.c
    softirq_entry.bpf.c
```

### 5.2 Initialization Flow

```c
int jitter_ebpf_init(void)
{
    /* 1. Open and load BPF object file (pre-compiled .o or skeleton) */
    skel = jitter_bpf__open_and_load();

    /* 2. Get map FDs */
    cs_map_fd = bpf_map__fd(skel->maps.jitter_cs_map);
    irq_map_fd = bpf_map__fd(skel->maps.jitter_irq_map);
    config_map_fd = bpf_map__fd(skel->maps.jitter_config_map);

    /* 3. mmap the maps into userspace */
    cs_mmap = mmap(NULL, map_size, PROT_READ, MAP_SHARED, cs_map_fd, 0);
    irq_mmap = mmap(NULL, map_size, PROT_READ, MAP_SHARED, irq_map_fd, 0);
    config_mmap = mmap(NULL, map_size, PROT_READ | PROT_WRITE,
                       MAP_SHARED, config_map_fd, 0);

    /* 4. Write target PIDs/CPUs to config map */
    config_mmap->target_pids[0] = gettid();  /* per lcore */
    config_mmap->num_targets = ...;
    config_mmap->enabled = 1;

    /* 5. Attach BPF programs to tracepoints */
    jitter_bpf__attach(skel);

    return 0;
}
```

### 5.3 Cold-Path Reading (no syscall)

```c
void jitter_ebpf_read_cs(struct jitter_lcore_ctx *ctx,
                          struct jitter_record *r)
{
    int cpu_idx = ctx->ebpf_cpu_idx;
    struct jitter_cs_percpu *cs = &cs_mmap[cpu_idx];

    /* Pure memory read — no syscall */
    if (cs->seq != ctx->last_cs_seq) {
        r->voluntary_cs_delta = cs->total_voluntary - ctx->last_voluntary_cs;
        r->nonvoluntary_cs_delta = cs->total_preemptions -
                                    ctx->last_nonvoluntary_cs;
        ctx->last_voluntary_cs = cs->total_voluntary;
        ctx->last_nonvoluntary_cs = cs->total_preemptions;
        ctx->last_cs_seq = cs->seq;
    }
}

void jitter_ebpf_read_irqs(struct jitter_lcore_ctx *ctx,
                            struct jitter_record *r)
{
    int cpu_idx = ctx->ebpf_cpu_idx;
    struct jitter_irq_ring *ring = &irq_mmap[cpu_idx];

    /* Read new entries since last check */
    while (ctx->last_irq_head != ring->head) {
        u32 idx = ctx->last_irq_head % JITTER_IRQ_RING_SIZE;
        /* Record IRQ number and name in anomaly record */
        ...
        ctx->last_irq_head++;
    }
}
```

### 5.4 CLI Integration

New option: `--jitter-ebpf`

Enables eBPF-based context switch and interrupt tracking. Replaces
`--jitter-cs` and `--jitter-interrupts` with zero-noise equivalents.

Requires:
- Linux >= 5.5 (BPF_F_MMAPABLE support)
- `CAP_BPF` or `CAP_SYS_ADMIN` (for loading BPF programs)
- libbpf (build dependency)

## 6. Build Integration

### 6.1 BPF Program Compilation

BPF programs are compiled with clang to BPF bytecode:

```bash
clang -target bpf -O2 -g -c sched_switch.bpf.c -o sched_switch.bpf.o
```

Use bpftool to generate a skeleton header:

```bash
bpftool gen skeleton sched_switch.bpf.o > jitter_bpf.skel.h
```

### 6.2 Meson Integration

```meson
# Check for libbpf
libbpf_dep = dependency('libbpf', required: false)

if libbpf_dep.found() and is_linux
    # Add eBPF support
    sources += files('jitter_ebpf.c')
    ext_deps += libbpf_dep
    cflags += '-DJITTER_HAS_EBPF'

    # BPF program compilation (custom target)
    bpf_progs = custom_target('jitter_bpf_progs',
        input: files('jitter_ebpf_progs/sched_switch.bpf.c',
                     'jitter_ebpf_progs/irq_entry.bpf.c'),
        output: 'jitter_bpf.skel.h',
        command: [bpf_compile_script, '@INPUT@', '@OUTPUT@'],
    )
endif
```

### 6.3 Build Dependencies

```
# Fedora/RHEL:
sudo dnf install libbpf-devel clang bpftool

# Ubuntu/Debian:
sudo apt install libbpf-dev clang linux-tools-common
```

## 7. Runtime Requirements

- **Linux kernel >= 5.5**: Required for `BPF_F_MMAPABLE` array maps
- **CAP_BPF** (or CAP_SYS_ADMIN): Required to load BPF programs. testpmd
  typically runs as root for hugepage/DPDK access, so this is usually met.
- **BTF support**: Kernel must be compiled with `CONFIG_DEBUG_INFO_BTF=y`
  for CO-RE (Compile Once Run Everywhere) BPF programs. Most modern distro
  kernels have this enabled.
- **Tracepoints available**: `sched:sched_switch` and `irq:irq_handler_entry`
  must be available. Check with:
  ```bash
  ls /sys/kernel/debug/tracing/events/sched/sched_switch
  ls /sys/kernel/debug/tracing/events/irq/irq_handler_entry
  ```

## 8. Data Flow — Step by Step

1. **testpmd startup** (`--jitter-enable --jitter-ebpf`):
   - Load BPF programs via libbpf skeleton
   - Create BPF maps with `BPF_F_MMAPABLE`
   - `mmap()` maps into testpmd address space
   - Write forwarding thread PIDs and CPU IDs to config map
   - Attach BPF programs to tracepoints

2. **Kernel event fires** (e.g., `sched_switch` on forwarding CPU):
   - BPF program executes (JIT-compiled, ~50-100ns)
   - Checks config map: is this a target PID/CPU?
   - If yes: writes event data to per-CPU array map slot
   - Increments sequence counter

3. **testpmd hot path** (every iteration):
   - No change — TSC, rdpmc, rx_queue_count as before
   - Threshold check triggers cold path

4. **testpmd cold path** (anomaly detected):
   - Read mmap'd BPF maps — **plain memory load, no syscall**
   - Compare sequence counters to detect changes
   - Compute deltas for context switches and interrupts
   - Store in anomaly record

5. **testpmd exit**:
   - Detach BPF programs from tracepoints
   - Destroy BPF maps (munmap + close fd)
   - Free skeleton

## 9. Advantages Over Current Approach

| Aspect | Current (syscall) | eBPF (mmap) |
|--------|-------------------|-------------|
| Context switch read | `getrusage()` — 1 syscall | Memory load — 0 syscalls |
| Interrupt read | `/proc/interrupts` — fopen/fread/fclose | Memory load — 0 syscalls |
| Measurement noise | Each read may trigger CS/IRQ | Zero noise |
| Data freshness | Accumulated since last anomaly | Per-event, with timestamps |
| Event detail | Count only | Timestamp, PID, IRQ number, name |
| Kernel overhead | Zero (events not tracked) | ~50-100ns per tracepoint fire |
| Setup complexity | None | BPF load + attach |
| Privileges | Basic | CAP_BPF |
| Kernel version | Any | >= 5.5 |

## 10. Implementation Checklist

For the implementer to work through in order:

- [ ] Create shared header `jitter_ebpf.h` with struct definitions used by
      both BPF programs and userspace (event structs, config struct, map
      layout, ring buffer sizes)
- [ ] Create BPF program `sched_switch.bpf.c` — filter by target PID,
      write to per-CPU array map, bump sequence counter
- [ ] Create BPF program `irq_entry.bpf.c` — filter by target CPU, write
      to per-CPU IRQ ring buffer
- [ ] Create `jitter_ebpf.c` — libbpf skeleton loader, mmap setup,
      cold-path readers (`jitter_ebpf_read_cs`, `jitter_ebpf_read_irqs`),
      init/fini functions
- [ ] Add `--jitter-ebpf` CLI option to `parameters.c`
- [ ] Integrate eBPF cold-path readers into `jitter_record_anomaly()` —
      use eBPF path when available, fall back to syscall path
- [ ] Update meson.build — libbpf dependency, BPF program compilation,
      skeleton generation
- [ ] Update anomaly record struct — add fields for eBPF-sourced data
      (preempting PID, IRQ number/name with timestamps)
- [ ] Update report output — show eBPF-sourced interrupt and CS data
      with timestamps
- [ ] Update classification heuristics — use eBPF CS data for
      `JITTER_CLASS_KERNEL_PREEMPTION` when available
- [ ] Test: verify zero-noise by running with only `--jitter-ebpf` and
      checking that no cold-path syscalls appear in strace
- [ ] Test: verify BPF programs load on RHEL 8/9 and Fedora kernels
- [ ] Fallback: gracefully disable eBPF if BPF load fails (kernel too old,
      insufficient privileges, BTF not available)

## 11. Open Questions

1. **BPF program distribution**: Ship pre-compiled `.bpf.o` files, or
   compile from source at build time? Pre-compiled is simpler but requires
   CO-RE for portability across kernel versions. Compiling from source
   requires clang at build time.

2. **libbpf version**: Minimum libbpf version needed for BPF_F_MMAPABLE
   and skeleton support. libbpf >= 0.5 should work.

3. **Multiple forwarding threads**: The config map needs to hold all
   forwarding thread PIDs. These are known after `start_packet_forwarding()`
   but the BPF programs are loaded at init. Solution: load programs at init,
   populate config map at forwarding start (the mmap is writable).

4. **BPF program size limits**: The `sched_switch` tracepoint fires very
   frequently on busy systems. The BPF program must be extremely fast
   (~50ns) and the PID filter must be the first check to bail out early
   for non-target threads.

5. **Security**: BPF programs have read access to kernel memory via
   tracepoint arguments. The programs only read PID, CPU, IRQ number, and
   timestamp — no sensitive data. However, `CAP_BPF` is still required.
