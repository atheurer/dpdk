/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Red Hat, Inc.
 *
 * Shared definitions between eBPF programs and userspace.
 * This header is compiled in two contexts:
 *   1. BPF programs (clang -target bpf)
 *   2. testpmd userspace (gcc/clang, linked with DPDK)
 * Use linux/__u* types for portability across both.
 *
 * BPF programs include vmlinux.h (which defines __u64 etc.); userspace
 * includes <linux/types.h>.  Guard the include so both work.
 */

#ifndef _JITTER_EBPF_H_
#define _JITTER_EBPF_H_

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define JITTER_EBPF_MAX_TARGETS   128
#define JITTER_EBPF_IRQ_RING_SIZE  16
#define JITTER_EBPF_INVALID_CPU    0xFFFFFFFF

/* Interrupt source types recorded by eBPF programs */
enum jitter_irq_type {
	JITTER_IRQ_DEVICE = 0,       /* irq:irq_handler_entry */
	JITTER_IRQ_LOCAL_TIMER,      /* irq_vectors:local_timer_entry */
	JITTER_IRQ_RESCHEDULE,       /* irq_vectors:reschedule_entry */
	JITTER_IRQ_CALL_FUNC,        /* irq_vectors:call_function_entry */
	JITTER_IRQ_CALL_FUNC_SINGLE, /* irq_vectors:call_function_single_entry */
	JITTER_IRQ_IRQ_WORK,         /* irq_vectors:irq_work_entry */
	JITTER_IRQ_THERMAL,          /* irq_vectors:thermal_apic_entry */
	JITTER_IRQ_THRESHOLD,        /* irq_vectors:threshold_apic_entry */
	JITTER_IRQ_DEFERRED_ERR,     /* irq_vectors:deferred_error_apic_entry */
	JITTER_IRQ_ERROR,            /* irq_vectors:error_apic_entry */
	JITTER_IRQ_SPURIOUS,         /* irq_vectors:spurious_apic_entry */
	JITTER_IRQ_X86_PLATFORM,     /* irq_vectors:x86_platform_ipi_entry */
	JITTER_IRQ_SOFTIRQ_HI,      /* irq:softirq_entry vec=0 */
	JITTER_IRQ_SOFTIRQ_TIMER,   /* irq:softirq_entry vec=1 */
	JITTER_IRQ_SOFTIRQ_NET_TX,  /* irq:softirq_entry vec=2 */
	JITTER_IRQ_SOFTIRQ_NET_RX,  /* irq:softirq_entry vec=3 */
	JITTER_IRQ_SOFTIRQ_BLOCK,   /* irq:softirq_entry vec=4 */
	JITTER_IRQ_SOFTIRQ_IRQ_POLL,/* irq:softirq_entry vec=5 */
	JITTER_IRQ_SOFTIRQ_TASKLET, /* irq:softirq_entry vec=6 */
	JITTER_IRQ_SOFTIRQ_SCHED,   /* irq:softirq_entry vec=7 */
	JITTER_IRQ_SOFTIRQ_HRTIMER, /* irq:softirq_entry vec=8 */
	JITTER_IRQ_SOFTIRQ_RCU,     /* irq:softirq_entry vec=9 */
	JITTER_IRQ_NMI,              /* nmi:nmi_handler */
	JITTER_IRQ_TYPE_MAX
};

/*
 * Per-CPU context switch state.
 * One entry per monitored CPU in jitter_cs_map.
 * BPF program writes; userspace reads via mmap.
 */
struct jitter_cs_percpu {
	__u64 seq;               /* monotonic counter, bumped on each event */
	__u64 last_switch_out;   /* ktime_ns when fwd thread was switched out */
	__u64 last_switch_in;    /* ktime_ns when fwd thread was switched back */
	__u64 total_preemptions;  /* involuntary context switches */
	__u64 total_voluntary;    /* voluntary context switches */
	__u32 last_preempt_pid;   /* PID of task that preempted us */
	__u32 _pad0;
};

/*
 * Single IRQ event within the per-CPU ring.
 */
struct jitter_irq_event {
	__u64 timestamp;         /* ktime_get_ns() */
	__u32 irq;               /* IRQ number or vector */
	__u32 type;              /* enum jitter_irq_type */
};

/*
 * Per-CPU ring buffer of recent IRQ events.
 * One entry per monitored CPU in jitter_irq_map.
 * BPF program writes; userspace reads via mmap.
 */
struct jitter_irq_ring {
	__u32 head;              /* write index (monotonic, wraps via modulo) */
	__u32 _pad0;
	struct jitter_irq_event events[JITTER_EBPF_IRQ_RING_SIZE];
};

/*
 * Configuration written by userspace, read by BPF programs.
 * Single entry in jitter_config_map (index 0).
 */
struct jitter_bpf_config {
	__u32 target_pids[JITTER_EBPF_MAX_TARGETS];
	__u32 target_cpus[JITTER_EBPF_MAX_TARGETS];
	__u32 num_targets;
	__u8  enabled;
	__u8  _pad0[3];
};

#endif /* _JITTER_EBPF_H_ */
