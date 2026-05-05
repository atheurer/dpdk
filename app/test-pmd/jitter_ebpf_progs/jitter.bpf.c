/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Red Hat, Inc.
 *
 * eBPF programs for testpmd jitter instrumentation.
 *
 * trace_sched_switch  — context switch tracker (sched:sched_switch)
 * trace_irq_entry     — interrupt tracker (irq:irq_handler_entry)
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "../jitter_ebpf.h"

/* TASK_RUNNING == 0 in all kernel versions */
#define TASK_RUNNING 0

/* vmlinux.h doesn't include UAPI constants; use kernel header value */
#ifndef BPF_F_MMAPABLE
#define BPF_F_MMAPABLE (1U << 10)
#endif

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, JITTER_EBPF_MAX_TARGETS);
	__type(key, __u32);
	__type(value, struct jitter_cs_percpu);
	__uint(map_flags, BPF_F_MMAPABLE);
} jitter_cs_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, JITTER_EBPF_MAX_TARGETS);
	__type(key, __u32);
	__type(value, struct jitter_irq_ring);
	__uint(map_flags, BPF_F_MMAPABLE);
} jitter_irq_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct jitter_bpf_config);
	__uint(map_flags, BPF_F_MMAPABLE);
} jitter_config_map SEC(".maps");

static __always_inline int
find_target_slot(const struct jitter_bpf_config *cfg, __u32 pid)
{
	__u32 i;

	/* PID 0 is the idle task — never a forwarding thread.
	 * Also guards against matching uninitialized (zero) slots. */
	if (pid == 0)
		return -1;

	for (i = 0; i < JITTER_EBPF_MAX_TARGETS; i++) {
		if (i >= cfg->num_targets)
			return -1;
		if (cfg->target_pids[i] == pid)
			return i;
	}
	return -1;
}

/*
 * Context struct matching /sys/kernel/tracing/events/sched/sched_switch/format.
 * Fields start after the 8-byte common header (common_type, common_flags,
 * common_preempt_count, common_pid).
 */
struct sched_switch_args {
	__u64 __pad;
	char prev_comm[16];	/* offset  8, size 16 */
	__s32 prev_pid;		/* offset 24, size  4 */
	__s32 prev_prio;	/* offset 28, size  4 */
	__s64 prev_state;	/* offset 32, size  8 */
	char next_comm[16];	/* offset 40, size 16 */
	__s32 next_pid;		/* offset 56, size  4 */
	__s32 next_prio;	/* offset 60, size  4 */
};

SEC("tracepoint/sched/sched_switch")
int trace_sched_switch(struct sched_switch_args *ctx)
{
	__u32 zero = 0;
	struct jitter_bpf_config *cfg;
	struct jitter_cs_percpu *cs;
	__u64 now;
	__u32 prev_pid, next_pid;
	int slot;

	cfg = bpf_map_lookup_elem(&jitter_config_map, &zero);
	if (!cfg || !cfg->enabled)
		return 0;

	prev_pid = (__u32)ctx->prev_pid;
	next_pid = (__u32)ctx->next_pid;

	/* Check if the forwarding thread is being switched OUT */
	slot = find_target_slot(cfg, prev_pid);
	if (slot >= 0) {
		__u32 key = (__u32)slot;

		cs = bpf_map_lookup_elem(&jitter_cs_map, &key);
		if (cs) {
			now = bpf_ktime_get_ns();
			cs->last_switch_out = now;
			cs->last_preempt_pid = next_pid;

			if (ctx->prev_state == TASK_RUNNING)
				cs->total_preemptions++;
			else
				cs->total_voluntary++;

			cs->seq++;
		}
		return 0;
	}

	/* Check if the forwarding thread is being switched IN */
	slot = find_target_slot(cfg, next_pid);
	if (slot >= 0) {
		__u32 key = (__u32)slot;

		cs = bpf_map_lookup_elem(&jitter_cs_map, &key);
		if (cs)
			cs->last_switch_in = bpf_ktime_get_ns();
	}

	return 0;
}

/* --- IRQ tracker --- */

static __always_inline int
find_cpu_slot(const struct jitter_bpf_config *cfg, __u32 cpu)
{
	__u32 i;

	for (i = 0; i < JITTER_EBPF_MAX_TARGETS; i++) {
		if (i >= cfg->num_targets)
			return -1;
		if (cfg->target_cpus[i] != JITTER_EBPF_INVALID_CPU &&
		    cfg->target_cpus[i] == cpu)
			return i;
	}
	return -1;
}

/*
 * Common helper: record an interrupt event in the per-CPU ring.
 */
static __always_inline int
record_irq(int vector, __u32 type)
{
	__u32 zero = 0;
	struct jitter_bpf_config *cfg;
	struct jitter_irq_ring *ring;
	__u32 cpu, idx;
	int slot;

	cfg = bpf_map_lookup_elem(&jitter_config_map, &zero);
	if (!cfg || !cfg->enabled)
		return 0;

	cpu = bpf_get_smp_processor_id();
	slot = find_cpu_slot(cfg, cpu);
	if (slot < 0)
		return 0;

	__u32 key = (__u32)slot;
	ring = bpf_map_lookup_elem(&jitter_irq_map, &key);
	if (!ring)
		return 0;

	idx = ring->head % JITTER_EBPF_IRQ_RING_SIZE;
	ring->events[idx].timestamp = bpf_ktime_get_ns();
	ring->events[idx].irq = (__u32)vector;
	ring->events[idx].type = type;
	ring->head++;
	return 0;
}

/* irq:irq_handler_entry — device-line IRQs */
struct irq_handler_entry_args {
	__u64 __pad;
	__s32 irq;		/* offset  8, size  4 */
};

SEC("tracepoint/irq/irq_handler_entry")
int trace_irq_entry(struct irq_handler_entry_args *ctx)
{
	return record_irq(ctx->irq, JITTER_IRQ_DEVICE);
}

/* irq_vectors tracepoints all share the same format: int vector at offset 8 */
struct irq_vector_args {
	__u64 __pad;
	__s32 vector;		/* offset  8, size  4 */
};

#define DEFINE_VECTOR_HANDLER(tp_name, irq_type)			\
SEC("tracepoint/irq_vectors/" #tp_name)					\
int trace_##tp_name(struct irq_vector_args *ctx)			\
{									\
	return record_irq(ctx->vector, irq_type);			\
}

DEFINE_VECTOR_HANDLER(local_timer_entry, JITTER_IRQ_LOCAL_TIMER)
DEFINE_VECTOR_HANDLER(reschedule_entry, JITTER_IRQ_RESCHEDULE)
DEFINE_VECTOR_HANDLER(call_function_entry, JITTER_IRQ_CALL_FUNC)
DEFINE_VECTOR_HANDLER(call_function_single_entry, JITTER_IRQ_CALL_FUNC_SINGLE)
DEFINE_VECTOR_HANDLER(irq_work_entry, JITTER_IRQ_IRQ_WORK)
DEFINE_VECTOR_HANDLER(thermal_apic_entry, JITTER_IRQ_THERMAL)
DEFINE_VECTOR_HANDLER(threshold_apic_entry, JITTER_IRQ_THRESHOLD)
DEFINE_VECTOR_HANDLER(deferred_error_apic_entry, JITTER_IRQ_DEFERRED_ERR)
DEFINE_VECTOR_HANDLER(error_apic_entry, JITTER_IRQ_ERROR)
DEFINE_VECTOR_HANDLER(spurious_apic_entry, JITTER_IRQ_SPURIOUS)
DEFINE_VECTOR_HANDLER(x86_platform_ipi_entry, JITTER_IRQ_X86_PLATFORM)

/* irq:softirq_entry — softirq processing after hardware interrupt */
struct softirq_entry_args {
	__u64 __pad;
	__u32 vec;		/* offset  8, size  4 */
};

SEC("tracepoint/irq/softirq_entry")
int trace_softirq_entry(struct softirq_entry_args *ctx)
{
	__u32 type = JITTER_IRQ_SOFTIRQ_HI + ctx->vec;

	if (type >= JITTER_IRQ_TYPE_MAX)
		type = JITTER_IRQ_SOFTIRQ_HI;
	return record_irq(ctx->vec, type);
}

/* nmi:nmi_handler — non-maskable interrupts */
struct nmi_handler_args {
	__u64 __pad;
	__u64 handler;		/* offset  8, size  8 (void *) */
	__s64 delta_ns;		/* offset 16, size  8 */
	__s32 handled;		/* offset 24, size  4 */
};

SEC("tracepoint/nmi/nmi_handler")
int trace_nmi_handler(struct nmi_handler_args *ctx __attribute__((unused)))
{
	return record_irq(0, JITTER_IRQ_NMI);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
