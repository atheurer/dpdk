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
 * Context struct for irq:irq_handler_entry tracepoint.
 * The name field uses __data_loc encoding: a 4-byte value where
 * bits [15:0] = offset from record start, bits [31:16] = length.
 */
struct irq_handler_entry_args {
	__u64 __pad;
	__s32 irq;		/* offset  8, size  4 */
	__u32 __data_loc_name;	/* offset 12, size  4 */
};

SEC("tracepoint/irq/irq_handler_entry")
int trace_irq_entry(struct irq_handler_entry_args *ctx)
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
	ring->events[idx].irq = (__u32)ctx->irq;

	/* Read the IRQ name from the __data_loc encoded field */
	{
		__u32 loc = ctx->__data_loc_name;
		__u16 off = loc & 0xFFFF;
		bpf_probe_read_str(ring->events[idx].name,
				   JITTER_EBPF_IRQ_NAME_LEN,
				   (const void *)ctx + off);
	}

	ring->head++;
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
