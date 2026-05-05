/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Red Hat, Inc.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include <bpf/libbpf.h>

#include <rte_common.h>
#include <rte_log.h>

#include "testpmd.h"
#include "jitter.h"
#include "jitter_ebpf.h"
#include "jitter_ebpf_progs/jitter.skel.h"

static struct jitter_bpf *skel;
static struct jitter_bpf_config *config_mmap;
static volatile struct jitter_cs_percpu *cs_mmap;
static volatile struct jitter_irq_ring *irq_mmap;
static size_t config_mmap_sz;
static size_t cs_mmap_sz;
static size_t irq_mmap_sz;

static pid_t
get_tid(void)
{
	return (pid_t)syscall(SYS_gettid);
}

int
jitter_ebpf_init(void)
{
	int config_fd, cs_fd, irq_fd;

	skel = jitter_bpf__open_and_load();
	if (!skel) {
		TESTPMD_LOG(WARNING,
			    "eBPF: failed to load programs: %s\n",
			    strerror(errno));
		return -1;
	}

	config_fd = bpf_map__fd(skel->maps.jitter_config_map);
	cs_fd = bpf_map__fd(skel->maps.jitter_cs_map);
	irq_fd = bpf_map__fd(skel->maps.jitter_irq_map);
	if (config_fd < 0 || cs_fd < 0 || irq_fd < 0) {
		TESTPMD_LOG(WARNING, "eBPF: failed to get map FDs\n");
		goto fail;
	}

	config_mmap_sz = sizeof(struct jitter_bpf_config);
	config_mmap = mmap(NULL, config_mmap_sz, PROT_READ | PROT_WRITE,
			   MAP_SHARED, config_fd, 0);
	if (config_mmap == MAP_FAILED) {
		TESTPMD_LOG(WARNING, "eBPF: mmap config map failed: %s\n",
			    strerror(errno));
		config_mmap = NULL;
		goto fail;
	}

	cs_mmap_sz = sizeof(struct jitter_cs_percpu) * JITTER_EBPF_MAX_TARGETS;
	cs_mmap = mmap(NULL, cs_mmap_sz, PROT_READ, MAP_SHARED, cs_fd, 0);
	if (cs_mmap == MAP_FAILED) {
		TESTPMD_LOG(WARNING, "eBPF: mmap cs map failed: %s\n",
			    strerror(errno));
		cs_mmap = NULL;
		goto fail;
	}

	irq_mmap_sz = sizeof(struct jitter_irq_ring) * JITTER_EBPF_MAX_TARGETS;
	irq_mmap = mmap(NULL, irq_mmap_sz, PROT_READ, MAP_SHARED, irq_fd, 0);
	if (irq_mmap == MAP_FAILED) {
		TESTPMD_LOG(WARNING, "eBPF: mmap irq map failed: %s\n",
			    strerror(errno));
		irq_mmap = NULL;
		goto fail;
	}

	memset(config_mmap, 0, sizeof(*config_mmap));
	for (int i = 0; i < JITTER_EBPF_MAX_TARGETS; i++)
		config_mmap->target_cpus[i] = JITTER_EBPF_INVALID_CPU;

	if (jitter_bpf__attach(skel) != 0) {
		TESTPMD_LOG(WARNING, "eBPF: failed to attach programs: %s\n",
			    strerror(errno));
		goto fail;
	}

	TESTPMD_LOG(NOTICE,
		    "eBPF: sched_switch + irq_handler_entry loaded and attached\n");
	return 0;

fail:
	if (irq_mmap) {
		munmap(irq_mmap, irq_mmap_sz);
		irq_mmap = NULL;
	}
	if (cs_mmap) {
		munmap(cs_mmap, cs_mmap_sz);
		cs_mmap = NULL;
	}
	if (config_mmap) {
		munmap(config_mmap, config_mmap_sz);
		config_mmap = NULL;
	}
	jitter_bpf__destroy(skel);
	skel = NULL;
	return -1;
}

void
jitter_ebpf_fini(void)
{
	if (skel) {
		jitter_bpf__detach(skel);
		if (irq_mmap) {
			munmap(irq_mmap, irq_mmap_sz);
			irq_mmap = NULL;
		}
		if (cs_mmap) {
			munmap(cs_mmap, cs_mmap_sz);
			cs_mmap = NULL;
		}
		if (config_mmap) {
			config_mmap->enabled = 0;
			munmap(config_mmap, config_mmap_sz);
			config_mmap = NULL;
		}
		jitter_bpf__destroy(skel);
		skel = NULL;
		TESTPMD_LOG(NOTICE, "eBPF: programs detached and unloaded\n");
	}
}

int
jitter_ebpf_register_lcore(int slot, pid_t tid, int cpu)
{
	if (!config_mmap || slot < 0 || slot >= JITTER_EBPF_MAX_TARGETS)
		return -1;

	config_mmap->target_pids[slot] = (__u32)tid;
	config_mmap->target_cpus[slot] = (__u32)cpu;

	__sync_synchronize();

	if ((__u32)(slot + 1) > config_mmap->num_targets)
		config_mmap->num_targets = (__u32)(slot + 1);
	config_mmap->enabled = 1;

	TESTPMD_LOG(NOTICE,
		    "eBPF: registered lcore slot %d tid %d cpu %d\n",
		    slot, (int)tid, cpu);
	return slot;
}

void
jitter_ebpf_read_cs(struct jitter_lcore_ctx *ctx, struct jitter_record *r)
{
	int slot = ctx->ebpf_slot;
	const volatile struct jitter_cs_percpu *cs;
	uint64_t seq, vol, preempt;

	if (!cs_mmap || slot < 0 || slot >= JITTER_EBPF_MAX_TARGETS)
		return;

	cs = &cs_mmap[slot];

	/* Snapshot values through volatile pointer to prevent caching */
	seq = cs->seq;
	vol = cs->total_voluntary;
	preempt = cs->total_preemptions;

	/* Always save raw values for debugging */
	r->ebpf_cs_seq = seq;
	r->ebpf_cs_total_vol = vol;
	r->ebpf_cs_total_preempt = preempt;
	r->ebpf_cs_prev_seq = ctx->last_cs_seq;
	r->ebpf_cs_prev_vol = ctx->last_ebpf_voluntary_cs;
	r->ebpf_cs_prev_preempt = ctx->last_ebpf_nonvoluntary_cs;

	if (seq != ctx->last_cs_seq) {
		r->voluntary_cs_delta = vol - ctx->last_ebpf_voluntary_cs;
		r->nonvoluntary_cs_delta = preempt -
			ctx->last_ebpf_nonvoluntary_cs;

		ctx->last_ebpf_voluntary_cs = vol;
		ctx->last_ebpf_nonvoluntary_cs = preempt;
		ctx->last_cs_seq = seq;
	}
}

void
jitter_ebpf_read_irqs(struct jitter_lcore_ctx *ctx, struct jitter_record *r)
{
	int slot = ctx->ebpf_slot;
	const volatile struct jitter_irq_ring *ring;
	uint32_t head, prev_head, idx;
	uint16_t count = 0;

	if (!irq_mmap || slot < 0 || slot >= JITTER_EBPF_MAX_TARGETS)
		return;

	ring = &irq_mmap[slot];
	head = ring->head;
	prev_head = ctx->last_irq_head;

	if (head == prev_head)
		return;

	/* Walk new entries in the ring */
	while (prev_head != head && count < JITTER_MAX_IRQS) {
		idx = prev_head % JITTER_EBPF_IRQ_RING_SIZE;
		r->irq_deltas[count] = ring->events[idx].irq;
		count++;
		prev_head++;
	}

	r->irq_count = count;
	ctx->last_irq_head = head;
}

const volatile struct jitter_cs_percpu *
jitter_ebpf_get_cs_ptr(int slot)
{
	if (!cs_mmap || slot < 0 || slot >= JITTER_EBPF_MAX_TARGETS)
		return NULL;
	return &cs_mmap[slot];
}

const volatile struct jitter_irq_ring *
jitter_ebpf_get_irq_ptr(int slot)
{
	if (!irq_mmap || slot < 0 || slot >= JITTER_EBPF_MAX_TARGETS)
		return NULL;
	return &irq_mmap[slot];
}

int
jitter_ebpf_available(void)
{
	return skel != NULL;
}

pid_t
jitter_ebpf_gettid(void)
{
	return get_tid();
}
