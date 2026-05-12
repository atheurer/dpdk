/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Red Hat, Inc.
 */

#ifndef _JITTER_H_
#define _JITTER_H_

#include <stdint.h>
#include <limits.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_branch_prediction.h>
#include <rte_mempool.h>

#if defined(RTE_ARCH_X86_64) && defined(RTE_EXEC_ENV_LINUX)
#include <linux/perf_event.h>
#endif

#ifdef JITTER_HAS_EBPF
#include "jitter_ebpf.h"
#endif

#define JITTER_MAX_XSTATS 64
#define JITTER_MAX_IRQS   128
#define JITTER_IRQ_NAME_SIZE 32

enum jitter_class {
	JITTER_CLASS_UNKNOWN = 0,
	JITTER_CLASS_KERNEL_PREEMPTION,
	JITTER_CLASS_SMI,
	JITTER_CLASS_FREQ_THROTTLE,
	JITTER_CLASS_CSTATE,
	JITTER_CLASS_MEMORY_STALL,
	JITTER_CLASS_PCIE_REPLAY,
	JITTER_CLASS_NIC_OVERFLOW,
	JITTER_CLASS_MEMPOOL_STARVED,
	JITTER_CLASS_APP_BACKLOG,
};

struct jitter_record {
	uint64_t tsc_start;
	uint64_t tsc_end;
	uint64_t tsc_delta;

	/* Per-phase TSC deltas (0 if marker not called) */
	uint64_t tsc_rx_delta;      /* start -> post_rx */
	uint64_t tsc_process_delta; /* post_rx -> post_process */
	uint64_t tsc_tx_delta;      /* post_process -> end */

	/* Hot-path PMC deltas */
	uint64_t inst_retired_delta;
	uint64_t inst_retired_user_delta;
	uint64_t cycles_unhalted_delta;
	uint64_t ref_cycles_delta;
	uint64_t llc_misses_delta;
	uint64_t branch_misses_delta;

	/* Device-side state */
	uint32_t rx_ring_depth_before;
	uint32_t rx_ring_depth_after;
	uint16_t nb_rx;
	uint16_t port_id;
	uint16_t queue_id;
	uint16_t lcore_id;

	/* Cold-path attributions (zero if not collected) */
	uint64_t smi_count_delta;
	uint64_t aperf_delta;
	uint64_t mperf_delta;
	uint64_t voluntary_cs_delta;
	uint64_t nonvoluntary_cs_delta;

	/* PCIe AER deltas */
	uint32_t aer_correctable_delta;
	uint32_t aer_uncorrectable_delta;

	/* NIC-side */
	uint64_t rx_missed_delta;
	uint64_t rx_nombuf_delta;
	uint64_t ierrors_delta;
	uint32_t mempool_avail;

	/* PMD-specific xstat deltas */
	uint64_t xstat_deltas[JITTER_MAX_XSTATS];
	uint16_t xstat_count;

	/* Per-CPU interrupt deltas (0 if not collected) */
	uint64_t irq_deltas[JITTER_MAX_IRQS];
	uint16_t irq_count;

	/* eBPF raw values at time of read (for debugging) */
	uint64_t ebpf_cs_seq;
	uint64_t ebpf_cs_total_vol;
	uint64_t ebpf_cs_total_preempt;
	uint64_t ebpf_cs_prev_seq;
	uint64_t ebpf_cs_prev_vol;
	uint64_t ebpf_cs_prev_preempt;
	uint32_t ebpf_irq_head;
	uint32_t ebpf_irq_prev_head;

	/* Set by jitter_classify() at dump time */
	uint16_t classification; /* enum jitter_class */
	uint16_t flags;
};

/* Bits in jitter_record.flags — why this anomaly was recorded */
#define JITTER_FLAG_THRESHOLD  (1 << 0)  /* TSC delta exceeded threshold */
#define JITTER_FLAG_CS_EVENT   (1 << 1)  /* eBPF context switch detected */
#define JITTER_FLAG_IRQ_EVENT  (1 << 2)  /* eBPF interrupt detected */

#define JITTER_XSTAT_RX_MISSED  0
#define JITTER_XSTAT_RX_NOMBUF  1
#define JITTER_XSTAT_IERRORS     2
#define JITTER_XSTAT_MAX         3

struct jitter_lcore_ctx {
#if defined(RTE_ARCH_X86_64) && defined(RTE_EXEC_ENV_LINUX)
	struct perf_event_mmap_page *pmc_inst_page;
	struct perf_event_mmap_page *pmc_inst_user_page;
	struct perf_event_mmap_page *pmc_cycles_page;
	struct perf_event_mmap_page *pmc_ref_cycles_page;
	struct perf_event_mmap_page *pmc_llc_misses_page;
	struct perf_event_mmap_page *pmc_branch_misses_page;
	int pmc_inst_fd;
	int pmc_inst_user_fd;
	int pmc_cycles_fd;
	int pmc_ref_cycles_fd;
	int pmc_llc_misses_fd;
	int pmc_branch_misses_fd;
#endif

	/* Last-known cold-path values */
	uint64_t last_smi_count;
	uint64_t last_aperf;
	uint64_t last_mperf;
	uint64_t last_voluntary_cs;
	uint64_t last_nonvoluntary_cs;
	uint64_t last_xstats[JITTER_XSTAT_MAX];
	uint32_t last_aer_correctable;
	uint32_t last_aer_uncorrectable;

	/* Ring buffer */
	struct jitter_record *records;
	uint32_t record_capacity;
	uint32_t record_head;
	uint64_t total_anomalies;
	uint64_t total_iterations;
	uint64_t max_iter_cycles;

	/* Per-trigger-type counters */
	uint64_t total_threshold;
	uint64_t total_cs_events;
	uint64_t total_irq_events;

	/* Config */
	int msr_fd;
	uint16_t lcore_id;
	uint16_t primary_port_id;
	uint16_t primary_queue_id;
	uint8_t msr_enabled;
	uint8_t aer_enabled;
	uint8_t pmc_enabled;
	uint8_t pmc_init_done;

	/* Mempool pointer for avail_count on anomaly */
	struct rte_mempool *mbuf_pool;

	/* AER state — one per polled port */
	struct {
		uint16_t port_id;
		uint16_t aer_cap_offset;
	} aer_ports[RTE_MAX_ETHPORTS];
	uint16_t nb_aer_ports;

	/* Per-CPU interrupt tracking */
	uint8_t irq_enabled;
	int irq_cpu_col;  /* column index for our CPU in /proc/interrupts */
	struct {
		char name[JITTER_IRQ_NAME_SIZE];
		uint64_t last_count;
	} irqs[JITTER_MAX_IRQS];
	uint16_t irq_count;

	/* PMD-specific xstat tracking */
	struct {
		uint64_t ids[JITTER_MAX_XSTATS];
		char names[JITTER_MAX_XSTATS][RTE_ETH_XSTATS_NAME_SIZE];
		uint64_t last_values[JITTER_MAX_XSTATS];
		uint16_t count;
	} xstats;

#ifdef JITTER_HAS_EBPF
	/* eBPF context switch tracking */
	uint8_t ebpf_registered;
	int ebpf_slot;
	uint64_t last_cs_seq;
	uint64_t last_ebpf_voluntary_cs;
	uint64_t last_ebpf_nonvoluntary_cs;
	const volatile struct jitter_cs_percpu *ebpf_cs_ptr;
	const volatile struct jitter_irq_ring *ebpf_irq_ptr;
	uint32_t last_irq_head;
#endif
} __rte_cache_aligned;

/* Global configuration — set from CLI, read by all lcores */
extern uint8_t jitter_enabled;
extern uint64_t jitter_threshold_cycles;
extern uint32_t jitter_record_count;
extern uint8_t jitter_msr_enabled;
extern uint8_t jitter_aer_enabled;
extern uint8_t jitter_irq_enabled;
extern uint8_t jitter_cs_enabled;
extern uint8_t jitter_xstats_enabled;
extern uint8_t jitter_ebpf_enabled;
extern char jitter_output_path[PATH_MAX];
extern char jitter_output_format[16];

/* Per-lcore ctx table, indexed by lcore_id */
extern struct jitter_lcore_ctx *jitter_lcore_ctxs[RTE_MAX_LCORE];

/* Global init/teardown — call from main thread */
int jitter_global_init(void);
void jitter_global_fini(void);

/* Per-lcore init — call from each forwarding lcore once */
struct jitter_lcore_ctx *jitter_lcore_init(unsigned int lcore_id,
					   uint16_t port_id,
					   uint16_t queue_id);
void jitter_lcore_fini(struct jitter_lcore_ctx *ctx);

/* Forward declaration for hot-path use */
struct jitter_iter_state;

/* Cold-path anomaly recording — NOT inlined */
void jitter_record_anomaly(struct jitter_lcore_ctx *ctx,
			   struct jitter_iter_state *st,
			   uint64_t tsc_end, uint64_t delta,
			   uint16_t nb_rx, uint16_t flags);

/* Reporting */
int jitter_dump(const char *path, const char *format);
void jitter_dump_top(uint32_t n);
void jitter_show_summary(void);
void jitter_reset_all(void);
void jitter_set_threshold_us(uint64_t us);

/* PMC helpers (jitter_pmc.c) */
int jitter_pmc_setup(struct jitter_lcore_ctx *ctx, int cpu);
void jitter_pmc_teardown(struct jitter_lcore_ctx *ctx);

/* Lazy PMC init — called from forwarding lcore on first iteration */
void jitter_pmc_lazy_init(struct jitter_lcore_ctx *ctx);

/* xstat discovery — called from jitter_lcore_init() */
void jitter_xstats_init(struct jitter_lcore_ctx *ctx, uint16_t port_id);

/* MSR helpers (jitter_msr.c) */
int jitter_msr_open(int cpu);
uint64_t jitter_msr_read(int fd, uint32_t msr);

/* PCIe helpers (jitter_pcie.c) */
uint16_t jitter_pcie_find_aer_cap(uint16_t port_id);
int jitter_pcie_read_aer(uint16_t port_id, uint16_t aer_off,
			 uint32_t *correctable, uint32_t *uncorrectable);

/* Context switch reader (jitter.c) */
int jitter_read_ctxt_switches(uint64_t *vcs, uint64_t *nvcs);

/* Classification (jitter_report.c) */
enum jitter_class jitter_classify(const struct jitter_record *r);

/* eBPF helpers (jitter_ebpf.c) */
#ifdef JITTER_HAS_EBPF
int jitter_ebpf_init(void);
void jitter_ebpf_fini(void);
int jitter_ebpf_register_lcore(int slot, pid_t tid, int cpu);
void jitter_ebpf_read_cs(struct jitter_lcore_ctx *ctx,
			  struct jitter_record *r);
void jitter_ebpf_read_irqs(struct jitter_lcore_ctx *ctx,
			    struct jitter_record *r);
const volatile struct jitter_cs_percpu *jitter_ebpf_get_cs_ptr(int slot);
const volatile struct jitter_irq_ring *jitter_ebpf_get_irq_ptr(int slot);
int jitter_ebpf_available(void);
pid_t jitter_ebpf_gettid(void);
#endif

/* Hot-path iteration markers */
struct jitter_iter_state {
	uint64_t tsc_start;
	uint64_t tsc_post_rx;
	uint64_t tsc_post_process;
	uint64_t inst_start;
	uint64_t inst_user_start;
	uint64_t cycles_start;
	uint64_t ref_cycles_start;
	uint64_t llc_misses_start;
	uint64_t branch_misses_start;
	uint32_t rx_ring_depth_before;
	uint16_t port_id;
	uint16_t queue_id;
};

#if defined(RTE_ARCH_X86_64) && defined(RTE_EXEC_ENV_LINUX)
static __rte_always_inline uint64_t
jitter_rdpmc_read(struct perf_event_mmap_page *pc)
{
	uint32_t seq, idx;
	uint64_t count, offset;

	if (pc == NULL)
		return 0;

	do {
		seq = pc->lock;
		rte_compiler_barrier();
		idx = pc->index;
		offset = pc->offset;
		if (idx == 0) {
			count = 0;
			break;
		}
		{
			uint32_t low, high;
			__asm__ volatile("rdpmc"
					 : "=a"(low), "=d"(high)
					 : "c"(idx - 1));
			count = ((uint64_t)high << 32) | low;
		}
		rte_compiler_barrier();
	} while (pc->lock != seq);

	return count + offset;
}
#endif

static __rte_always_inline void
jitter_iter_begin(struct jitter_lcore_ctx *ctx,
		  struct jitter_iter_state *st,
		  uint16_t port_id, uint16_t queue_id)
{
	if (unlikely(ctx == NULL))
		return;
	if (unlikely(!ctx->pmc_init_done))
		jitter_pmc_lazy_init(ctx);
	st->tsc_post_rx = 0;
	st->tsc_post_process = 0;
	st->port_id = port_id;
	st->queue_id = queue_id;
	{
		int cnt = rte_eth_rx_queue_count(port_id, queue_id);
		st->rx_ring_depth_before = cnt > 0 ? (uint32_t)cnt : 0;
	}
#if defined(RTE_ARCH_X86_64) && defined(RTE_EXEC_ENV_LINUX)
	if (likely(ctx->pmc_enabled)) {
		st->inst_start = jitter_rdpmc_read(ctx->pmc_inst_page);
		st->inst_user_start = jitter_rdpmc_read(ctx->pmc_inst_user_page);
		st->cycles_start = jitter_rdpmc_read(ctx->pmc_cycles_page);
		st->ref_cycles_start = jitter_rdpmc_read(ctx->pmc_ref_cycles_page);
		st->llc_misses_start = jitter_rdpmc_read(ctx->pmc_llc_misses_page);
		st->branch_misses_start = jitter_rdpmc_read(ctx->pmc_branch_misses_page);
	} else {
		st->inst_start = 0;
		st->inst_user_start = 0;
		st->cycles_start = 0;
		st->ref_cycles_start = 0;
		st->llc_misses_start = 0;
		st->branch_misses_start = 0;
	}
#else
	st->inst_start = 0;
	st->inst_user_start = 0;
	st->cycles_start = 0;
	st->ref_cycles_start = 0;
	st->llc_misses_start = 0;
	st->branch_misses_start = 0;
#endif
	st->tsc_start = rte_rdtsc();
}

static __rte_always_inline void
jitter_mark_rx(struct jitter_lcore_ctx *ctx,
	       struct jitter_iter_state *st)
{
	if (unlikely(ctx == NULL))
		return;
	st->tsc_post_rx = rte_rdtsc();
}

static __rte_always_inline void
jitter_mark_process(struct jitter_lcore_ctx *ctx,
		    struct jitter_iter_state *st)
{
	if (unlikely(ctx == NULL))
		return;
	st->tsc_post_process = rte_rdtsc();
}

static __rte_always_inline void
jitter_iter_end(struct jitter_lcore_ctx *ctx,
		struct jitter_iter_state *st,
		uint16_t nb_rx)
{
	uint64_t tsc_end, delta;
	uint16_t flags = 0;

	if (unlikely(ctx == NULL))
		return;
	tsc_end = rte_rdtsc();
	delta = tsc_end - st->tsc_start;
	ctx->total_iterations++;
	if (delta > ctx->max_iter_cycles)
		ctx->max_iter_cycles = delta;
	if (unlikely(delta >= jitter_threshold_cycles))
		flags |= JITTER_FLAG_THRESHOLD;
#ifdef JITTER_HAS_EBPF
	if (ctx->ebpf_cs_ptr &&
	    unlikely(ctx->ebpf_cs_ptr->seq != ctx->last_cs_seq))
		flags |= JITTER_FLAG_CS_EVENT;
	if (ctx->ebpf_irq_ptr &&
	    unlikely(ctx->ebpf_irq_ptr->head != ctx->last_irq_head))
		flags |= JITTER_FLAG_IRQ_EVENT;
#endif
	if (likely(flags == 0))
		return;
	jitter_record_anomaly(ctx, st, tsc_end, delta, nb_rx, flags);
#ifdef JITTER_HAS_EBPF
	/* Consume the event seq/head in the hot path to guarantee
	 * we never re-trigger on the same event, even if the cold
	 * path read saw a stale value from the mmap. */
	if (ctx->ebpf_cs_ptr)
		ctx->last_cs_seq = ctx->ebpf_cs_ptr->seq;
	if (ctx->ebpf_irq_ptr)
		ctx->last_irq_head = ctx->ebpf_irq_ptr->head;
#endif
}

#endif /* _JITTER_H_ */
