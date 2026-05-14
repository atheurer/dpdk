/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Red Hat, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_log.h>

#include "testpmd.h"
#include "jitter.h"
#ifdef JITTER_HAS_EBPF
#include "jitter_ebpf.h"
#endif

static const char *jitter_irq_type_names[] = {
	[JITTER_IRQ_DEVICE]           = "DEVICE",
	[JITTER_IRQ_LOCAL_TIMER]      = "LOC",
	[JITTER_IRQ_RESCHEDULE]       = "RES",
	[JITTER_IRQ_CALL_FUNC]        = "CAL",
	[JITTER_IRQ_CALL_FUNC_SINGLE] = "CFS",
	[JITTER_IRQ_IRQ_WORK]         = "IWQ",
	[JITTER_IRQ_THERMAL]          = "TRM",
	[JITTER_IRQ_THRESHOLD]        = "THR",
	[JITTER_IRQ_DEFERRED_ERR]     = "DFR",
	[JITTER_IRQ_ERROR]            = "ERR",
	[JITTER_IRQ_SPURIOUS]         = "SPU",
	[JITTER_IRQ_X86_PLATFORM]     = "PLT",
	[JITTER_IRQ_SOFTIRQ_HI]      = "SI:HI",
	[JITTER_IRQ_SOFTIRQ_TIMER]   = "SI:TIMER",
	[JITTER_IRQ_SOFTIRQ_NET_TX]  = "SI:NET_TX",
	[JITTER_IRQ_SOFTIRQ_NET_RX]  = "SI:NET_RX",
	[JITTER_IRQ_SOFTIRQ_BLOCK]   = "SI:BLOCK",
	[JITTER_IRQ_SOFTIRQ_IRQ_POLL]= "SI:IRQPOL",
	[JITTER_IRQ_SOFTIRQ_TASKLET] = "SI:TASKLT",
	[JITTER_IRQ_SOFTIRQ_SCHED]   = "SI:SCHED",
	[JITTER_IRQ_SOFTIRQ_HRTIMER] = "SI:HRTMR",
	[JITTER_IRQ_SOFTIRQ_RCU]     = "SI:RCU",
	[JITTER_IRQ_NMI]              = "NMI",
};

static const char *jitter_class_names[] = {
	[JITTER_CLASS_UNKNOWN]            = "UNKNOWN",
	[JITTER_CLASS_KERNEL_PREEMPTION]  = "KERNEL_PREEMPTION",
	[JITTER_CLASS_SMI]                = "SMI",
	[JITTER_CLASS_FREQ_THROTTLE]      = "FREQ_THROTTLE",
	[JITTER_CLASS_CSTATE]             = "CSTATE",
	[JITTER_CLASS_MEMORY_STALL]       = "MEMORY_STALL",
	[JITTER_CLASS_PCIE_REPLAY]        = "PCIE_REPLAY",
	[JITTER_CLASS_NIC_OVERFLOW]       = "NIC_OVERFLOW",
	[JITTER_CLASS_MEMPOOL_STARVED]    = "MEMPOOL_STARVED",
	[JITTER_CLASS_APP_BACKLOG]        = "APP_BACKLOG",
};

enum jitter_class
jitter_classify(const struct jitter_record *r)
{
	if (r->smi_count_delta > 0)
		return JITTER_CLASS_SMI;

	if (r->nonvoluntary_cs_delta > 0 || r->voluntary_cs_delta > 0)
		return JITTER_CLASS_KERNEL_PREEMPTION;

	/* Frequency throttle: check hot-path ref_cycles first, fall back to
	 * cold-path APERF/MPERF. Ratio < 0.80 means significant throttling. */
	if (r->ref_cycles_delta > 0 && r->cycles_unhalted_delta > 0) {
		uint64_t ratio_x1000 = (r->cycles_unhalted_delta * 1000) /
			r->ref_cycles_delta;
		if (ratio_x1000 < 800)
			return JITTER_CLASS_FREQ_THROTTLE;
	} else if (r->mperf_delta > 0) {
		uint64_t ratio_x1000 = (r->aperf_delta * 1000) / r->mperf_delta;
		if (ratio_x1000 < 800)
			return JITTER_CLASS_FREQ_THROTTLE;
	}

	if (r->inst_retired_delta > r->inst_retired_user_delta)
		return JITTER_CLASS_KERNEL_PREEMPTION;

	if (r->cycles_unhalted_delta > 0 &&
	    r->tsc_delta > 2 * r->cycles_unhalted_delta)
		return JITTER_CLASS_CSTATE;

	if (r->aer_correctable_delta > 0 || r->aer_uncorrectable_delta > 0)
		return JITTER_CLASS_PCIE_REPLAY;

	if (r->rx_nombuf_delta > 0)
		return JITTER_CLASS_MEMPOOL_STARVED;

	if (r->rx_missed_delta > 0 && r->rx_ring_depth_before > 0)
		return JITTER_CLASS_NIC_OVERFLOW;

	if (r->rx_ring_depth_before > 512 && r->inst_retired_delta > 1000)
		return JITTER_CLASS_APP_BACKLOG;

	if (r->cycles_unhalted_delta > 0 &&
	    r->inst_retired_delta * 4 < r->cycles_unhalted_delta)
		return JITTER_CLASS_MEMORY_STALL;

	return JITTER_CLASS_UNKNOWN;
}

static void
dump_record_text(FILE *f, const struct jitter_record *r, uint32_t idx,
		 const struct jitter_lcore_ctx *ctx)
{
	uint64_t tsc_hz = rte_get_tsc_hz();
	double delta_us = (double)r->tsc_delta * 1000000.0 / (double)tsc_hz;
	enum jitter_class cls = jitter_classify(r);
	uint16_t i;

	fprintf(f, "=== Anomaly #%u lcore=%u port=%u queue=%u ===\n",
		idx, r->lcore_id, r->port_id, r->queue_id);
	fprintf(f, "  TSC start:    0x%016" PRIx64 "\n", r->tsc_start);
	fprintf(f, "  TSC delta:    %.1f us  (%" PRIu64 " cycles)\n",
		delta_us, r->tsc_delta);
	if (r->tsc_rx_delta > 0 || r->tsc_process_delta > 0 ||
	    r->tsc_tx_delta > 0) {
		fprintf(f, "  Phase breakdown:\n");
		if (r->tsc_rx_delta > 0)
			fprintf(f, "    rx:      %8.1f us  (%" PRIu64 " cycles)\n",
				(double)r->tsc_rx_delta * 1000000.0 / (double)tsc_hz,
				r->tsc_rx_delta);
		if (r->tsc_process_delta > 0)
			fprintf(f, "    process: %8.1f us  (%" PRIu64 " cycles)\n",
				(double)r->tsc_process_delta * 1000000.0 / (double)tsc_hz,
				r->tsc_process_delta);
		if (r->tsc_tx_delta > 0)
			fprintf(f, "    tx:      %8.1f us  (%" PRIu64 " cycles)\n",
				(double)r->tsc_tx_delta * 1000000.0 / (double)tsc_hz,
				r->tsc_tx_delta);
	}
	fprintf(f, "  Classification: %s\n", jitter_class_names[cls]);
	fprintf(f, "  Trigger:        flags=0x%04x %s%s%s%s\n",
		r->flags,
		(r->flags & JITTER_FLAG_THRESHOLD) ? "THRESHOLD " : "",
		(r->flags & JITTER_FLAG_CS_EVENT)  ? "CS " : "",
		(r->flags & JITTER_FLAG_IRQ_EVENT) ? "IRQ " : "",
		(r->flags == 0) ? "(NONE)" : "");
	fprintf(f, "  Hot-path:\n");
	fprintf(f, "    inst_retired:    %" PRIu64 "\n",
		r->inst_retired_delta);
	fprintf(f, "    inst_user:       %" PRIu64 "\n",
		r->inst_retired_user_delta);
	if (r->inst_retired_delta > r->inst_retired_user_delta)
		fprintf(f, "    inst_kernel:     %" PRIu64 "\n",
			r->inst_retired_delta - r->inst_retired_user_delta);
	fprintf(f, "    cycles_unhalted: %" PRIu64 "\n",
		r->cycles_unhalted_delta);
	fprintf(f, "    ref_cycles:      %" PRIu64 "\n",
		r->ref_cycles_delta);
	if (r->inst_retired_delta > 0)
		fprintf(f, "    cycles/inst:     %.2f\n",
			(double)r->cycles_unhalted_delta /
			(double)r->inst_retired_delta);
	else
		fprintf(f, "    cycles/inst:     N/A\n");
	if (r->ref_cycles_delta > 0)
		fprintf(f, "    freq ratio:      %.2f\n",
			(double)r->cycles_unhalted_delta /
			(double)r->ref_cycles_delta);
	else
		fprintf(f, "    freq ratio:      N/A\n");
	fprintf(f, "    llc_misses:      %" PRIu64 "\n",
		r->llc_misses_delta);
	fprintf(f, "    branch_misses:   %" PRIu64 "\n",
		r->branch_misses_delta);
	if (r->mem_stalls_llc_miss_delta > 0 || r->mem_stalls_llc_hit_delta > 0
	    || r->llc_refs_delta > 0) {
		fprintf(f, "    mem_stall_llc_miss: %" PRIu64 " cycles\n",
			r->mem_stalls_llc_miss_delta);
		fprintf(f, "    mem_stall_llc_hit:  %" PRIu64 " cycles\n",
			r->mem_stalls_llc_hit_delta);
		fprintf(f, "    llc_refs:          %" PRIu64 "\n",
			r->llc_refs_delta);
	}
	fprintf(f, "    rx_ring_before:  %u  rx_ring_after: %u  nb_rx: %u\n",
		r->rx_ring_depth_before, r->rx_ring_depth_after, r->nb_rx);
	if (r->flags & JITTER_FLAG_IRQ_EVENT) {
		fprintf(f, "    Interrupts (eBPF-detected):\n");
		fprintf(f, "      eBPF irq ring: head=%u prev_head=%u\n",
			r->ebpf_irq_head, r->ebpf_irq_prev_head);
		if (r->irq_count > 0) {
			for (i = 0; i < JITTER_IRQ_TYPE_MAX; i++) {
				if (r->irq_deltas[i] != 0)
					fprintf(f, "      %-8s %" PRIu64 "\n",
						jitter_irq_type_names[i],
						r->irq_deltas[i]);
			}
		}
	}
	if (r->flags & JITTER_FLAG_CS_EVENT) {
		fprintf(f, "    Scheduling (eBPF-detected):\n");
		fprintf(f, "      eBPF raw:  seq=%" PRIu64 " vol=%" PRIu64
			" preempt=%" PRIu64 "\n",
			r->ebpf_cs_seq, r->ebpf_cs_total_vol,
			r->ebpf_cs_total_preempt);
		fprintf(f, "      eBPF prev: seq=%" PRIu64 " vol=%" PRIu64
			" preempt=%" PRIu64 "\n",
			r->ebpf_cs_prev_seq, r->ebpf_cs_prev_vol,
			r->ebpf_cs_prev_preempt);
	}
	fprintf(f, "  Cold-path:\n");
	fprintf(f, "    Scheduling:\n");
	fprintf(f, "      voluntary_cs_delta:     %" PRIu64 "\n",
		r->voluntary_cs_delta);
	fprintf(f, "      nonvoluntary_cs_delta:  %" PRIu64 "\n",
		r->nonvoluntary_cs_delta);
	if (!(r->flags & JITTER_FLAG_CS_EVENT)) {
		fprintf(f, "      eBPF raw:  seq=%" PRIu64 " vol=%" PRIu64
			" preempt=%" PRIu64 "\n",
			r->ebpf_cs_seq, r->ebpf_cs_total_vol,
			r->ebpf_cs_total_preempt);
		fprintf(f, "      eBPF prev: seq=%" PRIu64 " vol=%" PRIu64
			" preempt=%" PRIu64 "\n",
			r->ebpf_cs_prev_seq, r->ebpf_cs_prev_vol,
			r->ebpf_cs_prev_preempt);
	}
	fprintf(f, "    CPU/Power:\n");
	fprintf(f, "      smi_count_delta:        %" PRIu64 "\n",
		r->smi_count_delta);
	if (r->mperf_delta > 0)
		fprintf(f, "      aperf/mperf ratio:      %.2f\n",
			(double)r->aperf_delta / (double)r->mperf_delta);
	else
		fprintf(f, "      aperf/mperf ratio:      N/A\n");
	fprintf(f, "    PCIe/AER:\n");
	fprintf(f, "      correctable delta:      %u\n",
		r->aer_correctable_delta);
	fprintf(f, "      uncorrectable delta:    %u\n",
		r->aer_uncorrectable_delta);
	fprintf(f, "    NIC stats:\n");
	fprintf(f, "      rx_missed_delta:        %" PRIu64 "\n",
		r->rx_missed_delta);
	fprintf(f, "      rx_nombuf_delta:        %" PRIu64 "\n",
		r->rx_nombuf_delta);
	fprintf(f, "      ierrors_delta:           %" PRIu64 "\n",
		r->ierrors_delta);
	fprintf(f, "      mempool_avail:          %u\n", r->mempool_avail);
	if (!(r->flags & JITTER_FLAG_IRQ_EVENT)) {
		fprintf(f, "    Interrupts:\n");
		fprintf(f, "      eBPF irq ring: head=%u prev_head=%u\n",
			r->ebpf_irq_head, r->ebpf_irq_prev_head);
		if (r->irq_count > 0) {
			if (r->ebpf_irq_head > 0 || r->ebpf_irq_prev_head > 0) {
				for (i = 0; i < JITTER_IRQ_TYPE_MAX; i++) {
					if (r->irq_deltas[i] != 0)
						fprintf(f, "      %-8s %" PRIu64 "\n",
							jitter_irq_type_names[i],
							r->irq_deltas[i]);
				}
			} else {
				for (i = 0; i < r->irq_count &&
				     i < ctx->irq_count; i++) {
					if (r->irq_deltas[i] != 0)
						fprintf(f, "      %-8s %" PRIu64 "\n",
							ctx->irqs[i].name,
							r->irq_deltas[i]);
				}
			}
		}
	}
	if (r->xstat_count > 0) {
		int any = 0;

		for (i = 0; i < r->xstat_count && i < ctx->xstats.count; i++) {
			if (r->xstat_deltas[i] != 0) {
				if (!any) {
					fprintf(f, "    PMD xstats:\n");
					any = 1;
				}
				fprintf(f, "      %-32s %" PRIu64 "\n",
					ctx->xstats.names[i],
					r->xstat_deltas[i]);
			}
		}
	}
	fprintf(f, "\n");
}

static void
dump_csv_header(FILE *f, const struct jitter_lcore_ctx *ctx)
{
	uint16_t i;

	fprintf(f, "lcore_id,port_id,queue_id,tsc_start,tsc_end,"
		"tsc_delta,delta_us,classification,"
		"inst_retired_delta,inst_retired_user_delta,cycles_unhalted_delta,"
		"rx_ring_depth_before,rx_ring_depth_after,nb_rx,"
		"smi_count_delta,aperf_delta,mperf_delta,"
		"voluntary_cs_delta,nonvoluntary_cs_delta,"
		"aer_correctable_delta,aer_uncorrectable_delta,"
		"rx_missed_delta,rx_nombuf_delta,ierrors_delta,"
		"mempool_avail");
	for (i = 0; i < ctx->xstats.count; i++)
		fprintf(f, ",%s", ctx->xstats.names[i]);
	fprintf(f, "\n");
}

static void
dump_record_csv(FILE *f, const struct jitter_record *r,
		const struct jitter_lcore_ctx *ctx)
{
	uint64_t tsc_hz = rte_get_tsc_hz();
	double delta_us = (double)r->tsc_delta * 1000000.0 / (double)tsc_hz;
	enum jitter_class cls = jitter_classify(r);
	uint16_t i;

	fprintf(f, "%u,%u,%u,%" PRIu64 ",%" PRIu64 ","
		"%" PRIu64 ",%.1f,%s,"
		"%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
		"%u,%u,%u,"
		"%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
		"%" PRIu64 ",%" PRIu64 ","
		"%u,%u,"
		"%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
		"%u",
		r->lcore_id, r->port_id, r->queue_id,
		r->tsc_start, r->tsc_end,
		r->tsc_delta, delta_us, jitter_class_names[cls],
		r->inst_retired_delta, r->inst_retired_user_delta,
		r->cycles_unhalted_delta,
		r->rx_ring_depth_before, r->rx_ring_depth_after, r->nb_rx,
		r->smi_count_delta, r->aperf_delta, r->mperf_delta,
		r->voluntary_cs_delta, r->nonvoluntary_cs_delta,
		r->aer_correctable_delta, r->aer_uncorrectable_delta,
		r->rx_missed_delta, r->rx_nombuf_delta, r->ierrors_delta,
		r->mempool_avail);
	for (i = 0; i < ctx->xstats.count; i++)
		fprintf(f, ",%" PRIu64,
			i < r->xstat_count ? r->xstat_deltas[i] : 0UL);
	fprintf(f, "\n");
}

int
jitter_dump(const char *path, const char *format)
{
	FILE *f;
	unsigned int lcore_id;
	int is_csv;

	if (path == NULL || path[0] == '\0')
		f = stderr;
	else {
		f = fopen(path, "w");
		if (f == NULL) {
			TESTPMD_LOG(ERR, "Cannot open jitter output file %s\n",
				    path);
			return -1;
		}
	}

	is_csv = (format != NULL && strcmp(format, "csv") == 0);

	/* For CSV, emit header using the first active ctx for xstat names */
	if (is_csv) {
		for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
			if (jitter_lcore_ctxs[lcore_id] != NULL) {
				dump_csv_header(f, jitter_lcore_ctxs[lcore_id]);
				break;
			}
		}
	}

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		struct jitter_lcore_ctx *ctx = jitter_lcore_ctxs[lcore_id];
		uint32_t count, start, i;

		if (ctx == NULL || ctx->total_anomalies == 0)
			continue;

		count = ctx->record_head;
		if (count > ctx->record_capacity)
			count = ctx->record_capacity;

		if (ctx->record_head > ctx->record_capacity)
			start = ctx->record_head - ctx->record_capacity;
		else
			start = 0;

		for (i = start; i < ctx->record_head; i++) {
			struct jitter_record *r =
				&ctx->records[i % ctx->record_capacity];
			if (is_csv)
				dump_record_csv(f, r, ctx);
			else
				dump_record_text(f, r, i, ctx);
		}
	}

	if (f != stderr)
		fclose(f);

	return 0;
}

struct jitter_top_entry {
	const struct jitter_record *r;
	const struct jitter_lcore_ctx *ctx;
	uint32_t idx;
};

static int
top_entry_cmp(const void *a, const void *b)
{
	const struct jitter_top_entry *ea = a;
	const struct jitter_top_entry *eb = b;

	if (eb->r->tsc_delta > ea->r->tsc_delta)
		return 1;
	if (eb->r->tsc_delta < ea->r->tsc_delta)
		return -1;
	return 0;
}

void
jitter_dump_top(uint32_t n)
{
	struct jitter_top_entry *entries;
	uint32_t total = 0, cap = 0;
	unsigned int lcore_id;

	/* Collect from worst-N buffers (preserved across ring wraps) */
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		struct jitter_lcore_ctx *ctx = jitter_lcore_ctxs[lcore_id];

		if (ctx == NULL || ctx->worst == NULL)
			continue;
		cap += ctx->worst_count;
	}

	if (cap == 0) {
		fprintf(stdout, "No anomaly records captured.\n");
		return;
	}

	entries = malloc(sizeof(*entries) * cap);
	if (entries == NULL)
		return;

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		struct jitter_lcore_ctx *ctx = jitter_lcore_ctxs[lcore_id];
		uint32_t i;

		if (ctx == NULL || ctx->worst == NULL)
			continue;

		for (i = 0; i < ctx->worst_count; i++) {
			entries[total].r = &ctx->worst[i];
			entries[total].ctx = ctx;
			entries[total].idx = i;
			total++;
		}
	}

	qsort(entries, total, sizeof(entries[0]), top_entry_cmp);

	if (n > total)
		n = total;

	fprintf(stdout, "\n--- Top %u anomalies by duration (all-time worst) ---\n\n", n);
	for (uint32_t i = 0; i < n; i++)
		dump_record_text(stdout, entries[i].r,
				 entries[i].idx, entries[i].ctx);

	free(entries);
}

void
jitter_show_summary(void)
{
	unsigned int lcore_id;
	uint64_t tsc_hz = rte_get_tsc_hz();

	fprintf(stdout, "\n--- Jitter Instrumentation Summary ---\n");
	fprintf(stdout, "%-8s %12s %10s %10s %10s %10s %10s\n",
		"Lcore", "Iterations", "Anomalies",
		"Threshold", "CS", "IRQ", "Max(us)");
	fprintf(stdout, "%-8s %12s %10s %10s %10s %10s %10s\n",
		"-----", "----------", "---------",
		"---------", "--", "---", "-------");

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		struct jitter_lcore_ctx *ctx = jitter_lcore_ctxs[lcore_id];
		double max_us;

		if (ctx == NULL)
			continue;
		if (ctx->total_iterations == 0 && ctx->total_anomalies == 0)
			continue;

		max_us = (double)ctx->max_iter_cycles * 1000000.0 /
			 (double)tsc_hz;

		fprintf(stdout,
			"%-8u %12" PRIu64 " %10" PRIu64
			" %10" PRIu64 " %10" PRIu64 " %10" PRIu64
			" %10.1f\n",
			lcore_id, ctx->total_iterations,
			ctx->total_anomalies,
			ctx->total_threshold,
			ctx->total_cs_events,
			ctx->total_irq_events,
			max_us);
	}
	fprintf(stdout, "\n");
}

void
jitter_reset_all(void)
{
	unsigned int lcore_id;

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		struct jitter_lcore_ctx *ctx = jitter_lcore_ctxs[lcore_id];

		if (ctx == NULL)
			continue;

		memset(ctx->records, 0,
		       sizeof(struct jitter_record) * ctx->record_capacity);
		ctx->record_head = 0;
		ctx->total_anomalies = 0;
		ctx->total_iterations = 0;
		ctx->max_iter_cycles = 0;
		ctx->total_threshold = 0;
		ctx->total_cs_events = 0;
		ctx->total_irq_events = 0;
		if (ctx->worst != NULL) {
			memset(ctx->worst, 0,
			       sizeof(struct jitter_record) * ctx->worst_capacity);
			ctx->worst_count = 0;
		}
	}
}
