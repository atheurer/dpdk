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

	if (r->mperf_delta > 0) {
		uint64_t ratio_x1000 = (r->aperf_delta * 1000) / r->mperf_delta;
		if (ratio_x1000 < 800)
			return JITTER_CLASS_FREQ_THROTTLE;
	}

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
	fprintf(f, "  Classification: %s\n", jitter_class_names[cls]);
	fprintf(f, "  Hot-path:\n");
	fprintf(f, "    inst_retired:    %" PRIu64 "\n",
		r->inst_retired_delta);
	fprintf(f, "    cycles_unhalted: %" PRIu64 "\n",
		r->cycles_unhalted_delta);
	fprintf(f, "    rx_ring_before:  %u  rx_ring_after: %u  nb_rx: %u\n",
		r->rx_ring_depth_before, r->rx_ring_depth_after, r->nb_rx);
	fprintf(f, "  Cold-path:\n");
	fprintf(f, "    smi_count_delta:        %" PRIu64 "\n",
		r->smi_count_delta);
	fprintf(f, "    voluntary_cs_delta:     %" PRIu64 "\n",
		r->voluntary_cs_delta);
	fprintf(f, "    nonvoluntary_cs_delta:  %" PRIu64 "\n",
		r->nonvoluntary_cs_delta);
	if (r->mperf_delta > 0)
		fprintf(f, "    aperf/mperf ratio:      %.2f\n",
			(double)r->aperf_delta / (double)r->mperf_delta);
	else
		fprintf(f, "    aperf/mperf ratio:      N/A\n");
	fprintf(f, "    AER correctable delta:  %u\n",
		r->aer_correctable_delta);
	fprintf(f, "    AER uncorrectable delta: %u\n",
		r->aer_uncorrectable_delta);
	fprintf(f, "    rx_missed_delta:        %" PRIu64 "\n",
		r->rx_missed_delta);
	fprintf(f, "    rx_nombuf_delta:        %" PRIu64 "\n",
		r->rx_nombuf_delta);
	fprintf(f, "    ierrors_delta:           %" PRIu64 "\n",
		r->ierrors_delta);
	fprintf(f, "    mempool_avail:          %u\n", r->mempool_avail);
	if (r->xstat_count > 0) {
		int any = 0;

		for (i = 0; i < r->xstat_count && i < ctx->xstats.count; i++) {
			if (r->xstat_deltas[i] != 0) {
				if (!any) {
					fprintf(f, "  PMD xstats:\n");
					any = 1;
				}
				fprintf(f, "    %-32s %" PRIu64 "\n",
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
		"inst_retired_delta,cycles_unhalted_delta,"
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
		"%" PRIu64 ",%" PRIu64 ","
		"%u,%u,%u,"
		"%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
		"%" PRIu64 ",%" PRIu64 ","
		"%u,%u,"
		"%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
		"%u",
		r->lcore_id, r->port_id, r->queue_id,
		r->tsc_start, r->tsc_end,
		r->tsc_delta, delta_us, jitter_class_names[cls],
		r->inst_retired_delta, r->cycles_unhalted_delta,
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

void
jitter_show_summary(void)
{
	unsigned int lcore_id;
	uint64_t tsc_hz = rte_get_tsc_hz();

	fprintf(stdout, "\n--- Jitter Instrumentation Summary ---\n");
	fprintf(stdout, "%-8s %-12s %-15s %-12s\n",
		"Lcore", "Iterations", "Anomalies", "Max(us)");
	fprintf(stdout, "%-8s %-12s %-15s %-12s\n",
		"-----", "----------", "---------", "-------");

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		struct jitter_lcore_ctx *ctx = jitter_lcore_ctxs[lcore_id];
		double max_us;

		if (ctx == NULL)
			continue;
		if (ctx->total_iterations == 0 && ctx->total_anomalies == 0)
			continue;

		max_us = (double)ctx->max_iter_cycles * 1000000.0 /
			 (double)tsc_hz;

		fprintf(stdout, "%-8u %-12" PRIu64 " %-15" PRIu64 " %-12.1f\n",
			lcore_id, ctx->total_iterations,
			ctx->total_anomalies, max_us);
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
	}
}
