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
#include <limits.h>
#include <inttypes.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/resource.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mempool.h>

#include "testpmd.h"
#include "jitter.h"

#define MSR_SMI_COUNT   0x34
#define MSR_IA32_APERF  0xE8
#define MSR_IA32_MPERF  0xE7

/* Global configuration */
uint8_t jitter_enabled;
uint64_t jitter_threshold_cycles;
uint32_t jitter_record_count = 1024;
uint8_t jitter_msr_enabled;
uint8_t jitter_aer_enabled;
char jitter_output_path[PATH_MAX] = "";
char jitter_output_format[16] = "text";

static uint64_t jitter_threshold_us_val = 100;

/* Per-lcore ctx table */
struct jitter_lcore_ctx *jitter_lcore_ctxs[RTE_MAX_LCORE];

int
jitter_global_init(void)
{
	jitter_threshold_cycles =
		(rte_get_tsc_hz() * jitter_threshold_us_val) / 1000000ULL;

	TESTPMD_LOG(NOTICE, "Jitter instrumentation enabled: "
		    "threshold=%" PRIu64 " us (%" PRIu64 " cycles), "
		    "records=%u\n",
		    jitter_threshold_us_val, jitter_threshold_cycles,
		    jitter_record_count);
	return 0;
}

void
jitter_global_fini(void)
{
	unsigned int i;

	for (i = 0; i < RTE_MAX_LCORE; i++) {
		if (jitter_lcore_ctxs[i] != NULL) {
			jitter_lcore_fini(jitter_lcore_ctxs[i]);
			jitter_lcore_ctxs[i] = NULL;
		}
	}
}

struct jitter_lcore_ctx *
jitter_lcore_init(unsigned int lcore_id, uint16_t port_id, uint16_t queue_id)
{
	struct jitter_lcore_ctx *ctx;
	int socket_id;

	if (jitter_lcore_ctxs[lcore_id] != NULL)
		return jitter_lcore_ctxs[lcore_id];

	socket_id = rte_lcore_to_socket_id(lcore_id);
	ctx = rte_zmalloc_socket("jitter_ctx", sizeof(*ctx),
				 RTE_CACHE_LINE_SIZE, socket_id);
	if (ctx == NULL) {
		TESTPMD_LOG(ERR, "Failed to allocate jitter ctx for lcore %u\n",
			    lcore_id);
		return NULL;
	}

	ctx->records = rte_zmalloc_socket("jitter_records",
					  sizeof(struct jitter_record) * jitter_record_count,
					  RTE_CACHE_LINE_SIZE, socket_id);
	if (ctx->records == NULL) {
		TESTPMD_LOG(ERR, "Failed to allocate jitter records for lcore %u\n",
			    lcore_id);
		rte_free(ctx);
		return NULL;
	}

	ctx->record_capacity = jitter_record_count;
	ctx->lcore_id = lcore_id;
	ctx->primary_port_id = port_id;
	ctx->primary_queue_id = queue_id;
	ctx->msr_fd = -1;

	/* MSR init is deferred to jitter_pmc_lazy_init() */

	if (jitter_aer_enabled) {
		uint16_t off = jitter_pcie_find_aer_cap(port_id);
		if (off != 0) {
			ctx->aer_enabled = 1;
			ctx->aer_ports[0].port_id = port_id;
			ctx->aer_ports[0].aer_cap_offset = off;
			ctx->nb_aer_ports = 1;
		} else {
			TESTPMD_LOG(WARNING, "AER cap not found for port %u\n",
				    port_id);
		}
	}

	/* Seed context switch baselines via getrusage */
	{
		struct rusage ru;
		if (getrusage(RUSAGE_THREAD, &ru) == 0) {
			ctx->last_voluntary_cs = (uint64_t)ru.ru_nvcsw;
			ctx->last_nonvoluntary_cs = (uint64_t)ru.ru_nivcsw;
		}
	}

	/* Seed NIC stats baselines */
	struct rte_eth_stats stats;
	if (rte_eth_stats_get(port_id, &stats) == 0) {
		ctx->last_xstats[JITTER_XSTAT_RX_MISSED] =
			stats.imissed;
		ctx->last_xstats[JITTER_XSTAT_RX_NOMBUF] = stats.rx_nombuf;
		ctx->last_xstats[JITTER_XSTAT_IERRORS] = stats.ierrors;
	}

	/* Discover PMD-specific xstats */
	jitter_xstats_init(ctx, port_id);

	jitter_lcore_ctxs[lcore_id] = ctx;
	return ctx;
}

void
jitter_lcore_fini(struct jitter_lcore_ctx *ctx)
{
	if (ctx == NULL)
		return;

#if defined(RTE_ARCH_X86_64) && defined(RTE_EXEC_ENV_LINUX)
	jitter_pmc_teardown(ctx);
#endif

	if (ctx->msr_fd >= 0)
		close(ctx->msr_fd);

	rte_free(ctx->records);
	rte_free(ctx);
}

void
jitter_record_anomaly(struct jitter_lcore_ctx *ctx,
		      struct jitter_iter_state *st,
		      uint64_t tsc_end, uint64_t delta,
		      uint16_t nb_rx)
{
	struct jitter_record *r;

	r = &ctx->records[ctx->record_head % ctx->record_capacity];
	ctx->record_head++;
	ctx->total_anomalies++;

	memset(r, 0, sizeof(*r));
	r->tsc_start = st->tsc_start;
	r->tsc_end = tsc_end;
	r->tsc_delta = delta;
	r->lcore_id = ctx->lcore_id;
	r->port_id = st->port_id;
	r->queue_id = st->queue_id;
	r->nb_rx = nb_rx;
	r->rx_ring_depth_before = st->rx_ring_depth_before;
	{
		int cnt = rte_eth_rx_queue_count(st->port_id, st->queue_id);
		r->rx_ring_depth_after = cnt > 0 ? (uint32_t)cnt : 0;
	}

	/*
	 * Read context switches FIRST, before any cold-path syscalls.
	 * This captures only what happened during the forwarding iteration.
	 */
	struct rusage ru_before;
	if (getrusage(RUSAGE_THREAD, &ru_before) == 0) {
		r->voluntary_cs_delta = (uint64_t)ru_before.ru_nvcsw -
			ctx->last_voluntary_cs;
		r->nonvoluntary_cs_delta = (uint64_t)ru_before.ru_nivcsw -
			ctx->last_nonvoluntary_cs;
	}

#if defined(RTE_ARCH_X86_64) && defined(RTE_EXEC_ENV_LINUX)
	if (ctx->pmc_enabled) {
		uint64_t inst_end = jitter_rdpmc_read(ctx->pmc_inst_page);
		uint64_t cyc_end = jitter_rdpmc_read(ctx->pmc_cycles_page);
		r->inst_retired_delta = inst_end - st->inst_start;
		r->cycles_unhalted_delta = cyc_end - st->cycles_start;
	}
#endif

	if (ctx->msr_enabled) {
		uint64_t smi_now = jitter_msr_read(ctx->msr_fd, MSR_SMI_COUNT);
		uint64_t aperf = jitter_msr_read(ctx->msr_fd, MSR_IA32_APERF);
		uint64_t mperf = jitter_msr_read(ctx->msr_fd, MSR_IA32_MPERF);
		r->smi_count_delta = smi_now - ctx->last_smi_count;
		r->aperf_delta = aperf - ctx->last_aperf;
		r->mperf_delta = mperf - ctx->last_mperf;
		ctx->last_smi_count = smi_now;
		ctx->last_aperf = aperf;
		ctx->last_mperf = mperf;
	}

	/* AER */
	if (ctx->aer_enabled && ctx->nb_aer_ports > 0) {
		uint32_t corr = 0, uncorr = 0;
		jitter_pcie_read_aer(ctx->aer_ports[0].port_id,
				     ctx->aer_ports[0].aer_cap_offset,
				     &corr, &uncorr);
		r->aer_correctable_delta = corr - ctx->last_aer_correctable;
		r->aer_uncorrectable_delta = uncorr - ctx->last_aer_uncorrectable;
		ctx->last_aer_correctable = corr;
		ctx->last_aer_uncorrectable = uncorr;
	}

	/* NIC stats deltas */
	struct rte_eth_stats stats;
	if (rte_eth_stats_get(st->port_id, &stats) == 0) {
		r->rx_missed_delta = stats.imissed -
			ctx->last_xstats[JITTER_XSTAT_RX_MISSED];
		r->rx_nombuf_delta = stats.rx_nombuf -
			ctx->last_xstats[JITTER_XSTAT_RX_NOMBUF];
		r->ierrors_delta = stats.ierrors -
			ctx->last_xstats[JITTER_XSTAT_IERRORS];
		ctx->last_xstats[JITTER_XSTAT_RX_MISSED] =
			stats.imissed;
		ctx->last_xstats[JITTER_XSTAT_RX_NOMBUF] = stats.rx_nombuf;
		ctx->last_xstats[JITTER_XSTAT_IERRORS] = stats.ierrors;
	}

	/* Mempool avail count */
	if (ctx->mbuf_pool != NULL)
		r->mempool_avail = rte_mempool_avail_count(ctx->mbuf_pool);

	/* PMD-specific xstats */
	if (ctx->xstats.count > 0) {
		uint64_t values[JITTER_MAX_XSTATS];
		int ret;
		uint16_t i;

		ret = rte_eth_xstats_get_by_id(st->port_id,
					       ctx->xstats.ids, values,
					       ctx->xstats.count);
		if (ret == (int)ctx->xstats.count) {
			r->xstat_count = ctx->xstats.count;
			for (i = 0; i < ctx->xstats.count; i++) {
				r->xstat_deltas[i] = values[i] -
					ctx->xstats.last_values[i];
				ctx->xstats.last_values[i] = values[i];
			}
		}
	}

	/*
	 * Read context switches AGAIN after all cold-path work.
	 * Update baseline to this value so the next anomaly's delta
	 * excludes syscalls made by our own measurement code.
	 */
	struct rusage ru_after;
	if (getrusage(RUSAGE_THREAD, &ru_after) == 0) {
		ctx->last_voluntary_cs = (uint64_t)ru_after.ru_nvcsw;
		ctx->last_nonvoluntary_cs = (uint64_t)ru_after.ru_nivcsw;
	}
}

int
jitter_read_ctxt_switches(uint64_t *vcs, uint64_t *nvcs)
{
	char path[64];
	FILE *f;
	char line[256];

	*vcs = *nvcs = 0;
	snprintf(path, sizeof(path), "/proc/self/task/%d/status",
		 (int)rte_sys_gettid());
	f = fopen(path, "r");
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "voluntary_ctxt_switches:", 24) == 0)
			*vcs = strtoull(line + 24, NULL, 10);
		else if (strncmp(line, "nonvoluntary_ctxt_switches:", 27) == 0)
			*nvcs = strtoull(line + 27, NULL, 10);
	}
	fclose(f);
	return 0;
}

static const char * const jitter_xstat_positive[] = {
	"error", "err",
	"drop", "discard",
	"miss",
	"xon", "xoff",
	"pci",
	"stall",
	"overflow",
	"out_of_buffer", "nombuf",
	"crc",
	"timeout",
	"dma_err",
};

static const char * const jitter_xstat_negative[] = {
	"ipsec",
	"crypto",
	"filter_add",
	"filter_remove",
	"filter_miss",
	"mac_filter",
	"vlan_tag",
	"tag_filter",
	"ttl_zero",
	"tso",
	"too_many_segs",
	"match_crc",
	"gft_filter",
	"security",
	"secdrp",
	"sa_hit",
	"cls_drop",
};

static int
jitter_xstat_name_match(const char *name)
{
	unsigned int i;
	int matched = 0;

	for (i = 0; i < RTE_DIM(jitter_xstat_positive); i++) {
		if (strcasestr(name, jitter_xstat_positive[i]) != NULL) {
			matched = 1;
			break;
		}
	}
	if (!matched)
		return 0;

	for (i = 0; i < RTE_DIM(jitter_xstat_negative); i++) {
		if (strcasestr(name, jitter_xstat_negative[i]) != NULL)
			return 0;
	}
	return 1;
}

void
jitter_xstats_init(struct jitter_lcore_ctx *ctx, uint16_t port_id)
{
	struct rte_eth_xstat_name *names;
	struct rte_eth_xstat *values;
	int nb_xstats, i;

	ctx->xstats.count = 0;

	nb_xstats = rte_eth_xstats_get_names(port_id, NULL, 0);
	if (nb_xstats <= 0)
		return;

	names = malloc(sizeof(*names) * nb_xstats);
	values = malloc(sizeof(*values) * nb_xstats);
	if (names == NULL || values == NULL) {
		free(names);
		free(values);
		return;
	}

	if (rte_eth_xstats_get_names(port_id, names, nb_xstats) != nb_xstats ||
	    rte_eth_xstats_get(port_id, values, nb_xstats) != nb_xstats) {
		free(names);
		free(values);
		return;
	}

	for (i = 0; i < nb_xstats; i++) {
		if (ctx->xstats.count >= JITTER_MAX_XSTATS)
			break;
		if (!jitter_xstat_name_match(names[i].name))
			continue;

		ctx->xstats.ids[ctx->xstats.count] = values[i].id;
		strlcpy(ctx->xstats.names[ctx->xstats.count],
			names[i].name, RTE_ETH_XSTATS_NAME_SIZE);
		ctx->xstats.last_values[ctx->xstats.count] = values[i].value;
		ctx->xstats.count++;
	}

	free(names);
	free(values);

	if (ctx->xstats.count > 0) {
		uint16_t j;

		TESTPMD_LOG(NOTICE, "Jitter: discovered %u xstats for port %u:\n",
			    ctx->xstats.count, port_id);
		for (j = 0; j < ctx->xstats.count; j++)
			TESTPMD_LOG(NOTICE, "  xstat[%u]: %s (id=%" PRIu64 ")\n",
				    j, ctx->xstats.names[j],
				    ctx->xstats.ids[j]);
	}
}

void
jitter_pmc_lazy_init(struct jitter_lcore_ctx *ctx)
{
	ctx->pmc_init_done = 1;
#if defined(RTE_ARCH_X86_64) && defined(RTE_EXEC_ENV_LINUX)
	{
		int cpu = sched_getcpu();
		if (cpu < 0)
			cpu = 0;
		if (jitter_pmc_setup(ctx, cpu) < 0)
			TESTPMD_LOG(WARNING, "PMC setup failed for lcore %u "
				    "(rdpmc disabled)\n", ctx->lcore_id);
		else
			TESTPMD_LOG(NOTICE, "PMC setup OK for lcore %u cpu %d\n",
				    ctx->lcore_id, cpu);

		if (jitter_msr_enabled) {
			ctx->msr_fd = jitter_msr_open(cpu);
			if (ctx->msr_fd >= 0) {
				ctx->msr_enabled = 1;
				ctx->last_smi_count = jitter_msr_read(
					ctx->msr_fd, MSR_SMI_COUNT);
				ctx->last_aperf = jitter_msr_read(
					ctx->msr_fd, MSR_IA32_APERF);
				ctx->last_mperf = jitter_msr_read(
					ctx->msr_fd, MSR_IA32_MPERF);
				TESTPMD_LOG(NOTICE, "MSR setup OK for lcore %u "
					    "cpu %d\n", ctx->lcore_id, cpu);
			} else {
				TESTPMD_LOG(WARNING, "MSR open failed for "
					    "lcore %u cpu %d (MSR disabled)\n",
					    ctx->lcore_id, cpu);
			}
		}
	}
#endif
}

void
jitter_set_threshold_us(uint64_t us)
{
	jitter_threshold_us_val = us;
	jitter_threshold_cycles = (rte_get_tsc_hz() * us) / 1000000ULL;
	TESTPMD_LOG(DEBUG, "Jitter threshold set to %" PRIu64 " us "
		    "(%" PRIu64 " cycles)\n", us, jitter_threshold_cycles);
}
