/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Red Hat, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_log.h>

#include "testpmd.h"
#include "jitter.h"

#if defined(RTE_ARCH_X86_64) && defined(RTE_EXEC_ENV_LINUX)

#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>

static long
perf_event_open_wrapper(struct perf_event_attr *attr, pid_t pid, int cpu,
			int group_fd, unsigned long flags)
{
	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

int
jitter_pmc_setup(struct jitter_lcore_ctx *ctx, int cpu)
{
	struct perf_event_attr attr;
	int fd_inst, fd_cyc;
	void *p;

	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_HARDWARE;
	attr.size = sizeof(attr);
	attr.config = PERF_COUNT_HW_INSTRUCTIONS;
	attr.disabled = 0;
	attr.exclude_kernel = 0;
	attr.exclude_hv = 1;
	attr.pinned = 1;
	attr.sample_period = 0;
	attr.wakeup_events = 0;

	fd_inst = perf_event_open_wrapper(&attr, 0, cpu, -1, 0);
	if (fd_inst < 0) {
		TESTPMD_LOG(WARNING, "perf_event_open(INSTRUCTIONS) failed: %s\n",
			    strerror(errno));
		return -errno;
	}

	p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd_inst, 0);
	if (p == MAP_FAILED) {
		close(fd_inst);
		return -errno;
	}
	ctx->pmc_inst_page = p;
	ctx->pmc_inst_fd = fd_inst;

	/* User-only instructions (exclude_kernel=1) */
	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_HARDWARE;
	attr.size = sizeof(attr);
	attr.config = PERF_COUNT_HW_INSTRUCTIONS;
	attr.exclude_kernel = 1;
	attr.exclude_hv = 1;
	int fd_inst_user = perf_event_open_wrapper(&attr, 0, cpu, -1, 0);
	if (fd_inst_user < 0) {
		TESTPMD_LOG(WARNING, "perf_event_open(INSTRUCTIONS user-only) "
			    "failed: %s (user inst disabled)\n",
			    strerror(errno));
		ctx->pmc_inst_user_page = NULL;
		ctx->pmc_inst_user_fd = 0;
	} else {
		p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd_inst_user, 0);
		if (p == MAP_FAILED) {
			close(fd_inst_user);
			ctx->pmc_inst_user_page = NULL;
			ctx->pmc_inst_user_fd = 0;
		} else {
			ctx->pmc_inst_user_page = p;
			ctx->pmc_inst_user_fd = fd_inst_user;
		}
	}
	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_HARDWARE;
	attr.size = sizeof(attr);
	attr.config = PERF_COUNT_HW_CPU_CYCLES;
	attr.exclude_hv = 1;
	attr.pinned = 1;
	fd_cyc = perf_event_open_wrapper(&attr, 0, cpu, -1, 0);
	if (fd_cyc < 0) {
		TESTPMD_LOG(WARNING, "perf_event_open(CYCLES) failed: %s\n",
			    strerror(errno));
		munmap(ctx->pmc_inst_page, 4096);
		ctx->pmc_inst_page = NULL;
		close(fd_inst);
		return -errno;
	}

	p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd_cyc, 0);
	if (p == MAP_FAILED) {
		close(fd_cyc);
		munmap(ctx->pmc_inst_page, 4096);
		ctx->pmc_inst_page = NULL;
		close(fd_inst);
		return -errno;
	}
	ctx->pmc_cycles_page = p;
	ctx->pmc_cycles_fd = fd_cyc;

	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_HARDWARE;
	attr.size = sizeof(attr);
	attr.config = PERF_COUNT_HW_REF_CPU_CYCLES;
	attr.exclude_hv = 1;
	int fd_ref = perf_event_open_wrapper(&attr, 0, cpu, -1, 0);
	if (fd_ref < 0) {
		TESTPMD_LOG(WARNING, "perf_event_open(REF_CYCLES) failed: %s "
			    "(ref_cycles disabled)\n", strerror(errno));
		ctx->pmc_ref_cycles_page = NULL;
		ctx->pmc_ref_cycles_fd = 0;
	} else {
		p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd_ref, 0);
		if (p == MAP_FAILED) {
			close(fd_ref);
			ctx->pmc_ref_cycles_page = NULL;
			ctx->pmc_ref_cycles_fd = 0;
		} else {
			ctx->pmc_ref_cycles_page = p;
			ctx->pmc_ref_cycles_fd = fd_ref;
		}
	}

	/* Platform-specific raw events for cross-core contention diagnosis.
	 * OCR events use PERF_TYPE_RAW with config1 for the offcore filter. */
	struct {
		uint64_t config;
		uint64_t config1;
		const char *name;
		struct perf_event_mmap_page **page;
		int *fd;
	} raw_events[] = {
		{ 0x1b7, 0x10003c0001, "ocr.demand_data_rd.l3_hit.snoop_hitm",
		  &ctx->pmc_ocr_hitm_page, &ctx->pmc_ocr_hitm_fd },
		{ 0x1b7, 0x8003c0001, "ocr.demand_data_rd.l3_hit.snoop_hit_with_fwd",
		  &ctx->pmc_ocr_fwd_page, &ctx->pmc_ocr_fwd_fd },
		{ 0x1b7, 0x3fbfc00001, "ocr.demand_data_rd.l3_miss",
		  &ctx->pmc_ocr_l3miss_page, &ctx->pmc_ocr_l3miss_fd },
		{ 0x2c3, 0, "machine_clears.memory_ordering",
		  &ctx->pmc_mclr_memord_page, &ctx->pmc_mclr_memord_fd },
	};

	for (unsigned i = 0; i < RTE_DIM(raw_events); i++) {
		memset(&attr, 0, sizeof(attr));
		attr.type = PERF_TYPE_RAW;
		attr.size = sizeof(attr);
		attr.config = raw_events[i].config;
		attr.config1 = raw_events[i].config1;
		attr.disabled = 0;
		attr.exclude_kernel = 0;
		attr.exclude_hv = 1;
		attr.pinned = 0;

		int raw_fd = perf_event_open_wrapper(&attr, 0, cpu, -1, 0);
		if (raw_fd < 0) {
			TESTPMD_LOG(INFO, "%s not available on this platform\n",
				    raw_events[i].name);
			*raw_events[i].page = NULL;
			*raw_events[i].fd = 0;
		} else {
			p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, raw_fd, 0);
			if (p == MAP_FAILED) {
				close(raw_fd);
				*raw_events[i].page = NULL;
				*raw_events[i].fd = 0;
			} else {
				*raw_events[i].page = p;
				*raw_events[i].fd = raw_fd;
			}
		}
	}

	ctx->pmc_enabled = 1;
	return 0;
}

void
jitter_pmc_teardown(struct jitter_lcore_ctx *ctx)
{
	if (ctx->pmc_inst_page != NULL) {
		munmap(ctx->pmc_inst_page, 4096);
		ctx->pmc_inst_page = NULL;
	}
	if (ctx->pmc_inst_fd > 0) {
		close(ctx->pmc_inst_fd);
		ctx->pmc_inst_fd = 0;
	}
	if (ctx->pmc_inst_user_page != NULL) {
		munmap(ctx->pmc_inst_user_page, 4096);
		ctx->pmc_inst_user_page = NULL;
	}
	if (ctx->pmc_inst_user_fd > 0) {
		close(ctx->pmc_inst_user_fd);
		ctx->pmc_inst_user_fd = 0;
	}
	if (ctx->pmc_cycles_page != NULL) {
		munmap(ctx->pmc_cycles_page, 4096);
		ctx->pmc_cycles_page = NULL;
	}
	if (ctx->pmc_cycles_fd > 0) {
		close(ctx->pmc_cycles_fd);
		ctx->pmc_cycles_fd = 0;
	}
	if (ctx->pmc_ref_cycles_page != NULL) {
		munmap(ctx->pmc_ref_cycles_page, 4096);
		ctx->pmc_ref_cycles_page = NULL;
	}
	if (ctx->pmc_ref_cycles_fd > 0) {
		close(ctx->pmc_ref_cycles_fd);
		ctx->pmc_ref_cycles_fd = 0;
	}
	if (ctx->pmc_ocr_hitm_page != NULL) {
		munmap(ctx->pmc_ocr_hitm_page, 4096);
		ctx->pmc_ocr_hitm_page = NULL;
	}
	if (ctx->pmc_ocr_hitm_fd > 0) {
		close(ctx->pmc_ocr_hitm_fd);
		ctx->pmc_ocr_hitm_fd = 0;
	}
	if (ctx->pmc_ocr_fwd_page != NULL) {
		munmap(ctx->pmc_ocr_fwd_page, 4096);
		ctx->pmc_ocr_fwd_page = NULL;
	}
	if (ctx->pmc_ocr_fwd_fd > 0) {
		close(ctx->pmc_ocr_fwd_fd);
		ctx->pmc_ocr_fwd_fd = 0;
	}
	if (ctx->pmc_ocr_l3miss_page != NULL) {
		munmap(ctx->pmc_ocr_l3miss_page, 4096);
		ctx->pmc_ocr_l3miss_page = NULL;
	}
	if (ctx->pmc_ocr_l3miss_fd > 0) {
		close(ctx->pmc_ocr_l3miss_fd);
		ctx->pmc_ocr_l3miss_fd = 0;
	}
	if (ctx->pmc_mclr_memord_page != NULL) {
		munmap(ctx->pmc_mclr_memord_page, 4096);
		ctx->pmc_mclr_memord_page = NULL;
	}
	if (ctx->pmc_mclr_memord_fd > 0) {
		close(ctx->pmc_mclr_memord_fd);
		ctx->pmc_mclr_memord_fd = 0;
	}
	ctx->pmc_enabled = 0;
}

#else /* !x86_64 || !Linux */

int
jitter_pmc_setup(struct jitter_lcore_ctx *ctx __rte_unused,
		 int cpu __rte_unused)
{
	return -ENOTSUP;
}

void
jitter_pmc_teardown(struct jitter_lcore_ctx *ctx __rte_unused)
{
}

#endif
