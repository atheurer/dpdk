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
	attr.config = PERF_COUNT_HW_INSTRUCTIONS;
	attr.exclude_kernel = 1;
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
	attr.exclude_kernel = 0;

	attr.config = PERF_COUNT_HW_CPU_CYCLES;
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

	attr.config = PERF_COUNT_HW_REF_CPU_CYCLES;
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

	/* LLC misses (optional — uses a programmable PMC slot) */
	attr.config = PERF_COUNT_HW_CACHE_MISSES;
	int fd_llc = perf_event_open_wrapper(&attr, 0, cpu, -1, 0);
	if (fd_llc < 0) {
		TESTPMD_LOG(WARNING, "perf_event_open(CACHE_MISSES) failed: %s "
			    "(LLC misses disabled)\n", strerror(errno));
		ctx->pmc_llc_misses_page = NULL;
		ctx->pmc_llc_misses_fd = 0;
	} else {
		p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd_llc, 0);
		if (p == MAP_FAILED) {
			close(fd_llc);
			ctx->pmc_llc_misses_page = NULL;
			ctx->pmc_llc_misses_fd = 0;
		} else {
			ctx->pmc_llc_misses_page = p;
			ctx->pmc_llc_misses_fd = fd_llc;
		}
	}

	/* Branch misses (optional — uses a programmable PMC slot) */
	attr.config = PERF_COUNT_HW_BRANCH_MISSES;
	int fd_br = perf_event_open_wrapper(&attr, 0, cpu, -1, 0);
	if (fd_br < 0) {
		TESTPMD_LOG(WARNING, "perf_event_open(BRANCH_MISSES) failed: %s "
			    "(branch misses disabled)\n", strerror(errno));
		ctx->pmc_branch_misses_page = NULL;
		ctx->pmc_branch_misses_fd = 0;
	} else {
		p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd_br, 0);
		if (p == MAP_FAILED) {
			close(fd_br);
			ctx->pmc_branch_misses_page = NULL;
			ctx->pmc_branch_misses_fd = 0;
		} else {
			ctx->pmc_branch_misses_page = p;
			ctx->pmc_branch_misses_fd = fd_br;
		}
	}

	/* Platform-specific raw events (Sierra Forest / Crestmont) */
	struct {
		uint64_t config;
		const char *name;
		struct perf_event_mmap_page **page;
		int *fd;
	} raw_events[] = {
		{ 0x7834, "mem_bound_stalls_load.llc_miss",
		  &ctx->pmc_mem_stalls_llc_miss_page,
		  &ctx->pmc_mem_stalls_llc_miss_fd },
		{ 0x0634, "mem_bound_stalls_load.llc_hit",
		  &ctx->pmc_mem_stalls_llc_hit_page,
		  &ctx->pmc_mem_stalls_llc_hit_fd },
		{ 0x4f2e, "longest_lat_cache.reference",
		  &ctx->pmc_llc_refs_page,
		  &ctx->pmc_llc_refs_fd },
	};

	for (unsigned i = 0; i < RTE_DIM(raw_events); i++) {
		memset(&attr, 0, sizeof(attr));
		attr.type = PERF_TYPE_RAW;
		attr.size = sizeof(attr);
		attr.config = raw_events[i].config;
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
	if (ctx->pmc_llc_misses_page != NULL) {
		munmap(ctx->pmc_llc_misses_page, 4096);
		ctx->pmc_llc_misses_page = NULL;
	}
	if (ctx->pmc_llc_misses_fd > 0) {
		close(ctx->pmc_llc_misses_fd);
		ctx->pmc_llc_misses_fd = 0;
	}
	if (ctx->pmc_branch_misses_page != NULL) {
		munmap(ctx->pmc_branch_misses_page, 4096);
		ctx->pmc_branch_misses_page = NULL;
	}
	if (ctx->pmc_branch_misses_fd > 0) {
		close(ctx->pmc_branch_misses_fd);
		ctx->pmc_branch_misses_fd = 0;
	}
	if (ctx->pmc_mem_stalls_llc_miss_page != NULL) {
		munmap(ctx->pmc_mem_stalls_llc_miss_page, 4096);
		ctx->pmc_mem_stalls_llc_miss_page = NULL;
	}
	if (ctx->pmc_mem_stalls_llc_miss_fd > 0) {
		close(ctx->pmc_mem_stalls_llc_miss_fd);
		ctx->pmc_mem_stalls_llc_miss_fd = 0;
	}
	if (ctx->pmc_mem_stalls_llc_hit_page != NULL) {
		munmap(ctx->pmc_mem_stalls_llc_hit_page, 4096);
		ctx->pmc_mem_stalls_llc_hit_page = NULL;
	}
	if (ctx->pmc_mem_stalls_llc_hit_fd > 0) {
		close(ctx->pmc_mem_stalls_llc_hit_fd);
		ctx->pmc_mem_stalls_llc_hit_fd = 0;
	}
	if (ctx->pmc_llc_refs_page != NULL) {
		munmap(ctx->pmc_llc_refs_page, 4096);
		ctx->pmc_llc_refs_page = NULL;
	}
	if (ctx->pmc_llc_refs_fd > 0) {
		close(ctx->pmc_llc_refs_fd);
		ctx->pmc_llc_refs_fd = 0;
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
