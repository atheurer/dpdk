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
	if (ctx->pmc_cycles_page != NULL) {
		munmap(ctx->pmc_cycles_page, 4096);
		ctx->pmc_cycles_page = NULL;
	}
	if (ctx->pmc_cycles_fd > 0) {
		close(ctx->pmc_cycles_fd);
		ctx->pmc_cycles_fd = 0;
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
