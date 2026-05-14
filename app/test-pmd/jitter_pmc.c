/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Red Hat, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

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

	/*
	 * OCR events via direct MSR programming — bypasses perf_event_open
	 * to avoid PMI interrupt storm on isolated CPUs.
	 *
	 * Uses PMC slots 6 and 7 (typically unused by perf_event_open).
	 * PERFEVTSEL format: EN(22) | OS(17) | USR(16) | umask(15:8) | event(7:0)
	 * INT bit (20) is NOT set — no overflow interrupts.
	 *
	 * OCR events use event code 0xB7:
	 *   umask=0x01 → filter in MSR_OFFCORE_RSP_0 (0x1A6)
	 *   umask=0x02 → filter in MSR_OFFCORE_RSP_1 (0x1A7)
	 */
#define IA32_PERFEVTSEL6  0x18C
#define IA32_PERFEVTSEL7  0x18D
#define IA32_PMC6         0xC7
#define IA32_PMC7         0xC8
#define MSR_OFFCORE_RSP_0 0x1A6
#define MSR_OFFCORE_RSP_1 0x1A7
#define PERFEVTSEL_EN     (1ULL << 22)
#define PERFEVTSEL_OS     (1ULL << 17)
#define PERFEVTSEL_USR    (1ULL << 16)

	{
		char msr_path[64];
		snprintf(msr_path, sizeof(msr_path), "/dev/cpu/%d/msr", cpu);
		int msr_fd = open(msr_path, O_RDWR);
		if (msr_fd < 0) {
			TESTPMD_LOG(WARNING, "Cannot open %s for OCR MSR "
				    "programming: %s\n", msr_path,
				    strerror(errno));
		} else {
			uint64_t evtsel, rsp;

			/* Slot 6: mem_bound_stalls_load.all
			 * (event=0x34, umask=0x7F) */
			evtsel = PERFEVTSEL_EN | PERFEVTSEL_OS |
				 PERFEVTSEL_USR | (0x7FULL << 8) | 0x34;
			pwrite(msr_fd, &evtsel, 8, IA32_PERFEVTSEL6);
			ctx->ocr_msr_fd = msr_fd;
			ctx->ocr_slot6_enabled = 1;
			TESTPMD_LOG(NOTICE, "MSR slot 6: mem_bound_stalls_load"
				    ".all (direct, no interrupts)\n");

			/* Slot 7: mem_bound_stalls_load.l2_hit
			 * (event=0x34, umask=0x01) */
			evtsel = PERFEVTSEL_EN | PERFEVTSEL_OS |
				 PERFEVTSEL_USR | (0x01ULL << 8) | 0x34;
			pwrite(msr_fd, &evtsel, 8, IA32_PERFEVTSEL7);
			ctx->ocr_slot7_enabled = 1;
			TESTPMD_LOG(NOTICE, "MSR slot 7: mem_bound_stalls_load"
				    ".l2_hit (direct, no interrupts)\n");
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
	/* Disable MSR-programmed OCR counters */
	if (ctx->ocr_msr_fd > 0) {
		uint64_t zero = 0;
		if (ctx->ocr_slot6_enabled) {
			pwrite(ctx->ocr_msr_fd, &zero, 8, IA32_PERFEVTSEL6);
			ctx->ocr_slot6_enabled = 0;
		}
		if (ctx->ocr_slot7_enabled) {
			pwrite(ctx->ocr_msr_fd, &zero, 8, IA32_PERFEVTSEL7);
			ctx->ocr_slot7_enabled = 0;
		}
		close(ctx->ocr_msr_fd);
		ctx->ocr_msr_fd = 0;
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
