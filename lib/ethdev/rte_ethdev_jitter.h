/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Red Hat, Inc.
 *
 * Shared rx_burst timing data between PMDs and applications.
 * PMDs write, applications read. No struct dependency required.
 */

#ifndef _RTE_ETHDEV_JITTER_H_
#define _RTE_ETHDEV_JITTER_H_

#include <stdint.h>
#include <rte_cycles.h>

#define RTE_ETHDEV_JITTER_MAX_PORTS  32
#define RTE_ETHDEV_JITTER_MAX_QUEUES 16

struct rte_ethdev_rx_burst_tsc {
	uint64_t start;
	uint64_t poll;
	uint64_t alloc;
	uint64_t wqe;
	/* Conditional PMC snapshot — only populated when poll exceeds threshold */
	uint64_t poll_mem_stall_all;
	uint64_t poll_mem_stall_l2hit;
	uint8_t  poll_pmc_valid;
};

/* Threshold in TSC cycles for triggering PMC reads inside rx_burst.
 * Set by testpmd at init; 0 = disabled. */
extern uint64_t rte_ethdev_rx_burst_pmc_threshold;

extern struct rte_ethdev_rx_burst_tsc
	rte_ethdev_rx_burst_tsc[RTE_ETHDEV_JITTER_MAX_PORTS]
			       [RTE_ETHDEV_JITTER_MAX_QUEUES];

static inline void
rte_ethdev_rx_burst_tsc_begin(uint16_t port_id, uint16_t queue_id)
{
	if (port_id < RTE_ETHDEV_JITTER_MAX_PORTS &&
	    queue_id < RTE_ETHDEV_JITTER_MAX_QUEUES) {
		struct rte_ethdev_rx_burst_tsc *t =
			&rte_ethdev_rx_burst_tsc[port_id][queue_id];
		t->start = rte_rdtsc();
		t->poll = 0;
		t->alloc = 0;
		t->wqe = 0;
		t->poll_pmc_valid = 0;
	}
}

/* Direct rdpmc read by counter index (no perf_event mmap page needed).
 * Requires CR4.PCE set (/sys/bus/event_source/devices/cpu/rdpmc >= 2). */
#if defined(RTE_ARCH_X86_64)
static inline uint64_t
rte_ethdev_jitter_rdpmc(uint32_t idx)
{
	uint32_t low, high;
	__asm__ volatile("rdpmc" : "=a"(low), "=d"(high) : "c"(idx));
	return ((uint64_t)high << 32) | low;
}
#endif

#endif /* _RTE_ETHDEV_JITTER_H_ */
