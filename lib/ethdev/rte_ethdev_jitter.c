/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Red Hat, Inc.
 */

#include "rte_ethdev_jitter.h"

struct rte_ethdev_rx_burst_tsc
	rte_ethdev_rx_burst_tsc[RTE_ETHDEV_JITTER_MAX_PORTS]
			       [RTE_ETHDEV_JITTER_MAX_QUEUES];

uint64_t rte_ethdev_rx_burst_pmc_threshold;
