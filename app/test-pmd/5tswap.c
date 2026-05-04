/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2014-2020 Mellanox Technologies, Ltd
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_flow.h>

#include "testpmd.h"
#include "5tswap.h"
#include "jitter.h"

/*
 * 5 tuple swap forwarding mode: Swap the source and the destination of layers
 * 2,3,4. Swaps source and destination for MAC, IPv4/IPv6, UDP/TCP.
 * Parses each layer and swaps it. When the next layer doesn't match it stops.
 */
static bool
pkt_burst_5tuple_swap(struct fwd_stream *fs)
{
	struct rte_mbuf  *pkts_burst[MAX_PKT_BURST];
	struct jitter_iter_state js;
	uint16_t nb_rx;

	jitter_iter_begin(fs->jitter_ctx, &js, fs->rx_port, fs->rx_queue);

	nb_rx = common_fwd_stream_receive(fs, pkts_burst, nb_pkt_per_burst);
	jitter_mark_rx(fs->jitter_ctx, &js);
	if (unlikely(nb_rx == 0)) {
		jitter_iter_end(fs->jitter_ctx, &js, 0);
		return false;
	}

	do_5tswap(pkts_burst, nb_rx, fs);
	jitter_mark_process(fs->jitter_ctx, &js);

	common_fwd_stream_transmit(fs, pkts_burst, nb_rx);

	jitter_iter_end(fs->jitter_ctx, &js, nb_rx);
	return true;
}

struct fwd_engine five_tuple_swap_fwd_engine = {
	.fwd_mode_name  = "5tswap",
	.stream_init    = common_fwd_stream_init,
	.packet_fwd     = pkt_burst_5tuple_swap,
};
