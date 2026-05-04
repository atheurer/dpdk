/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Red Hat, Inc.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>

#include <rte_common.h>
#include <rte_log.h>

#include "testpmd.h"
#include "jitter.h"

#if defined(RTE_EXEC_ENV_LINUX)

int
jitter_msr_open(int cpu)
{
	char path[64];
	int fd;

	snprintf(path, sizeof(path), "/dev/cpu/%d/msr", cpu);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		TESTPMD_LOG(WARNING, "Cannot open %s: %s "
			    "(is the msr module loaded?)\n",
			    path, strerror(errno));
	return fd;
}

uint64_t
jitter_msr_read(int fd, uint32_t msr)
{
	uint64_t val = 0;

	if (fd < 0)
		return 0;
	if (pread(fd, &val, sizeof(val), msr) != sizeof(val))
		return 0;
	return val;
}

#else /* !Linux */

int
jitter_msr_open(int cpu __rte_unused)
{
	return -1;
}

uint64_t
jitter_msr_read(int fd __rte_unused, uint32_t msr __rte_unused)
{
	return 0;
}

#endif
