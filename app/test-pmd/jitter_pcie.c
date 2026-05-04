/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Red Hat, Inc.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_pci.h>
#include <bus_pci_driver.h>

#include "testpmd.h"
#include "jitter.h"

#define PCI_EXT_CAP_ID_ERR    0x0001
#define PCI_ERR_UNCOR_STATUS  0x04
#define PCI_ERR_COR_STATUS    0x10

uint16_t
jitter_pcie_find_aer_cap(uint16_t port_id)
{
	struct rte_eth_dev_info dev_info;
	struct rte_device *rdev;
	struct rte_pci_device *pci_dev;
	uint32_t header;
	uint16_t offset = 0x100;

	if (rte_eth_dev_info_get(port_id, &dev_info) != 0)
		return 0;
	rdev = dev_info.device;
	if (rdev == NULL)
		return 0;

	pci_dev = RTE_DEV_TO_PCI(rdev);
	if (pci_dev == NULL)
		return 0;

	while (offset != 0 && offset < 0x1000) {
		if (rte_pci_read_config(pci_dev, &header, 4, offset) != 4)
			return 0;
		if ((header & 0xFFFF) == PCI_EXT_CAP_ID_ERR)
			return offset;
		offset = (header >> 20) & 0xFFC;
	}
	return 0;
}

int
jitter_pcie_read_aer(uint16_t port_id, uint16_t aer_off,
		     uint32_t *correctable, uint32_t *uncorrectable)
{
	struct rte_eth_dev_info dev_info;
	struct rte_device *rdev;
	struct rte_pci_device *pci_dev;

	*correctable = 0;
	*uncorrectable = 0;

	if (rte_eth_dev_info_get(port_id, &dev_info) != 0)
		return -1;
	rdev = dev_info.device;
	if (rdev == NULL)
		return -1;
	pci_dev = RTE_DEV_TO_PCI(rdev);
	if (pci_dev == NULL)
		return -1;

	rte_pci_read_config(pci_dev, uncorrectable, 4,
			    aer_off + PCI_ERR_UNCOR_STATUS);
	rte_pci_read_config(pci_dev, correctable, 4,
			    aer_off + PCI_ERR_COR_STATUS);
	return 0;
}
