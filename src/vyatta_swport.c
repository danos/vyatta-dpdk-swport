/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: (LGPL-2.1-only AND BSD-3-Clause)
 */
/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the name of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <arpa/inet.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_string_fns.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ethdev_vdev.h>
#include <rte_kvargs.h>
#include <rte_atomic.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_version.h>
#include "../include/vyatta_swport.h"
#include "onie_tlvinfo.h"

#define SWP_LOG(l, t, ...) rte_log(RTE_LOG_ ## l, \
				   RTE_LOGTYPE_USER1, # t ": " __VA_ARGS__)

#define SWP_DEBUG(...) SWP_LOG(DEBUG, SW_PORT, __VA_ARGS__)
#define SWP_INFO(...) SWP_LOG(INFO, SW_PORT,  __VA_ARGS__)
#define SWP_ERROR(...) SWP_LOG(ERR, SW_PORT, __VA_ARGS__)

#define DPDK_SW_PORT_ARG	"sw_port_args"

static const char * const valid_arguments[] = {
	DPDK_SW_PORT_ARG,
	NULL
};

struct switch_port_queue {
	struct sw_port *switch_port;
	struct rte_ring *ring;
	uint8_t qid;
	rte_atomic64_t pkts;
	rte_atomic64_t err_pkts;
};

struct sw_port {
	uint16_t port_id; /* port dpdk_id */
	uint16_t carrier_port; /* bp interconnect dpdk id */
	uint16_t flags;
	uint16_t (*fal_tx)(void *fal_info, uint16_t carrier, uint16_t port,
			   struct rte_mbuf **bufs, uint16_t nb_bufs);
	int32_t (*fal_tx_framer)(void *sw_port, void *fal_info,
				 struct rte_mbuf **bufs);
	char *name;
	unsigned int numa_node;
	int unit;
	int port;
	unsigned int max_rx_queues;
	unsigned int max_tx_queues;
	struct rte_eth_dev *carrier_dev;

	struct switch_port_queue rx_queues[SW_P_PMD_MAX_RX_QUEUE];

	struct ether_addr address;
	struct rte_eth_dev *dev;
	const struct eth_dev_ops *fal_dev_ops;
	void *fal_private;
	int (*plugin_detach_device)(const char *name);

	struct swport_dev_info sw_dev_info;
};

static int (*switch_port_prep_header_change)(struct rte_mbuf **m,
					     uint16_t header_len);
static uint8_t prep_header_change_bytes;

static struct sw_port *
fp_port2swport[MAX_HW_SWITCH_DEVICES][MAX_HW_SWITCH_PORTS];

static const char *drivername = "sw_port_vdev_pmd";

static struct platform_param {
	struct ether_addr base_mac_addr;
	uint16_t num_mac_addr;
	uint8_t num_reserved_macs;
} platform_cfg;

static bool is_valid_tlv(struct tlvinfo_tlv *tlv)
{
	return (tlv->type != 0x00) && (tlv->type != 0xFF);
}

static bool is_valid_tlvinfo_header(struct tlvinfo_header *hdr,
				    uint16_t end_stop)
{
	return (strcmp(hdr->signature, TLV_INFO_ID_STRING) == 0) &&
	       (hdr->version == TLV_INFO_VERSION) &&
	       (ntohs(hdr->totallen) <= end_stop);
}

static struct tlvinfo_tlv *
tlvinfo_get_tlv(unsigned char *onie, u_int8_t tcode, uint32_t end_stop)
{
	struct tlvinfo_header *onie_hdr = (struct tlvinfo_header *)onie;
	uint32_t end, offset =  sizeof(struct tlvinfo_header);
	struct tlvinfo_tlv *tlv;

	/* Search through the TLVs, looking for the first one which matches the
	 * supplied type code
	 */
	end = sizeof(struct tlvinfo_header) + ntohs(onie_hdr->totallen);
	end = min(end, end_stop);

	while (offset  < end) {
		tlv = (struct tlvinfo_tlv *) &onie[offset];
		if (!is_valid_tlv(tlv))
			return NULL;

		if (tlv->type == tcode)
			return tlv;

		offset += sizeof(struct tlvinfo_tlv) + tlv->length;
	}
	return NULL;
}

bool __attribute__ ((externally_visible))
sw_port_register_onie_prom(unsigned char *prom, uint16_t length,
			   uint8_t reserved_macs)
{
	struct tlvinfo_tlv *tlv;

	if (!is_valid_tlvinfo_header((struct tlvinfo_header *)prom,
				     length)) {
		SWP_ERROR("Invalid onie format passed\n");
		return false;
	}

	tlv = tlvinfo_get_tlv(prom,  TLV_CODE_MAC_BASE, length);
	if (!tlv) {
		SWP_ERROR("onie TLV_CODE_MAC_BASE not found\n");
		goto error;
	}

	memcpy(&platform_cfg.base_mac_addr, tlv->value, ETHER_ADDR_LEN);

	tlv = tlvinfo_get_tlv(prom, TLV_CODE_MAC_SIZE, length);
	if (!tlv) {
		SWP_ERROR("onie TLV_CODE_MAC_SIZE not found\n");
		goto error;
	}
	platform_cfg.num_mac_addr = (tlv->value[0] << 8) | tlv->value[1];
	platform_cfg.num_reserved_macs = reserved_macs;
	return true;

error:
	platform_cfg.num_mac_addr = 0;
	return false;
}

bool __attribute__ ((externally_visible))
sw_port_request_mac_addr(struct ether_addr *addr, uint8_t offset)
{
	uint32_t mac;

	if (!platform_cfg.num_mac_addr ||
	    offset > platform_cfg.num_mac_addr)
		return false;

	/* Increament the non OUI part of the mac */
	mac = platform_cfg.base_mac_addr.addr_bytes[5] +
		(platform_cfg.base_mac_addr.addr_bytes[4] << 8) +
		(platform_cfg.base_mac_addr.addr_bytes[3] << 16) +
		offset;

	memcpy(addr, &platform_cfg.base_mac_addr, ETHER_ADDR_LEN);
	addr->addr_bytes[5] = mac;
	addr->addr_bytes[4] = mac >> 8;
	addr->addr_bytes[3] = mac >> 16;

	return true;
}

/*
 * When in non BP interconnect mode, then supply a routine to poll
 * a switch port's receive rings.
 */
static uint16_t
switch_port_rx(void *q, struct rte_mbuf **bufs, uint16_t nb_bufs)
{
	struct switch_port_queue *r = q;
	uint16_t nb_rx = 0;
	void **ptrs = (void *)&bufs[0];

	nb_rx = r->ring ?
		rte_ring_sc_dequeue_burst(r->ring, ptrs, nb_bufs, NULL) : 0;

	r->pkts.cnt += nb_rx;

	return nb_rx;
}

/*
 * Queue packets for tx out of a switch port.
 *
 * Packets are either queued
 *   - directly to the  backplane interconnect,
 *   - directly hardware
 *   - to a port based tx ring for later transmission.
 *
 * In the first two cases the pluging supplies a tx routine.  For the
 * bp interconnect case, the plugin code uses a callback backplane tx
 * routine supplied to it via init call from the forwarding
 * application.
 *
 * In the third case the plugin queues packets from a ports tx rings
 * using sw_port_tx_dequeue.
 */
static uint16_t
switch_port_tx(void *q, struct rte_mbuf **bufs, uint16_t nb_bufs)
{
	struct switch_port_queue *r = q; struct rte_mbuf *mbuf;
	struct sw_port *sw_port = r->switch_port;
	uint16_t carrier = sw_port->carrier_port;
	uint16_t i, cnt_tx = 0;

	for (i = 0; i < nb_bufs; i++) {
		if (fal_pkt_mark_is_framed(bufs[i]))
			continue;

		if (switch_port_prep_header_change)
			if ((switch_port_prep_header_change)(&bufs[i],
					       prep_header_change_bytes) != 0)
				goto drop;
		mbuf = bufs[i];
		if (mbuf->ol_flags & PKT_TX_VLAN_PKT &&
		    !(sw_port->flags &
		      SWITCH_PORT_FLAG_TX_FRAMER_VLAN_INSERT)) {
			if (unlikely(rte_vlan_insert(&mbuf))) {
				SWP_ERROR("Insert vlan for packet %p\n", mbuf);
				goto drop;
			}
			mbuf->ol_flags &= ~PKT_TX_VLAN_PKT;
			bufs[i] = mbuf;
		}

		if (sw_port->fal_tx_framer)
			if (unlikely((sw_port->fal_tx_framer)
				     (sw_port,
				      sw_port->fal_private,
				      &bufs[i]) != 0)) {
				SWP_ERROR("tx_framer sw_port%d  port %d %p\n",
					  sw_port->unit, sw_port->port,
					  bufs[i]);
				goto drop;
			}

		fal_pkt_mark_set_framed(bufs[i]);
	}


	if (!(sw_port->flags & SWITCH_PORT_FLAG_TX_RING_CREATE)) {
		cnt_tx = (sw_port->fal_tx)(sw_port->fal_private, carrier,
					   r->qid, bufs, i);
	} else {
		cnt_tx = rte_ring_mp_enqueue_burst(r->ring, (void **)bufs,
						   i, NULL);
	}

	return cnt_tx;

drop:
	/*
	 * Unlikely to ever get here so drop all mbufs on the deck
	 */
	rte_atomic64_add(&r->err_pkts, nb_bufs);

	for (i = 0; i < nb_bufs; i++)
		rte_pktmbuf_free(bufs[i]);

	return nb_bufs;
}

uint16_t
sw_port_tx_dequeue(struct sw_port *port, uint32_t qid, void **dst,
		   uint32_t nb_bufs)
{
	struct switch_port_queue *q;

	if (qid >= SW_P_PMD_MAX_TX_QUEUE) {
		SWP_ERROR("%s Invalid qid %d\n", port->name, qid);
		return 0;
	}

	q = &port->rx_queues[qid];

	return rte_ring_sc_dequeue_burst(q->ring, dst, nb_bufs, NULL);
}

static int
sw_port_dev_configure(struct rte_eth_dev *dev)
{
	struct sw_port *port = dev->data->dev_private;

	if (port->fal_dev_ops->dev_configure)
		return (port->fal_dev_ops->dev_configure)(dev);
	return 0;
}

static int
sw_port_dev_set_link_down(struct rte_eth_dev *dev)
{
	struct sw_port *port = dev->data->dev_private;

	if (port->fal_dev_ops->dev_set_link_down)
		return (port->fal_dev_ops->dev_set_link_down)(dev);
	return -ENOTSUP;
}

static int
sw_port_dev_set_link_up(struct rte_eth_dev *dev)
{
	struct sw_port *port = dev->data->dev_private;

	if (port->fal_dev_ops->dev_set_link_up)
		return (port->fal_dev_ops->dev_set_link_up)(dev);
	return -ENOTSUP;
}

static int
sw_port_dev_start(struct rte_eth_dev *dev)
{
	struct sw_port *port = dev->data->dev_private;

	if (port->fal_dev_ops->dev_start)
		return (port->fal_dev_ops->dev_start)(dev);
	return -ENOTSUP;
}

static void
sw_port_dev_stop(struct rte_eth_dev *dev)
{
	struct sw_port *port = dev->data->dev_private;

	if (port->fal_dev_ops->dev_stop)
		(port->fal_dev_ops->dev_stop)(dev);
}

static struct rte_ring *
sw_port_create_ring(const char *name, const char *dir, uint16_t qid,
		    unsigned int count, int socket_id, unsigned int flags)
{
	char ring_name[RTE_RING_NAMESIZE];
	struct rte_ring *ring;

	snprintf(ring_name, sizeof(ring_name), "%s-%s-%u", name, dir, qid);
	ring = rte_ring_lookup(ring_name);
	if (!ring)
		ring = rte_ring_create(ring_name, count, socket_id,
							   flags);

	if (!ring)
		SWP_ERROR("Failed to create ring for %s", ring_name);

	return ring;
}

static int
sw_port_rx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_id,
		       uint16_t nb_rx_desc, unsigned int socket_id,
		       const struct rte_eth_rxconf *rx_conf __rte_unused,
		       struct rte_mempool *mb_pool __rte_unused)
{
	struct sw_port *port = dev->data->dev_private;
	struct rte_ring *ring = NULL;

	if (port->flags & SWITCH_PORT_FLAG_RX_RING_CREATE) {
		ring = sw_port_create_ring(port->name, "rx", queue_id,
					   nb_rx_desc, socket_id,
					   RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (!ring)
			return -1;
	}

	port->rx_queues[queue_id].ring = ring;
	dev->data->rx_queues[queue_id] = &port->rx_queues[queue_id];
	return 0;
}

static int
sw_port_tx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_id,
	uint16_t nb_tx_desc, unsigned int socket_id,
	const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct sw_port *port = dev->data->dev_private;
	struct switch_port_queue *txq;
	struct rte_ring *ring = NULL;

        txq = rte_zmalloc_socket("ethdev TX queue",
				 sizeof(*txq),
                                 RTE_CACHE_LINE_SIZE, socket_id);
        if (!txq)
                return -ENOMEM;

	if (port->flags & SWITCH_PORT_FLAG_TX_RING_CREATE) {
		ring = sw_port_create_ring(port->name, "tx",
					   queue_id, nb_tx_desc,
					   socket_id, RING_F_SC_DEQ);
		if (!ring) {
			rte_free(txq);
			return -ENOMEM;
		}
	}

	txq->ring = ring;
	txq->qid = queue_id;
	txq->switch_port = port;

	dev->data->tx_queues[queue_id] = txq;
	return 0;
}

static void
sw_port_dev_info(struct rte_eth_dev *dev,
	struct rte_eth_dev_info *dev_info)
{
	struct sw_port *port = dev->data->dev_private;

	dev_info->driver_name = drivername;
	dev_info->max_mac_addrs = 1;
	dev_info->max_rx_pktlen = (uint32_t)-1;
	dev_info->max_rx_queues = (uint16_t)port->max_rx_queues;
	dev_info->max_tx_queues = (uint16_t)port->max_tx_queues;
	dev_info->min_rx_bufsize = 0;
#if RTE_VERSION < RTE_VERSION_NUM(18,05,0,0)
	dev_info->pci_dev = NULL;
#else
	dev_info->tx_offload_capa =
		DEV_TX_OFFLOAD_MULTI_SEGS | DEV_TX_OFFLOAD_VLAN_INSERT;
	dev_info->rx_offload_capa =
		DEV_RX_OFFLOAD_SCATTER | DEV_RX_OFFLOAD_JUMBO_FRAME |
		DEV_RX_OFFLOAD_VLAN_STRIP;
#endif

	/*
	 * When a TX ring isn't used, there is no output queue so
	 * don't waste memory in the application on sizing the mbuf
	 * pool assuming that there is.
	 */
	if (!(port->flags & SWITCH_PORT_FLAG_TX_RING_CREATE))
		dev_info->tx_desc_lim.nb_max = 1;

	if (port->fal_dev_ops->dev_infos_get)
		return (port->fal_dev_ops->dev_infos_get)
			(dev, dev_info);
}

static int
sw_port_link_update(struct rte_eth_dev *dev, int wait_to_complete)
{
	struct sw_port *port = dev->data->dev_private;

	if (port->fal_dev_ops->link_update)
		return (port->fal_dev_ops->link_update)(dev, wait_to_complete);
	return -ENOTSUP;
}

static int
sw_port_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats)
{
	struct sw_port *port = dev->data->dev_private;
	unsigned int i;
	unsigned long tx_err_total = 0, rx_err_total = 0;

	if (port->fal_dev_ops->stats_get) {
		int rc;

		rc = port->fal_dev_ops->stats_get(dev, stats);
		if (rc != 0)
			return rc;
	}

	/* The only counters we should take directly from the pmd are
	 * the error counters that are updated in the dataplane. Port
	 * packet and octet counters are taken from the underlying
	 * switch.
	 */
	for (i = 0; i < RTE_ETHDEV_QUEUE_STAT_CNTRS &&
		     i < dev->data->nb_rx_queues; i++)
		rx_err_total +=
			rte_atomic64_read(&port->rx_queues[i].err_pkts);

	for (i = 0; i < RTE_ETHDEV_QUEUE_STAT_CNTRS &&
		     i < dev->data->nb_tx_queues; i++) {
		struct switch_port_queue *txq = dev->data->tx_queues[i];

		tx_err_total +=
			rte_atomic64_read(&txq->err_pkts);
	}

	stats->ierrors += rx_err_total;
	stats->oerrors += tx_err_total;

	return 0;
}

static void
sw_port_stats_reset(struct rte_eth_dev *dev)
{
	unsigned int i;
	struct sw_port *port = dev->data->dev_private;

	if (port->fal_dev_ops->stats_reset)
		port->fal_dev_ops->stats_reset(dev);

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rte_atomic64_set(&port->rx_queues[i].pkts, 0);
		rte_atomic64_set(&port->rx_queues[i].err_pkts, 0);
		port->rx_queues[i].pkts.cnt = 0;
	}
	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		struct switch_port_queue *txq = dev->data->tx_queues[i];

		rte_atomic64_set(&txq->pkts, 0);
		rte_atomic64_set(&txq->err_pkts, 0);
	}
}
static void
sw_port_stats_init(struct sw_port *port)
{
	int i;

	for (i = 0; i < port->max_rx_queues; i++) {
		rte_atomic64_init(&port->rx_queues[i].pkts);
		rte_atomic64_init(&port->rx_queues[i].err_pkts);
		port->rx_queues[i].pkts.cnt = 0;
	}
}

static int
sw_port_xstats_get_names(struct rte_eth_dev *dev,
			 struct rte_eth_xstat_name *xstats_names,
			 unsigned int size)
{
	struct sw_port *port = dev->data->dev_private;

	if (port->fal_dev_ops->xstats_get_names)
		return (port->fal_dev_ops->xstats_get_names)(dev,
							     xstats_names,
							     size);
	return -ENOTSUP;
}


static int
sw_port_xstats_get(struct rte_eth_dev *dev, struct rte_eth_xstat *xstats,
		   unsigned int n)
{
	struct sw_port *port = dev->data->dev_private;

	if (port->fal_dev_ops->xstats_get)
		return (port->fal_dev_ops->xstats_get)(dev, xstats, n);

	return -ENOTSUP;
}

static void
sw_port_xstats_reset(struct rte_eth_dev *dev)
{
	struct sw_port *port = dev->data->dev_private;

	if (port->fal_dev_ops->xstats_reset)
		(port->fal_dev_ops->xstats_reset)(dev);
}

static int
sw_port_xstats_get_by_id(struct rte_eth_dev *dev,
			 const uint64_t *ids,
			 uint64_t *values,
			 unsigned int n)
{
	struct sw_port *port = dev->data->dev_private;

	if (port->fal_dev_ops->xstats_get_by_id)
		return (port->fal_dev_ops->xstats_get_by_id)(dev, ids,
							     values, n);
	return -ENOTSUP;
}

static int
sw_port_xstats_get_names_by_id(struct rte_eth_dev *dev,
			       struct rte_eth_xstat_name *xstats_names,
			       const uint64_t *ids,
			       unsigned int size)
{
	struct sw_port *port = dev->data->dev_private;

	if (port->fal_dev_ops->xstats_get_names_by_id)
		return (port->fal_dev_ops->xstats_get_names_by_id)(dev,
								   xstats_names,
								   ids, size);
	return -ENOTSUP;
}

static void
sw_port_mac_addr_remove(struct rte_eth_dev *dev, uint32_t index)
{
	struct sw_port *port = dev->data->dev_private;

	if (port->fal_dev_ops->mac_addr_remove)
		return (port->fal_dev_ops->mac_addr_remove)(dev, index);
}

static int
sw_port_mac_addr_add(struct rte_eth_dev *dev, struct ether_addr *mac_addr,
		     uint32_t index, uint32_t vmdq)
{
	struct sw_port *port = dev->data->dev_private;

	if (port->fal_dev_ops->mac_addr_add)
		return (port->fal_dev_ops->mac_addr_add)
			(dev, mac_addr, index, vmdq);
	return -ENOTSUP;
}

#if RTE_VERSION < RTE_VERSION_NUM(18,05,0,0)
static void
#else
static int
#endif
sw_port_default_mac_addr_set(struct rte_eth_dev *dev,
			     struct ether_addr *mac_addr)
{
	struct sw_port *swport = dev->data->dev_private;

	if (swport->fal_dev_ops->mac_addr_set)
		(swport->fal_dev_ops->mac_addr_set)(dev, mac_addr);

#if RTE_VERSION >= RTE_VERSION_NUM(18,05,0,0)
	return 0;
#endif
}

static void
sw_port_rx_queue_release(void *q)
{
	struct switch_port_queue *rxq = q;

	if (rxq->ring)
		rte_ring_free(rxq->ring);
}

static void
sw_port_tx_queue_release(void *q)
{
	struct switch_port_queue *txq = q;

	if (txq && txq->ring)
		rte_ring_free(txq->ring);

	rte_free(txq);
}

static int
sw_port_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	struct sw_port *port = dev->data->dev_private;

	if (port->fal_dev_ops->mtu_set)
		return (port->fal_dev_ops->mtu_set)
			(dev, mtu);
	return -ENOTSUP;
}

static int sw_port_get_module_info(struct rte_eth_dev *dev,
				   struct rte_eth_dev_module_info *modinfo)
{
	struct sw_port *port = dev->data->dev_private;

	if (port->fal_dev_ops->get_module_info)
		return (port->fal_dev_ops->get_module_info)(dev, modinfo);

	return -ENOTSUP;
}

static int sw_port_get_module_eeprom(struct rte_eth_dev *dev,
				     struct rte_dev_eeprom_info *info)
{
	struct sw_port *port = dev->data->dev_private;

	if (port->fal_dev_ops->get_module_eeprom)
		return (port->fal_dev_ops->get_module_eeprom)(dev, info);
	return -ENOTSUP;
}

static int
sw_port_vlan_filter_set(struct rte_eth_dev *dev, uint16_t vlan_id, int on)
{
	struct sw_port *port = dev->data->dev_private;

	if (port->fal_dev_ops->vlan_filter_set)
		return (port->fal_dev_ops->vlan_filter_set)(dev, vlan_id, on);
	return -ENOTSUP;
}

static const struct eth_dev_ops eth_ops = {
	.dev_start = sw_port_dev_start,
	.dev_stop = sw_port_dev_stop,
	.dev_set_link_up = sw_port_dev_set_link_up,
	.dev_set_link_down = sw_port_dev_set_link_down,
	.dev_configure = sw_port_dev_configure,
	.dev_infos_get = sw_port_dev_info,
	.rx_queue_setup = sw_port_rx_queue_setup,
	.tx_queue_setup = sw_port_tx_queue_setup,
	.rx_queue_release = sw_port_rx_queue_release,
	.tx_queue_release = sw_port_tx_queue_release,
	.link_update = sw_port_link_update,
	.stats_get = sw_port_stats_get,
	.stats_reset = sw_port_stats_reset,
	.xstats_get_names = sw_port_xstats_get_names,
	.xstats_get = sw_port_xstats_get,
	.xstats_reset = sw_port_xstats_reset,
	.xstats_get_by_id = sw_port_xstats_get_by_id,
	.xstats_get_names_by_id = sw_port_xstats_get_names_by_id,
	.mac_addr_remove = sw_port_mac_addr_remove,
	.mac_addr_add = sw_port_mac_addr_add,
	.mac_addr_set = sw_port_default_mac_addr_set,
	.mtu_set = sw_port_mtu_set,
	.get_module_info = sw_port_get_module_info,
	.get_module_eeprom = sw_port_get_module_eeprom,
	.vlan_filter_set = sw_port_vlan_filter_set,
};

static inline void random_mac_addr(uint8_t *addr)
{
	uint64_t rand = rte_rand();
	uint8_t *p = (uint8_t *)&rand;

	memcpy(addr, p, ETHER_ADDR_LEN);
	addr[0] &= ~ETHER_GROUP_ADDR;       /* clear multicast bit */
	addr[0] |= ETHER_LOCAL_ADMIN_ADDR;  /* set local assignment bit */
}

static int
sw_port_atomic_copy_link_status(struct rte_eth_link *dst,
	struct rte_eth_link *src)
{
	if (rte_atomic64_cmpset((uint64_t *)dst, *(uint64_t *)dst,
					*(uint64_t *)src) == 0)
		return -1;
	return 0;
}

static struct sw_port *
sw_port_vdev_create(struct rte_vdev_device *dev,
		    struct sw_port_create_args *internal_args)
{
	unsigned int nb_rx_queues = internal_args->rx_queues;
	unsigned int nb_tx_queues = internal_args->tx_queues;
	unsigned int numa_node, q;
	struct rte_eth_dev_data *data = NULL;
	struct sw_port *switch_port = NULL;
	struct rte_eth_dev *eth_dev = NULL;
	const char *dev_name = rte_vdev_device_name(dev);

	SWP_INFO("Initializing switch port %s\n", dev_name);
	/* now do all data allocation - for eth_dev structure, dummy pci driver
	 * and internal (private) data
	 */
	if (dev->device.numa_node == SOCKET_ID_ANY)
		dev->device.numa_node = rte_socket_id();

	if (nb_rx_queues > SW_P_PMD_MAX_RX_QUEUE)
		nb_rx_queues = SW_P_PMD_MAX_RX_QUEUE;
	if (nb_tx_queues > SW_P_PMD_MAX_TX_QUEUE)
		nb_tx_queues = SW_P_PMD_MAX_TX_QUEUE;
	if (!(internal_args->flags & SWITCH_PORT_FLAG_RX_RING_CREATE))
		nb_rx_queues = 0;

	numa_node = dev->device.numa_node;

	/* reserve an ethdev entry */
	eth_dev = rte_eth_vdev_allocate(dev, sizeof(*switch_port));
	if (!eth_dev)
		return NULL;

	data = eth_dev->data;
	switch_port = eth_dev->data->dev_private;

	/* now put it all together
	 * - store queue data in port,
	 * - store numa_node info in eth_dev_data
	 * - point eth_dev_data to port
	 * - and point eth_dev structure to new eth_dev_data structure
	 */

	switch_port->numa_node = numa_node;
	switch_port->name = strdup(rte_vdev_device_name(dev));
	if (!switch_port->name)
		goto error;
	switch_port->unit = internal_args->hw_unit;
	switch_port->port = internal_args->hw_port;
	switch_port->port_id = eth_dev->data->port_id;
	switch_port->max_rx_queues = nb_rx_queues;
	switch_port->max_tx_queues = nb_tx_queues;
	switch_port->flags = internal_args->flags;
	switch_port->carrier_port = internal_args->bp_interconnect_port;
	switch_port->carrier_dev =
		&rte_eth_devices[switch_port->carrier_port];
	switch_port->sw_dev_info = internal_args->sw_dev_info;

	switch_port->fal_private = internal_args->plugin_private;
	switch_port->fal_dev_ops = internal_args->plugin_dev_ops;
	switch_port->fal_tx = internal_args->plugin_tx;
	switch_port->fal_tx_framer = internal_args->plugin_tx_framer;
	switch_port->plugin_detach_device = internal_args->plugin_detach_device;

	for (q = 0; q < nb_rx_queues; q++)
		switch_port->rx_queues[q].switch_port = switch_port;

	sw_port_stats_init(switch_port);

	if (internal_args->mac)
		memcpy(&switch_port->address.addr_bytes[0], internal_args->mac,
		       sizeof(struct ether_addr));
		else
			random_mac_addr(&switch_port->address.addr_bytes[0]);

	data->nb_rx_queues = (uint16_t)nb_rx_queues;
	data->nb_tx_queues = (uint16_t)nb_tx_queues;

	/*
	 * Place link into a known starting state
	 */
	data->dev_link.link_speed  = ETH_LINK_SPEED_AUTONEG;
	data->dev_link.link_duplex = ETH_LINK_FULL_DUPLEX;
	data->dev_link.link_status = ETH_LINK_DOWN;

	data->mac_addrs = &switch_port->address;

	if (internal_args->flags & SWITCH_PORT_FLAG_INTR_LSC)
		data->dev_flags |= RTE_ETH_DEV_INTR_LSC;

	eth_dev->dev_ops = &eth_ops;
	data->kdrv = RTE_KDRV_NONE;
	data->numa_node = numa_node;

	TAILQ_INIT(&(eth_dev->link_intr_cbs));

	/* finally assign rx and tx ops */
	eth_dev->rx_pkt_burst = switch_port_rx;
	eth_dev->tx_pkt_burst = switch_port_tx;
	switch_port->dev = eth_dev;

	switch_port_prep_header_change = internal_args->prep_header_change;
	prep_header_change_bytes = internal_args->prep_header_change_bytes;
#if RTE_VERSION >= RTE_VERSION_NUM(18,05,0,0)
	rte_eth_dev_probing_finish(eth_dev);
#endif

	return switch_port;
error:
	free(switch_port->name);

	/*
	 * rte_eth_dev_release_port will attempt to free this, but it
	 * is part of switch_port so NULL it.
	 */
	eth_dev->data->mac_addrs = NULL;
	rte_eth_dev_release_port(eth_dev);

	return NULL;
}

static int
parse_internal_args(const char *key __rte_unused, const char *value,
		void *data)
{
	struct sw_port_create_args **internal_args = data;
	void *args;

	if (sscanf(value, "%p", &args) != 1)
		return -1;

	*internal_args = args;

	return 0;
}

static int
sw_port_pmd_uninit(struct rte_vdev_device *dev)
{
	const char *name = rte_vdev_device_name(dev);
	struct rte_eth_dev *eth_dev;
	struct sw_port *switch_port;
	struct switch_port_queue *r;
	uint16_t i;

	if (name == NULL) {
		SWP_ERROR("Could not cleanup unnamed device\n");
		return -EINVAL;
	}

	/* find an ethdev entry */
	eth_dev = rte_eth_dev_allocated(name);
	if (eth_dev == NULL) {
		SWP_ERROR("Could not find device with name %s\n",
			  name);
		return -ENODEV;
	}

	SWP_INFO("Un-Initializing switch port %s\n", name);

	sw_port_dev_stop(eth_dev);

	switch_port = eth_dev->data->dev_private;

	for (i = 0; i < eth_dev->data->nb_tx_queues; i++)
		sw_port_tx_queue_release(eth_dev->data->tx_queues[i]);

	for (i = 0; i < eth_dev->data->nb_rx_queues; i++)
		sw_port_rx_queue_release(eth_dev->data->rx_queues[i]);

	free(switch_port->name);

	/*
	 * rte_eth_dev_release_port will attempt to free this, but it
	 * is part of switch_port so NULL it.
	 */
	eth_dev->data->mac_addrs = NULL;
	rte_eth_dev_release_port(eth_dev);

	return 0;
}

static int
sw_port_pmd_init(struct rte_vdev_device *dev)
{
	const char *name, *params;
	struct rte_kvargs *kvlist = NULL;
	struct sw_port *sw_port;
	int ret;

	name = rte_vdev_device_name(dev);
	params = rte_vdev_device_args(dev);

	if (params == NULL || params[0] == '\0') {
		SWP_ERROR("%s create fail, no params\n", name);
		return  -1;
	}


	SWP_INFO("Initializing switch port for %s\n", name);

	kvlist = rte_kvargs_parse(params, valid_arguments);
	if (!kvlist) {
		SWP_ERROR("%s create fail, no params\n", name);
		return  -1;
	}

	if (rte_kvargs_count(kvlist, DPDK_SW_PORT_ARG) != 1) {
		SWP_ERROR("%s create fail, no params\n", name);
		return  -1;
	}

	struct sw_port_create_args *internal_args;

	ret = rte_kvargs_process(kvlist, DPDK_SW_PORT_ARG,
					 parse_internal_args,
					 &internal_args);
	if (ret < 0)
		goto out_free;

	ret = -1;

	if (internal_args->hw_port != SW_P_PORT_NONE &&
	    (internal_args->hw_port >= MAX_HW_SWITCH_PORTS ||
	     internal_args->hw_unit >= MAX_HW_SWITCH_DEVICES)) {
		SWP_ERROR("%s create fail, port %d unit %d\n",
			  name, internal_args->hw_port, internal_args->hw_unit);
		goto out_free;
	}

	SWP_INFO("Initializing sw_port_vdev for %s\n ", name);
	sw_port =  sw_port_vdev_create(dev, internal_args);
	if (!sw_port) {
		SWP_ERROR("Failed to alloc sw_port_vdev for %s\n ", name);
		goto out_free;
	}

	/*
	 * LUT used for demultiplexing incoming traffic
	 */
	if (internal_args->hw_port != SW_P_PORT_NONE)
		fp_port2swport[internal_args->hw_unit][internal_args->hw_port] =
			sw_port;


	/*Setup return info */
	if (internal_args->plugin_link_device)
		internal_args->plugin_link_device(internal_args->plugin_private,
						  sw_port, sw_port->port_id);
	internal_args->fal_switch_port = sw_port;
	internal_args->dpdk_port_id = sw_port->port_id;

	ret = 0;
out_free:
	rte_kvargs_free(kvlist);
	return ret;
}


/*
 * sw_port_enqueue_rx_mbuf is the interface to the pmd for the callback
 * from the Broadcom SDK. The CB function is responsible for converting
 * bcm_pkt_t to rte_mbuf and passing the resulting bufs.
 */
int __attribute__ ((externally_visible))
sw_port_enqueue_rx_mbuf(struct sw_port *port, uint32_t qid,
			struct rte_mbuf **bufs, int nb_bufs)
{
	int rv = 0;
	struct switch_port_queue *q;
	void **ptrs = (void *)&bufs[0];

	if (qid >= SW_P_PMD_MAX_RX_QUEUE) {
		SWP_ERROR("%s Invalid qid %d\n", port->name, qid);
		return 0;
	}

	q = &port->rx_queues[qid];
	rv = rte_ring_mp_enqueue_burst(q->ring, ptrs, nb_bufs, NULL);

	return rv;
}

int __attribute__ ((externally_visible))
sw_port_fal_report_link(struct sw_port *sw_port, struct rte_eth_link *link)
{
	struct rte_eth_link *dst = &(sw_port->dev->data->dev_link);
	struct rte_eth_link *src = link;

	return sw_port_atomic_copy_link_status(dst, src);
}

int __attribute__ ((externally_visible))
sw_port_fal_report_link_intr(struct sw_port *sw_port, struct rte_eth_link *link)
{
	struct rte_eth_link *dst = &(sw_port->dev->data->dev_link);
	struct rte_eth_link *src = link;
	int ret;

	ret = sw_port_atomic_copy_link_status(dst, src);
	_rte_eth_dev_callback_process(sw_port->dev, RTE_ETH_EVENT_INTR_LSC,
#if RTE_VERSION < RTE_VERSION_NUM(18,02,0,0)
				      NULL, NULL);
#else
				      NULL);
#endif

	return ret;
}

int __attribute__ ((externally_visible))
sw_port_fal_get_link(struct sw_port *sw_port, struct rte_eth_link *link)
{
	struct rte_eth_link *src = &(sw_port->dev->data->dev_link);
	struct rte_eth_link *dst = link;

	return sw_port_atomic_copy_link_status(dst, src);
}

#define SW_PORT_ARG_STR_SIZE 48
#define SW_PORT_NAME_STR_SIZE 48
#define SW_PORT_COMB_STR_SIZE 96

int __attribute__ ((externally_visible))
sw_port_create(struct sw_port_create_args *args)
{
	char args_str[SW_PORT_ARG_STR_SIZE];
	char name_str[SW_PORT_NAME_STR_SIZE];
	char combined_str[SW_PORT_COMB_STR_SIZE];
	int size;

	if (args->port_name)
		snprintf(name_str, SW_PORT_NAME_STR_SIZE,
			 "net_sw_portsw%d%s", args->hw_unit, args->port_name);
	else
		snprintf(name_str, SW_PORT_NAME_STR_SIZE,
			 "net_sw_portsw%dport%d", args->hw_unit, args->hw_port);

	snprintf(args_str, SW_PORT_ARG_STR_SIZE, "%s=%p", DPDK_SW_PORT_ARG,
		 args);

	if (args->plugin_attach_device) {
		snprintf(combined_str, SW_PORT_COMB_STR_SIZE, "%s,%s",
			 name_str, args_str);
		return args->plugin_attach_device(combined_str);
	} else
		return rte_vdev_init(name_str, args_str);
}

int32_t __attribute__ ((externally_visible))
sw_port_from_hw_port(uint32_t device, uint32_t port, uint16_t *dpdk_port)
{
	if (port >= MAX_HW_SWITCH_PORTS ||
		device >= MAX_HW_SWITCH_DEVICES)
		return -1;

	if (fp_port2swport[device][port]) {
		*dpdk_port = fp_port2swport[device][port]->port_id;
		return 0;
	}

	return -1;
}

void __attribute__ ((externally_visible)) *
sw_port_fal_priv_from_dev(struct rte_eth_dev *dev)
{
	struct sw_port *port;

	if (!dev->data->dev_private)
		return NULL;
	port = dev->data->dev_private;

	return port->fal_private;
}

int __attribute__ ((externally_visible))
sw_port_delete(struct sw_port_delete_args *args)
{
	char name_str[SW_PORT_NAME_STR_SIZE];
	struct rte_eth_dev *dev;
	struct sw_port *port;

	if (args->port_name)
		snprintf(name_str, SW_PORT_NAME_STR_SIZE,
			 "net_sw_portsw%d%s", args->hw_unit, args->port_name);
	else
		snprintf(name_str, SW_PORT_NAME_STR_SIZE,
			 "net_sw_portsw%dport%d", args->hw_unit, args->hw_port);

	dev = rte_eth_dev_allocated(name_str);
	if (!dev) {
		SWP_ERROR("Could not find device %s\n", name_str);
		return -ENOENT;
	}

	if (!dev->data->dev_private) {
		SWP_ERROR("No SWP context block for device %s\n", name_str);
		return -ENOENT;
	}

	port = dev->data->dev_private;

	if (port->plugin_detach_device)
		return port->plugin_detach_device(name_str);
	else
		return rte_vdev_uninit(name_str);
}

void sw_port_set_backplane(struct sw_port *port, uint16_t bp_port)
{
	port->carrier_port = bp_port;
}

int sw_port_get_dev_info(uint16_t port_id, struct swport_dev_info *devinfo)
{
	struct rte_eth_dev *eth_dev;
	struct sw_port *port;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -EINVAL);

	eth_dev = &rte_eth_devices[port_id];
	port = eth_dev->data->dev_private;

	*devinfo = port->sw_dev_info;
	return 0;
}

static struct rte_vdev_driver sw_port_pmd_drv = {
	.probe = sw_port_pmd_init,
	.remove = sw_port_pmd_uninit,
};

RTE_PMD_REGISTER_VDEV(net_sw_port, sw_port_pmd_drv);
RTE_PMD_REGISTER_ALIAS(net_sw_port, eth_nsl);
RTE_PMD_REGISTER_PARAM_STRING(net_sw_port,
			      DPDK_SW_PORT_ARG"=<void *>");
