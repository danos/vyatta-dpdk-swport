/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef _VYATTA_SWPORT_H_
#define _VYATTA_SWPORT_H_

#include <stdbool.h>
#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_HW_SWITCH_PORTS RTE_MAX_ETHPORTS
#define MAX_HW_SWITCH_DEVICES 1

#define SW_P_PMD_MAX_RX_QUEUE 1
#define SW_P_PMD_MAX_TX_QUEUE 256

struct sw_port;

/*
 * sw_port create support
 */

struct sw_port_create_args {
	/* Registration information */
	uint32_t hw_unit;
	uint32_t hw_port;
	/*
	 * SWITCH_PORT_FLAG_XX
	 */
	uint16_t flags;

	/* Optional port name extension, by default the switch port is
	 * named sw<hw_unit>port<hw_port>, however a fal can pass a
	 * port name extension, thus resulting in a name
	 * sw<hw_unit><port_name_extensino>
	 */
	const char *port_name;

	/*
	 * tx queues requested, less or equal to SW_P_PMD_MAX_TX_QUEUE
	 */
	uint8_t tx_queues;

	/*
	 * rx queues requested, less or equal to SW_P_PMD_MAX_RX_QUEUE
	 */
	uint8_t rx_queues;

	/* ops registations */
	const struct eth_dev_ops *plugin_dev_ops;

	/* Per port private structure, passed with calls to plugin_dev_ops */
	void *plugin_private;

	/* Mac address of port */
	struct ether_addr *mac;

	/*
	 * Plugin supplied routine to transmit packets from a switch
	 * port, either framed or unframed.  If using a dpdk port for
	 * switch interconnect the plugin supplied routine typically
	 * calls back into the application dataplane forwarding code
	 * expose in fal_plug.h.  Returns: Number of mbufs
	 * transmitted. Untransmitted mbufs are returned to the
	 * caller.
	 */
	uint16_t (*plugin_tx)(void *fal_info, uint16_t carrier, uint16_t port,
			      struct rte_mbuf **bufs, uint16_t nb_bufs);

	/* Port_id of the dpdk hardswitch interconnect for this port */
	uint16_t bp_interconnect_port;

	/* Optional transmit framer, used with DPDK port based BP
	 * Returns: 0 on success
	 */
	int32_t (*plugin_tx_framer)(void *sw_port, void *fal_info,
				    struct rte_mbuf *bufs);
	/*
	 * Returned information
	 */

	/*
	 * swport context to be passed forward from the fal
	 * to switch port services.
	 */
	void *fal_switch_port;
	/*
	 * id of switch port created
	 */
	uint16_t dpdk_port_id;

	/*
	 * Routine that is call to prepare the packet for
	 * change. Ensure the first mbuf is not a clone, and that
	 * change_bytes(See Below) and are in the first mbuf
	 */
	int (*prep_header_change)(struct rte_mbuf **m, uint16_t header_len);

	/*
	 * Number of bytes prepared by header change
	 */
	uint8_t prep_header_change_bytes;

	/*
	 * callback to attach device to s/w forwarding engine
	 */
	int (*plugin_attach_device)(const char *devargs);

	/*
	 * callback to establish cross-linkage between
	 * device and sw_port before any operations can commence
	 * on the port
	 *
	 * ctx : the plugin_private pointer passed in by the plugin
	 * sw_port : switch port structure allocated for this port
	 * dpdk_port: dpdk port id allocated for this port
	 */
	void (*plugin_link_device)(void *ctx,
				   struct sw_port *port,
				   uint16_t dpdk_port);

	/*
	 * callback to remove device from s/w forwarding engine
	 */
	int (*plugin_detach_device)(const char *devargs);

};

struct sw_port_delete_args {
	/* Registration information */
	uint32_t hw_unit;
	uint32_t hw_port;
	const char *port_name;
};


/*
 * Create Rx ring on a switchport. Only used when the FAL is queuing directly
 * to the receive ring, i.e a non ethernet switch interconnect.
 */
#define SWITCH_PORT_FLAG_RX_RING_CREATE 1

/*
 * Create Tx ring on a switchport. Only used when the FAL is dequeuing from
 * the transmit ring i.e a non ethernet direct queue switch interconnect.
 */
#define SWITCH_PORT_FLAG_TX_RING_CREATE 2

/*
 * Insert VLAN header is appropiate before calling FAL Tx routine
 */
#define SWITCH_PORT_FLAG_TX_FRAMER_VLAN_INSERT  4

/*
 * Supports interrupt-based link-state change events
 */
#define SWITCH_PORT_FLAG_INTR_LSC  8

struct rte_eth_dev;
struct rte_eth_link;

/*
 * Switch port creation, returns 0 upon success;
 */
int sw_port_create(struct sw_port_create_args *args);
/*
 * Enqueue mbufs to a sw_ports receive ring, This mechanism is used for non
 * DPDK port hardware switch connected devices.
 * Returns: Number of mbufs queued, unqueued mbus are returned to the caller.
 */
int sw_port_enqueue_rx_mbuf(struct sw_port *port, uint32_t qid,
			    struct rte_mbuf **bufs, int nb_bufs);
/*
 * If Tx rings are configured then dequeue objects from a port tx Q.
 * Returns: Number of objects dequeued.
 *
 */
uint16_t sw_port_tx_dequeue(struct sw_port *port, uint32_t qid, void **dst,
			    uint32_t nb_bufs);
/*
 * Mechanism to report a port's link status.
 * Returns 0 on success
 *        -1 on failure
 */
int sw_port_fal_report_link(struct sw_port *sw_port,
			    struct rte_eth_link *link);

/*
 * Mechanism to report a port's link status changed from interrupt.
 * Returns 0 on success
 *        -1 on failure
 */
int sw_port_fal_report_link_intr(struct sw_port *sw_port,
				 struct rte_eth_link *link);

/* retrieve link status */
int sw_port_fal_get_link(struct sw_port *sw_port, struct rte_eth_link *link);

/*
 * When the plugin_dev_ops is passed an eth_dev retrieve the plugin
 * private info or NULL
 */
void *sw_port_fal_priv_from_dev(struct rte_eth_dev *dev);

/*
 * retreive the sw_port or NULL from a device by name
 */
void *sw_port_from_dev(const char *name);
 /*
  * Lookup a sw_port dpdk id from the device, returning the result in
  * dpdk_port Returns: 0 on successe else -1
  */
int32_t sw_port_from_hw_port(uint32_t device, uint32_t port,
			     uint16_t *dpdk_port);
/*
 * Register the onie prom obtained by the fal from the hardware.
 */
bool sw_port_register_onie_prom(unsigned char *prom, uint16_t length,
				uint8_t reserved_macs);
/*
 * Request a mac address of registered base + offset
 */
bool sw_port_request_mac_addr(struct ether_addr *addr, uint8_t offset);

/*
 * delete sw_port
 */
int sw_port_delete(struct sw_port_delete_args *args);

/*
 * update backplane port
 */
void sw_port_set_backplane(struct sw_port *port, uint16_t bp_port);

#ifdef __cplusplus
}
#endif

#endif
