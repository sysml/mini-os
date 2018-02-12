/*
 *          MiniOS
 *
 *   file: netfront_netmap.h
 *
 * Authors: Joao Martins <joao.martins@neclab.eu>
 *
 *
 * Copyright (c) 2014, NEC Europe Ltd., NEC Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * THIS HEADER MAY NOT BE EXTRACTED OR MODIFIED IN ANY WAY.
 */

#ifndef NETFRONT_NETMAP_H
#define NETFRONT_NETMAP_H
#include <mini-os/netfront.h>
#include <mini-os/netmap.h>
#include <math.h>

unsigned __errno;

DECLARE_WAIT_QUEUE_HEAD(rx_queue);
u_int rx_work_todo = 0;

/**
 * Represents an entry mapped entry into
 * domains address space
 *
 */
struct gnttab_map_entry {
	/* the guest address of the other domains page*/
	unsigned long host_addr;
	grant_handle_t handle;
};

/*
 * This referes to netmap necessary info retrived
 * from the xenstore.
 * The info includes:
 * 	- all grant refereces for ring/buffers
 *  - a proper mapping having all pte and mappings
 *	received from the hypercall grant map
 *  - total amount of pages granted
 *  - a waitqueue and lock
 *  - an event channel to notify Domain-0
 */
struct netmap_mem_d {
	/* Buffers ring references */
	uint32_t *ring_refs;
	/* Buffers grant references */
	uint32_t *bufs_refs;

	/* for grant map hypercall - for ring and kring */
	struct gnttab_map_grant_ref *ring_map;
	/* Rings page table entries mapped into guest address space */
	struct gnttab_map_entry *ring_gnt;

	/* for grant map hypercall - for buffers */
	struct gnttab_map_grant_ref *bufs_map;

	/* Buffers page table entries mapped into guest address space */
	struct gnttab_map_entry *bufs_gnt;

	/* Number of grant references for the ring */
	uint32_t nr_ring_refs;

	/* Number of grant references for the buffers */
	uint32_t nr_bufs_refs;

	/*
	 * once mapped the domain this points the buffers
	 */
	char  *bufs_base;

	/*
	 * used for blocking the domain await for txsync/rxsync
	 */
	struct wait_queue_head wait;
};

struct netfront_csb {
	/* these are only used by the guest */
	uint16_t txcur;
	uint16_t txhead;
	uint8_t guest_need_txkick;
	uint8_t guest_need_rxkick;

	/* these are mostly changed by the event channels */
	uint8_t host_need_rxkick;
	uint8_t host_need_txkick;
};

struct netmap_adapter {
	struct netmap_mem_d txd, rxd;
	struct netmap_ring *tx_rings, *rx_rings;

	struct netfront_csb *stat;
	char *nr_buf_tx, *nr_buf_rx;
	int num_tx_desc, num_rx_desc;

	domid_t  dom;
	char *nodename;
	unsigned int devid;
	char path[256];
	int bufs_size;

	xenbus_event_queue events;

	evtchn_port_t tx_irq, rx_irq;
	void (*netif_rx)(unsigned char* data, int len, void *arg);
};

#define ND(x, args ...)
#define D(x, args ...)  printk("" x "\n", ## args)

#define NETMAP_BUF_SIZE 2048
#define NETFRONT_BUF(dev, t, index) \
	dev->nr_buf_##t + index * NETMAP_BUF_SIZE;

inline
void netmap_netfront_rx(struct netfront_dev *dev)
{
	struct netmap_adapter *na = dev->na;
	struct netmap_ring *ring = na->rx_rings;
	struct netfront_csb *stat = na->stat;
	struct netmap_slot *slot;
	u_int rx = 0, limit = ring->num_slots, space;
	u_int cur = ring->cur;
	void *p;

#ifdef CONFIG_NETFRONT_POLL
	if (!rx_work_todo) {
		int64_t deadline = NOW() + MICROSECS(CONFIG_NETFRONT_POLLTIMEOUT);
		for (;;) {
			wait_event_deadline(rx_queue, rx_work_todo > 0, deadline);
			if (rx_work_todo || (deadline && NOW() >= deadline)) {
				break;
			}
		}
	}
#endif

#ifdef CONFIG_SELECT_POLL
	files[dev->fd].read = 0;
#endif

	if (!stat->host_need_rxkick) {
		return (rx);
	}

	cur = ring->cur;
	space = nm_ring_space(ring);

	if (nm_ring_empty(ring)) {
		return (rx);
	}

	if (space < limit)
		limit = space;

	for (rx = 0; rx < limit; rx++) {
		slot = &ring->slot[cur];

		if (slot->len == 0)
			continue;

		p = NETFRONT_BUF(na, rx, cur);
		if (dev->netif_rx)
			dev->netif_rx(p, slot->len, dev->netif_rx_arg);

		cur = NETMAP_RING_NEXT(ring, cur);
	}

	ring->head = ring->cur = cur;
	stat->host_need_rxkick = 0;
	rx_work_todo &= (~na->devid);
	notify_remote_via_evtchn(na->rx_irq);
	return (rx);
}

inline
void netmap_netfront_xmit(void *dev, unsigned char* data, int len)
{
	struct netmap_adapter *na = dev;
	struct netmap_ring *ring = na->tx_rings;
	struct netfront_csb *stat = na->stat; // shadow copy
	u_int cur = stat->txcur, flags = 0;
	struct netmap_slot *slot = &ring->slot[cur];
	char *p = NETFRONT_BUF(na, tx, cur);

#define BLOCK		   1
#define NOTIFY		  2
	pkt_copy(data, p, len);

	slot->len = len;
	cur = NETMAP_RING_NEXT(ring, cur);
	stat->txhead = stat->txcur = cur;

	if (nm_ring_empty(ring) || (stat->txcur == ring->tail)) {
		flags |= BLOCK;
	}

	if (stat->host_need_txkick) {
		flags |= NOTIFY;
		ring->head = ring->cur = stat->txcur;
		stat->txhead = ring->head;
		stat->host_need_txkick = 0;
		wmb();
		stat->guest_need_txkick = 1;
		notify_remote_via_evtchn(na->tx_irq);
	}

	if (flags & BLOCK) {
		for (;;) {
			wait_event_deadline(na->txd.wait, stat->guest_need_txkick == 0, 0);
			if (!(stat->guest_need_txkick)) {
				break;
			}
		}
	}
}

void netfront_rx_interrupt(evtchn_port_t port, struct pt_regs *regs, void *data)
{
	struct netfront_dev *dev = (struct netfront_dev *) data;
	struct netmap_adapter *na = dev->na;
	struct netfront_csb *stat = na->stat;
	u_int flags;
	ND("rxsync done");

	local_irq_save(flags);
	stat->host_need_rxkick = 1;
	stat->guest_need_rxkick = 1;
	rx_work_todo |= na->devid;
#ifdef CONFIG_SELECT_POLL
	wake_up(&netfront_queue);
	files[dev->fd].read = 1;
#else
	wake_up(&rx_queue);
#endif
	local_irq_restore(flags);
	mb();
}

void netfront_tx_interrupt(evtchn_port_t port, struct pt_regs *regs, void *data)
{
	struct netfront_dev *dev = (struct netfront_dev *) data;
	struct netmap_adapter *na = dev->na;
	struct netmap_ring *ring = na->tx_rings;
	struct netfront_csb *stat = na->stat;
	u_int flags;
	ND("txsync done");

	local_irq_save(flags);
	stat->host_need_txkick = 1;

	if (ring->cur != stat->txcur) {
		rmb();
		ring->head = ring->cur = stat->txcur;
		stat->host_need_txkick = 0;
		notify_remote_via_evtchn(na->tx_irq);
	}

	stat->guest_need_txkick = 0;
	wake_up(&na->txd.wait);
	local_irq_restore(flags);
	mb();
}

static
int pageorder(int nr_refs)
{
	int pgo = log2(nr_refs);
	while (pow(2,pgo) < nr_refs) pgo++;
 	return pgo;
}

#define map_ops_new(nrefs,addr,op,pte)	\
	addr = alloc_pages(pageorder(nrefs)); \
	op = malloc(nr_refs * sizeof(struct gnttab_map_grant_ref)); \
	pte = malloc(nr_refs * sizeof(struct gnttab_map_entry))

static
int netfront_gnttab_map(struct netmap_mem_d *rdesc, domid_t dom, int ring)
{
	int i, ofs, gnt_err = 0;
	unsigned long addr = 0;
	int nr_refs = 0;
	struct gnttab_map_grant_ref *op = NULL;
	struct gnttab_map_entry *pte = NULL;
	uint32_t *refs = NULL;

	if (ring) {
		nr_refs = rdesc->nr_ring_refs;
		map_ops_new(nr_refs, addr, op, pte);
		nr_refs--;
		rdesc->ring_map = op;
		rdesc->ring_gnt = pte;
		refs = rdesc->ring_refs;
	} else {
		nr_refs = rdesc->nr_bufs_refs;
		map_ops_new(nr_refs, addr, op, pte);
		rdesc->bufs_map = op;
		rdesc->bufs_gnt = pte;
		refs = rdesc->bufs_refs;
	}

	dom = 0; // XXX network stub domains

	for (i = 0; i < nr_refs; ++i) {
			op[i].ref   = (grant_ref_t) refs[i];
			op[i].dom   = (domid_t) dom;
			op[i].flags = GNTMAP_host_map;
			op[i].host_addr = addr + PAGE_SIZE * i;

			ND("map flags %d ref %d host_addr %d",
					op[i].flags, op[i].ref, op[i].host_addr);
	};

	if (HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref,
							op, nr_refs)) {
		return -EINVAL;
	}

	for (i = 0; i < nr_refs; i++) {
			if (op[i].status != GNTST_okay) {
					D("map %d not ok. status %d",
							op[i].ref, op[i].status);
					++gnt_err;
					continue;
			}

			pte[i].host_addr = op[i].host_addr;
			pte[i].handle = op[i].handle;
			ND("map ok. handle %u addr %u", op[i].handle,
							op[i].host_addr);
			rmb();
	}

	D("\t%d map errors", gnt_err);
	return 0;
}

static
int netfront_gnttab_unmap(struct netmap_mem_d *rdesc)
{
	int i, nr_refs = rdesc->nr_ring_refs;
	struct gnttab_map_entry *ring_gnt = rdesc->ring_gnt;
	struct gnttab_map_entry *bufs_gnt = rdesc->bufs_gnt;
	struct gnttab_unmap_grant_ref ring_op[rdesc->nr_ring_refs];
	struct gnttab_unmap_grant_ref bufs_op[rdesc->nr_bufs_refs];

	for (i = 0; i < nr_refs; ++i) {
			ring_op[i].host_addr = ring_gnt[i].host_addr;
			ring_op[i].handle = ring_gnt[i].handle;
			ring_op[i].dev_bus_addr = 0;

			ND("unmap ref %d host_addr %x",
					ring_gnt[i].handle, ring_gnt[i].host_addr);
	};

	D("Unmapping %d ring refs", nr_refs);
	if (HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref,
							ring_op, nr_refs))
		BUG();

	nr_refs = rdesc->nr_bufs_refs;

	for (i = 0; i < nr_refs; ++i) {
			bufs_op[i].host_addr = bufs_gnt[i].host_addr;
			bufs_op[i].handle = bufs_gnt[i].handle;
			bufs_op[i].dev_bus_addr = 0;

			ND("unmap ref %d host_addr %x",
					bufs_op[i].handle, bufs_op[i].host_addr);
	};

	D("Unmapping %d bufs refs", nr_refs);
	HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref,
							bufs_op, nr_refs);

	return 0;
}

static
int xenbus_read_ring_refs(struct netmap_adapter *na)
{
	int i;
	char path[256];

	snprintf(path, sizeof(path), "%s/tx-ring-refs", na->nodename);
	na->txd.nr_ring_refs = xenbus_read_integer(path);
	na->txd.ring_refs = malloc(1 + na->txd.nr_ring_refs * sizeof(uint32_t));

	// Read the tx-ring-refs
	for (i = 0; i < na->txd.nr_ring_refs; i++) {
		snprintf(path, sizeof(path), "%s/tx-ring-ref%u", na->nodename, i);
		na->txd.ring_refs[i] = xenbus_read_integer(path);
	}

	snprintf(path, sizeof(path), "%s/rx-ring-refs", na->nodename);
	na->rxd.nr_ring_refs = xenbus_read_integer(path);
	na->rxd.ring_refs = malloc(1 + na->rxd.nr_ring_refs * sizeof(uint32_t));

	// Read the rx-ring-refs
	for (i = 0; i < na->rxd.nr_ring_refs; i++) {
		snprintf(path, sizeof(path), "%s/rx-ring-ref%u", na->nodename, i);
		na->rxd.ring_refs[i] = xenbus_read_integer(path);
	}

	return 0;
}

static
int xenbus_read_bufs_refs(struct netmap_ring *ring, struct netmap_mem_d *rdesc)
{
	int i, j;

	rdesc->nr_bufs_refs = ring->num_slots/2;
	rdesc->bufs_refs = malloc(1 + rdesc->nr_bufs_refs * sizeof(uint32_t));

	for (i = 0, j = 0; i < ring->num_slots; i++) {
		if (ring->slot[i].ptr != 0) {
			rdesc->bufs_refs[j++] = ring->slot[i].ptr;
		}
	}
	rdesc->nr_bufs_refs = j;

	return 0;
}

static
int xenbus_wait_for_backend(struct netfront_dev *dev)
{
	struct netmap_adapter *priv = dev->na;
	XenbusState state;
	char backend_path[256];
	char *err = NULL;
	char *backend;

	snprintf(backend_path, sizeof(backend_path), "%s/backend", priv->nodename);

	err = xenbus_read(XBT_NIL, backend_path, &backend);
	{
			char path[strlen(backend) + strlen("/state") + 1];
			snprintf(path, sizeof(path), "%s/state", backend);

			xenbus_watch_path_token(XBT_NIL, path, path, &dev->events);

			err = NULL;
			state = xenbus_read_integer(path);

			D("Waiting for %s/state change to connected",
				backend, state, XenbusStateConnected);

			while (err == NULL && state < XenbusStateConnected)
				err = xenbus_wait_for_state_change(path, &state, &dev->events);

			if (state != XenbusStateConnected) {
				D("backend not available, state=%d\n", state);
				return -EINVAL;
			}
	}
	return 0;
error:
	return -EINVAL;
}

#define rndup2(v) \
	v--;v|=v>>1;v|=v>>2;v|=v>>4;v|=v>>8;v|=v>>16;v++;

inline
void* init_netfront_netmap(struct netfront_dev *dev,
				void (*handler)(unsigned char* data, int len, void* arg))
{
	struct netmap_adapter *na;
	xenbus_transaction_t xbt;
	int retry = 0, id;
	char *err;
	char path[256];

	na = malloc(sizeof(struct netmap_adapter));
	memset(na,0,sizeof(struct netmap_adapter));
	na->nodename = dev->nodename;
	id = atoi(dev->nodename + strlen("device/vif/")) + 1;
	rndup2(id);
	na->devid = id;
	na->dom = dev->dom;
	na->netif_rx = handler;
	snprintf(path, sizeof(path), "%s/feature-netmap-tx-desc", dev->backend);
	na->num_tx_desc = xenbus_read_integer(path);

	snprintf(path, sizeof(path), "%s/feature-netmap-rx-desc", dev->backend);
	na->num_rx_desc = xenbus_read_integer(path);

	init_waitqueue_head(&na->txd.wait);

	D("backend dom %d", na->dom);

	if (evtchn_alloc_unbound(na->dom, netfront_tx_interrupt,
				dev, &na->tx_irq) < 0) {
		printk("failed to allocate event-channel-tx\n");
		goto fail;
	}

	if (evtchn_alloc_unbound(na->dom, netfront_rx_interrupt,
				dev, &na->rx_irq) < 0) {
		printk("failed to allocate event-channel-rx\n");
		goto fail;
	}

	xenbus_read_ring_refs(na);

	D("Mapping TX rings");
	netfront_gnttab_map(&na->txd, na->dom, 1);
	na->tx_rings = (struct netmap_ring*) na->txd.ring_gnt[0].host_addr;
	while (na->tx_rings->num_slots != na->num_tx_desc)
			rmb();

	D("Mapping RX rings");
	netfront_gnttab_map(&na->rxd, na->dom, 1);
	na->rx_rings = (struct netmap_ring*) na->rxd.ring_gnt[0].host_addr;
	while (na->rx_rings->num_slots != na->num_rx_desc)
			rmb();

	xenbus_read_bufs_refs(na->tx_rings, &na->txd);
	D("Mapping TX buffers");
	netfront_gnttab_map(&na->txd, na->dom, 0);
	na->txd.bufs_base = (char *) na->txd.bufs_gnt[0].host_addr;
	na->nr_buf_tx = na->txd.bufs_base;

	xenbus_read_bufs_refs(na->rx_rings, &na->rxd);
	D("Mapping RX buffers");
	netfront_gnttab_map(&na->rxd, na->dom, 0);
	na->rxd.bufs_base = (char *) na->rxd.bufs_gnt[0].host_addr;
	na->nr_buf_rx = na->rxd.bufs_base;

	na->stat = malloc(sizeof(struct netfront_csb));
	memset(na->stat, 0, sizeof(struct netfront_csb));
	na->stat->txcur = na->tx_rings->cur;
	na->stat->txhead = na->tx_rings->cur;
	na->stat->host_need_txkick = 1;
	na->stat->guest_need_txkick = 0;
	na->stat->host_need_rxkick = 0;
	na->stat->guest_need_rxkick = 1;

retry_transaction:
	err = xenbus_transaction_start(&xbt);

	err = xenbus_printf(xbt, dev->nodename, "event-channel-tx",
					"%u", na->tx_irq);
	if (err) {
		printk("error writing event-channel-tx");
		goto abort_transaction;
	}

	err = xenbus_printf(xbt, dev->nodename, "event-channel-rx",
					"%u", na->rx_irq);
	if (err) {
		printk("error writing event-channel-rx");
		goto abort_transaction;
	}

	snprintf(path, sizeof(path), "%s/state", dev->nodename);
	err = xenbus_switch_state(xbt, path, XenbusStateConnected);

	err = xenbus_transaction_end(xbt, 0, &retry);
	free(err);
	if (retry) {
		goto retry_transaction;
	}


	printk("init_netfront_netmap %s\n", dev->nodename);
	return na;
abort_transaction:
	free(err);
fail:
	return NULL;
}

inline
void  connect_netfront(struct netfront_dev *dev)
{
	struct netmap_adapter *na = dev->na;
	xenbus_wait_for_backend(dev);
	D("unmasking event-channel-tx %d", na->tx_irq);
	unmask_evtchn(na->tx_irq);
	D("unmasking event-channel-rx %d", na->rx_irq);
	unmask_evtchn(na->rx_irq);

	notify_remote_via_evtchn(na->tx_irq);
	notify_remote_via_evtchn(na->rx_irq);
}

inline
void shutdown_netfront_netmap(struct netfront_dev *dev)
{
	struct netmap_adapter *na = dev->na;
	u_int flags;

	for (;;) {
		wait_event_deadline(na->txd.wait,
						na->stat->guest_need_txkick == 0, 0);
		if (!(na->stat->guest_need_txkick)) {
			break;
		}
	}

	local_irq_save(flags);
	D("Unmapping TX");
	netfront_gnttab_unmap(&na->txd);

	D("Unmapping RX");
	netfront_gnttab_unmap(&na->rxd);

	mask_evtchn(na->tx_irq);
	unbind_evtchn(na->tx_irq);
	mask_evtchn(na->rx_irq);
	unbind_evtchn(na->rx_irq);

	local_irq_restore(flags);

	printk("shutdown_netfront_netmap %s\n", na->nodename);
}

#endif
