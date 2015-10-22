/* Minimal network driver for Mini-OS.
 * Copyright (c) 2006-2007 Jacob Gorm Hansen, University of Copenhagen.
 * Copyright (c) 2014-2015 Joao Martins, NEC Europe Ltd.
 * Based on netfront.c from Xen Linux.
 *
 * Does not handle fragments or extras for transmit.
 */
#include <mini-os/os.h>
#include <mini-os/xenbus.h>
#include <mini-os/events.h>
#include <errno.h>
#include <xen/io/netif.h>
#include <mini-os/gnttab.h>
#include <mini-os/xmalloc.h>
#include <mini-os/time.h>
#include <mini-os/netfront.h>
#include <mini-os/lib.h>
#include <mini-os/semaphore.h>
#include <xen/io/netif.h>

#if defined(__x86_64__) && !defined DEBUG_BUILD
#include <rte_memcpy.h>
#define NETIF_MEMCPY(dst, src, len)  rte_memcpy((dst), (src), (len))
#else
#define NETIF_MEMCPY(dst, src, len)  memcpy((dst), (src), (len))
#endif

#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(num, div) (((num) + (div) - 1) / (div))
#endif

#ifdef HAVE_LWIP
#include "lwip/pbuf.h"
#include <lwip/stats.h>
#endif

DECLARE_WAIT_QUEUE_HEAD(netfront_queue);

#ifdef HAVE_LIBC
#define NETIF_SELECT_RX ((void*)-1)
#endif

#ifndef min
#define min(a, b)						\
    ({ __typeof__ (a) __a = (a);				\
       __typeof__ (b) __b = (b);				\
       __a < __b ? __a : __b; })
#endif

#define dprintk(format, ...)	do {} while(0)

#ifndef dprintk
#define dprintk(format, ...)	printk(format,##__VA_ARGS__)
#endif

#define NET_TX_RING_SIZE __CONST_RING_SIZE(netif_tx, PAGE_SIZE)
#define NET_RX_RING_SIZE __CONST_RING_SIZE(netif_rx, PAGE_SIZE)
#define GRANT_INVALID_REF 0

struct net_buffer {
	void* page;
	grant_ref_t gref;
};

struct netfront_dev {
	domid_t dom;

	unsigned short tx_freelist[NET_TX_RING_SIZE + 1];
	struct semaphore tx_sem;

	struct net_buffer rx_buffers[NET_RX_RING_SIZE];
	struct net_buffer tx_buffers[NET_TX_RING_SIZE];

	struct netif_tx_front_ring tx;
	struct netif_rx_front_ring rx;

	/* inflight response to be handled */
	struct netif_rx_response rsp;
	/* extras (if any) of the inflight buffer */
	struct netif_extra_info extras[XEN_NETIF_EXTRA_TYPE_MAX - 1];
	/* inflight buffer */
	struct pbuf *pbuf;
	/* next available chunk */
	struct pbuf *pbuf_cur;
	uint32_t pbuf_off;

	grant_ref_t tx_ring_ref;
	grant_ref_t rx_ring_ref;

	evtchn_port_t tx_evtchn;
	evtchn_port_t rx_evtchn;

	char *nodename;
	char *backend;
	char *mac;
#ifdef CONFIG_NETMAP
	int netmap;
	void *na;
#endif

	xenbus_event_queue events;

#ifdef HAVE_LIBC
	int fd;
	unsigned char *data;
	size_t len;
	size_t rlen;
#endif

#ifdef HAVE_LWIP
	void (*netif_rx_pbuf)(struct pbuf *p, void *arg);
#endif
	void (*netif_rx)(unsigned char* data, int len, void *arg);
	void *netif_rx_arg;
};

struct netfront_dev_list {
	struct netfront_dev *dev;
	unsigned char rawmac[6];
	char *ip;

	int refcount;

	struct netfront_dev_list *next;
};

#ifdef CONFIG_NETMAP
#include <mini-os/netfront_netmap.h>
#endif

static struct netfront_dev_list *dev_list = NULL;

static void init_rx_buffers(struct netfront_dev *dev);
static void netfront_tx_buf_gc(struct netfront_dev *dev);
static struct netfront_dev *_init_netfront(struct netfront_dev *dev,
					   unsigned char rawmac[6], char **ip);
static void _shutdown_netfront(struct netfront_dev *dev);

static inline void add_id_to_freelist(unsigned short id, unsigned short *freelist)
{
	freelist[id + 1] = freelist[0];
	freelist[0]  = id;
}

static inline unsigned short get_id_from_freelist(unsigned short *freelist)
{
	unsigned int id = freelist[0];
	freelist[0] = freelist[id + 1];
	return id;
}

__attribute__((weak)) void netif_rx(unsigned char* data, int len, void *arg)
{
	printk("%d bytes incoming at %p\n", len, data);
}

__attribute__((weak)) void net_app_main(void *si, unsigned char *mac)
{}

#ifdef HAVE_LWIP
__attribute__((weak)) void netif_rx_pbuf(struct pbuf *p, void *arg)
{
	printk("%d bytes incoming at pbuf %p\n", p->len, p);
}

struct eth_addr *netfront_get_hwaddr(struct netfront_dev *dev,
				     struct eth_addr *out)
{
	if (sscanf(dev->mac,
			   "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			   &out->addr[0],
			   &out->addr[1],
			   &out->addr[2],
			   &out->addr[3],
			   &out->addr[4],
			   &out->addr[5]) == 6) {
		return out;
	}

	return NULL;
}

/* Copies data to a pbuf */
static inline void pbuf_copy_bits(struct pbuf **p, uint32_t *offset,
				  unsigned char *data, int32_t len)
{
	struct pbuf *q;
	uint32_t q_ofs = *offset;
	unsigned char *cur = data;
	int l = min(len, (*p)->len);

	dprintk("rx: copy: pbuf %p ofs %d len %d p->len %d l %d\n",
		*p, q_ofs, len, (*p)->len, l);

	/* pbuf chain */
	for(q = *p; q && len > 0; cur += l) {
		l = min(len, q->len - q_ofs);
		NETIF_MEMCPY(q->payload + q_ofs, cur, l);

		dprintk("rx: copy: pbuf %p ofs %d l %d\n", q, q_ofs, l);

		len -= l;
		q_ofs += l;
		if (q_ofs >= q->len) {
			q_ofs = 0;
			q = q->next;
		}
	}

	if (q) {
		*p = q;
		*offset = q_ofs;
	}
}

/* Allocates a pbuf */
static inline struct pbuf *netfront_alloc_pbuf(struct netfront_dev *dev,
					       unsigned char *data, int32_t len,
					       int32_t realsize, int pad)
{
	struct pbuf *p;

	p = pbuf_alloc(PBUF_RAW, realsize + pad, PBUF_POOL);
	if (unlikely(!p))
		return NULL;

#if ETH_PAD_SIZE
	pbuf_header(p, -ETH_PAD_SIZE); /* drop the padding word */
#endif

	if (likely(!p->next)) {
		/* fast path */
		NETIF_MEMCPY(p->payload, data, len);
	} else {
		dev->pbuf_cur = p;
		dev->pbuf_off = 0;
		pbuf_copy_bits(&dev->pbuf_cur, &dev->pbuf_off, data, len);
	}

#if ETH_PAD_SIZE
	pbuf_header(p, ETH_PAD_SIZE); /* reclaim the padding word */
#endif
	return p;
}

static inline void handle_pbuf(struct netfront_dev *dev,
			       struct netif_rx_response *rx,
			       struct net_buffer *buf, int32_t realsize)
{
	unsigned char* page = buf->page;
	if (likely(!dev->pbuf)) { /* it's a paged pbuf */
		dprintk("rx: handle: new: pbuf %d\n", realsize);
		dev->pbuf = netfront_alloc_pbuf(dev, page+rx->offset, rx->status,
						realsize, ETH_PAD_SIZE);

		/* XXX TODO: Request refill */
		BUG_ON(!dev->pbuf);
	} else {
		dprintk("rx: handle: copy: pbuf %d\n", rx->status);
		pbuf_copy_bits(&dev->pbuf_cur, &dev->pbuf_off,
			       page+rx->offset, rx->status);
	}
}
#endif

/*
 * Main entry point for handling a packet. If HAVE_LWIP is set
 * we allow passing up pbufs upon registering the appropriate
 * callback.
 */
static inline int handle_buffer(struct netfront_dev *dev,
				struct netif_rx_response *rx,
				struct net_buffer *buf, int32_t realsize)
{
	unsigned char* page = buf->page;

#ifdef HAVE_LIBC
	if (dev->netif_rx == NETIF_SELECT_RX) {
		int len = rx->status;
		ASSERT(current == main_thread);
		if (len > dev->len)
			len = dev->len;
		NETIF_MEMCPY(dev->data, page+rx->offset, len);
		dev->rlen = len;
		return 1;
	}
#endif
	dprintk("rx: %c%c- %u bytes\n",
		rx->flags & NETRXF_extra_info ? 'S' : '-',
		rx->flags & ((NETRXF_csum_blank) | (NETRXF_data_validated)) ? 'C' : '-',
		rx->status);

	if (dev->netif_rx)
		dev->netif_rx(page+rx->offset, rx->status, dev->netif_rx_arg);

#ifdef HAVE_LWIP
	if (dev->netif_rx_pbuf)
		handle_pbuf(dev, rx, buf, realsize);
#endif
	return 1;
}

/* req->id is numbered from 0 - 255 */
static inline int netfront_rxidx(RING_IDX idx)
{
	return idx & (NET_RX_RING_SIZE - 1);
}

/*
 * Computes the size of the pbuf to allocate based
 * on how many slots the (possible GSO) frame requires.
 */
static int netfront_get_size(struct netfront_dev *dev, RING_IDX ri)
{
	struct netif_rx_response *rx;
	int32_t len = 0;
	int slots = 1;

	do {
		rx = RING_GET_RESPONSE(&dev->rx, ++ri);
		dprintk("rx: scan: slot %d len %d (more %s)\n",
			slots, rx->status,
			(rx->flags & NETRXF_more_data
				? "true": "false"));
		len += rx->status;
		slots++;
	} while (rx->flags & NETRXF_more_data);

	return len;
}

/*
 * Reads extra slots to check for a GSO packet
 */
static int netfront_get_extras(struct netfront_dev *dev,
			       struct netif_extra_info *extras, RING_IDX ri)
{
	struct netif_extra_info *extra;
	RING_IDX cons = dev->rx.rsp_cons;
	int err = 0;

	do {
		extra = (struct netif_extra_info *)
			RING_GET_RESPONSE(&dev->rx, ++cons);

		if (unlikely(!extra->type ||
			     extra->type >= XEN_NETIF_EXTRA_TYPE_MAX)) {
			printk("Invalid extra type: %d\n", extra->type);
			err = -EINVAL;
		} else {
			dprintk("rx: scan: extra %u %s\n", extra->type,
				(extra->flags & XEN_NETIF_EXTRA_FLAG_MORE
					? "(more true)": ""));
			NETIF_MEMCPY(&extras[extra->type - 1], extra,
			       sizeof(*extra));
		}
	} while (extra->flags & XEN_NETIF_EXTRA_FLAG_MORE);

	dev->rx.rsp_cons = cons;
	return err;
}

/*
 * Reads RX responses for a single packet
 */
static int netfront_get_responses(struct netfront_dev *dev,
				  RING_IDX rp)
{
	struct netif_rx_response *rsp = &(dev->rsp);
	int32_t realsize = rsp->status;
	int16_t size = rsp->status;
	uint16_t id = rsp->id;
	uint16_t flags = rsp->flags;
	RING_IDX cons = rp;
	uint16_t slots = 1;

	dprintk("rx: ring: len %d %s\n", size,
		(flags & NETRXF_more_data ? "(more true) ": ""));

	BUG_ON(id >= NET_TX_RING_SIZE);

	if (flags & NETRXF_extra_info) {
		memset(dev->extras, 0, sizeof(dev->extras));
		netfront_get_extras(dev, dev->extras, cons);
		cons = dev->rx.rsp_cons;
	}

	if (flags & NETRXF_more_data) {
		dprintk("rx: scan: slot 0 len %d %s\n",
			size, (flags & NETRXF_more_data ? "(more true)": ""));
		realsize = size + netfront_get_size(dev, cons);
	}

	for (;;) {
		if (unlikely(rsp->status < 0 ||
			     (rsp->offset + rsp->status > PAGE_SIZE)))
			printk("rx: ring: rx->offset %d, size %d\n",
				rsp->offset, size);
		else
			handle_buffer(dev, rsp, &dev->rx_buffers[id], realsize);

		if (!(flags & NETRXF_more_data))
			break;

		rsp = RING_GET_RESPONSE(&dev->rx, cons + slots);
		id = rsp->id;
		size = rsp->status;
		flags = rsp->flags;
		slots++;

		dprintk("rx: ring: len %d %s\n", size,
			(flags & NETRXF_more_data ? "(more true) ": ""));
	}

	dev->rx.rsp_cons = cons + slots;
	return 1;
}

void netfront_rx(struct netfront_dev *dev)
{
	RING_IDX rp, cons, prod;
	struct netif_rx_response *rsp = &(dev->rsp);
	struct netif_rx_request *req;
	int notify;
	int more;

#ifdef CONFIG_NETMAP
	if (dev->netmap) {
		netmap_netfront_rx(dev);
		return;
	}
#endif
moretodo:
	rp = dev->rx.sring->rsp_prod;
	rmb(); /* Ensure we see queued responses up to 'rp'. */
	cons = dev->rx.rsp_cons;

	while (cons != rp) {
		NETIF_MEMCPY(rsp, RING_GET_RESPONSE(&dev->rx, cons), sizeof(*rsp));
		netfront_get_responses(dev, cons);

#ifdef HAVE_LWIP
		if (dev->pbuf) {
			dprintk("rx: handle: netif: pbuf %u\n", dev->pbuf->tot_len);
			dev->netif_rx_pbuf(dev->pbuf, dev->netif_rx_arg);
			dev->pbuf = NULL;
			dev->pbuf_cur = NULL;
			dev->pbuf_off = 0;
		}
#endif

		cons = dev->rx.rsp_cons;
	}

	dev->rx.rsp_cons = cons;
	RING_FINAL_CHECK_FOR_RESPONSES(&dev->rx, more);
	if(more)
		goto moretodo;

	for (prod = dev->rx.req_prod_pvt;
	     prod - dev->rx.rsp_cons < NET_RX_RING_SIZE;
	     prod++) {
		uint16_t id = netfront_rxidx(prod);
		grant_ref_t ref = dev->rx_buffers[id].gref;

		req = RING_GET_REQUEST(&dev->rx, prod);
		req->id = id;
		req->gref = ref;
	}

	dev->rx.req_prod_pvt = prod;
	wmb();
	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&dev->rx, notify);
#ifdef CONFIG_SELECT_POLL
	files[dev->fd].read = 0;
#endif
	if (notify)
		notify_remote_via_evtchn(dev->rx_evtchn);
}

void netfront_rx_handler(evtchn_port_t port, struct pt_regs *regs, void *data)
{
	struct netfront_dev *dev = data;
	int fd = dev->fd;

#ifdef CONFIG_SELECT_POLL
	if (fd != -1)
		files[fd].read = 1;

	wake_up(&netfront_queue);
#endif
}

void netfront_tx_handler(evtchn_port_t port, struct pt_regs *regs, void *data)
{
	int flags;
	struct netfront_dev *dev = data;

	local_irq_save(flags);
	netfront_tx_buf_gc(dev);
	local_irq_restore(flags);
}

void netfront_handler(evtchn_port_t port, struct pt_regs *regs, void *data)
{
	netfront_tx_handler(port, regs, data);
	netfront_rx_handler(port, regs, data);
}

#ifdef HAVE_LIBC
void netfront_select_handler(evtchn_port_t port, struct pt_regs *regs, void *data)
{
	int flags;
	struct netfront_dev *dev = data;
	int fd = dev->fd;

	local_irq_save(flags);
	netfront_tx_buf_gc(dev);
	local_irq_restore(flags);

	if (fd != -1)
		files[fd].read = 1;
	wake_up(&netfront_queue);
}

int netfront_tap_open(char *nodename)
{
	struct netfront_dev *dev;

	dev = init_netfront(nodename, NETIF_SELECT_RX, NULL, NULL);
	if (!dev) {
		printk("TAP open failed\n");
		errno = EIO;
		return -1;
	}
	dev->fd = alloc_fd(FTYPE_TAP);
	printk("tap_open(%s) -> %d\n", nodename, dev->fd);
	files[dev->fd].tap.dev = dev;
	return dev->fd;
}

ssize_t netfront_receive(struct netfront_dev *dev, unsigned char *data,
			 size_t len)
{
	unsigned long flags;
	int fd = dev->fd;
	ASSERT(current == main_thread);

	dev->rlen = 0;
	dev->data = data;
	dev->len = len;

	local_irq_save(flags);
	netfront_rx(dev);

	if (!dev->rlen && fd != -1)
		/* No data for us, make select stop returning */
		files[fd].read = 0;

	/* Before re-enabling the interrupts, in case a packet just arrived in the
	 * meanwhile. */
	local_irq_restore(flags);

	dev->data = NULL;
	dev->len = 0;

	return dev->rlen;
}
#endif

void netfront_set_rx_handler(struct netfront_dev *dev,
			     void (*thenetif_rx)(unsigned char *data, int len,
						 void *arg),
			     void *arg)
{
	if (dev->netif_rx && dev->netif_rx != netif_rx)
		printk("Replacing netif_rx handler for dev %s\n", dev->nodename);

	dev->netif_rx = thenetif_rx;
	dev->netif_rx_arg = arg;
}

static void netfront_tx_buf_gc(struct netfront_dev *dev)
{
	RING_IDX cons, prod;
	unsigned short id;

	do {
		prod = dev->tx.sring->rsp_prod;
		rmb(); /* Ensure we see responses up to 'rp'. */

		for (cons = dev->tx.rsp_cons; cons != prod; cons++) {
			struct netif_tx_response *txrsp;

			txrsp = RING_GET_RESPONSE(&dev->tx, cons);
			if (txrsp->status == NETIF_RSP_NULL)
				continue;

			if (txrsp->status == NETIF_RSP_ERROR)
				printk("tx: error");

			id  = txrsp->id;
			BUG_ON(id >= NET_TX_RING_SIZE);

			add_id_to_freelist(id, dev->tx_freelist);
			up(&dev->tx_sem);
		}

		dev->tx.rsp_cons = prod;

		/*
		 * Set a new event, then check for race with update of tx_cons.
		 * Note that it is essential to schedule a callback, no matter
		 * how few tx_buffers are pending. Even if there is space in the
		 * transmit ring, higher layers may be blocked because too much
		 * data is outstanding: in such cases notification from Xen is
		 * likely to be the only kick that we'll get.
		 */
		dev->tx.sring->rsp_event =
			prod + ((dev->tx.sring->req_prod - prod) >> 1) + 1;
		mb();
	} while ((cons == prod) && (prod != dev->tx.sring->rsp_prod));
}

/*
 * Gets a free TX request for copying data to backend
 */
static inline struct netif_tx_request *netfront_get_page(struct netfront_dev *dev)
{
	struct netif_tx_request *tx;
	unsigned short id;
	struct net_buffer* buf;
	int flags;

	local_irq_save(flags);
	if (unlikely(!trydown(&dev->tx_sem))) {
		local_irq_restore(flags);
		return NULL; /* we run out of available pages */
	}
	id = get_id_from_freelist(dev->tx_freelist);
	buf = &dev->tx_buffers[id];
	local_irq_restore(flags);

	tx = RING_GET_REQUEST(&dev->tx, dev->tx.req_prod_pvt++);
	tx->gref = buf->gref;
	tx->offset = 0;
	tx->size = 0;
	tx->id = id;
	tx->flags = 0;
	return tx;
}

#define netfront_tx_available(dev, slots) \
  (((dev)->tx.req_prod_pvt - (dev)->tx.rsp_cons) < (NET_TX_RING_SIZE - (slots)))

static inline void netfront_xmit_notify(struct netfront_dev *dev)
{
	int notify;

	/* So that backend sees new requests and check notify */
	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&dev->tx, notify);
	if (notify)
		notify_remote_via_evtchn(dev->tx_evtchn);
}

/**
 * Transmit function for raw buffers (non-GSO/TCO)
 */
void netfront_xmit(struct netfront_dev *dev, unsigned char *data, int len)
{
	int flags;
	struct netif_tx_request *tx;
	void* page;

#ifdef CONFIG_NETMAP
	if (dev->netmap) {
		netmap_netfront_xmit(dev->na, data, len);
		return;
	}
#endif

	BUG_ON(len > PAGE_SIZE);

	if (!netfront_tx_available(dev, 1))
		goto out;

	tx = netfront_get_page(dev);
	ASSERT(tx != NULL);
	page = dev->tx_buffers[tx->id].page;
	NETIF_MEMCPY(page, data, len);
	tx->flags |= (NETTXF_data_validated);
	tx->size = len;

	netfront_xmit_notify(dev);
	dprintk("tx: raw %d\n", len);

out:
	local_irq_save(flags);
	netfront_tx_buf_gc(dev);
	local_irq_restore(flags);
}

#ifdef HAVE_LWIP
#define netfront_count_pbuf_slots(dev, len) \
	DIV_ROUND_UP((len), PAGE_SIZE);

static inline struct netif_tx_request *netfront_make_txreqs(struct netfront_dev *dev,
							    struct netif_tx_request *tx,
							    struct pbuf *p, int *slots)
{
	void *page = dev->tx_buffers[tx->id].page;
	unsigned page_off, page_left;
	unsigned p_off, p_left;
	unsigned len;

	(*slots)  = 0;
	p_off     = 0;
	p_left    = p->len;
	page_off  = tx->size;
	page_left = (PAGE_SIZE) - page_off;
	for (;;) {
		len = min(page_left, p_left);

		dprintk("tx: make_txreqs: slot %3u, id %3u: page@%12p, page_off: %4u page_left: %4u <-%-4u bytes-- p@%12p, p_off: %4u, p_left: %4u\n",
			*slots, tx->id, page, page_off, page_left, len, p->payload, p_off, p_left);
		NETIF_MEMCPY((void *)(((uintptr_t) page) + page_off),
			     (void *)(((uintptr_t) p->payload) + p_off),
			     len);
		p_off     += len;
		p_left    -= len;
		tx->size  += len;
		page_off  += len;
		page_left -= len;

		if (!p_left) {
			if (!p->next)
				break; /* we are done processing this pbuf chain */
			p = p->next;
			p_off  = 0;
			p_left = p->len;
		}
		if (!page_left) {
			tx->flags |= NETTXF_more_data;
			tx = netfront_get_page(dev); /* next page */
			ASSERT(tx != NULL); /* out of memory
					       -> this should have been catched before calling this function */
			page = dev->tx_buffers[tx->id].page;
			page_off = 0;
			page_left = PAGE_SIZE;
			(*slots)++;
		}
	}
	return tx;
}

/**
 * Transmit function for pbufs which can handle checksum and segmentation offloading for TCPv4 and TCPv6
 */
err_t netfront_xmit_pbuf(struct netfront_dev *dev, struct pbuf *p, int tso, int push)
{
	struct netif_tx_request *first_tx, *tx;
	struct netif_extra_info *extra_info;
	int slots;
	int used = 0;
	int flags;
	struct pbuf *q;
	void *page;
#ifdef CONFIG_NETFRONT_GSO
	int gso;
#endif /* CONFIG_NETFRONT_GSO */

	/* Counts how many slots we require for this buf */
	slots = netfront_count_pbuf_slots(dev, p->tot_len);
#ifdef CONFIG_NETFRONT_GSO
	gso = (p->tot_len > TCP_MSS) ? 1 : 0;
	/* GSO requires TCP offloading set */
	BUG_ON(gso && !(tso & (XEN_NETIF_GSO_TYPE_TCPV4 | XEN_NETIF_GSO_TYPE_TCPV6)));
#endif /* CONFIG_NETFRONT_GSO */

	/* Checks if there are enough requests for this many slots (gso requires one slot more) */
#ifdef CONFIG_NETFRONT_GSO
	if (unlikely(!netfront_tx_available(dev, slots + gso))) {
#else
	if (unlikely(!netfront_tx_available(dev, slots))) {
#endif /* CONFIG_NETFRONT_GSO */
		netfront_xmit_push(dev);
		return ERR_MEM;
	}

	/* Set extras if packet is GSO kind */
	first_tx = netfront_get_page(dev);
	ASSERT(first_tx != NULL);
#ifdef CONFIG_NETFRONT_GSO
	if (gso) {
		first_tx->flags |= NETTXF_extra_info;
		extra_info = RING_GET_REQUEST(&dev->tx, dev->tx.req_prod_pvt++);
		extra_info->type = XEN_NETIF_EXTRA_TYPE_GSO;
		extra_info->flags = 0;
		extra_info->u.gso.size = TCP_MSS;
		extra_info->u.gso.type = tso; /* XEN_NETIF_GSO_TYPE_TCPV4, XEN_NETIF_GSO_TYPE_TCPV6 */
		extra_info->u.gso.pad = 0;
		extra_info->u.gso.features = 0;

		used++;
	}
	/* partially checksummed (offload enabled), or checksummed */
	first_tx->flags |= tso ? ((NETTXF_csum_blank) | (NETTXF_data_validated)) : (NETTXF_data_validated);
#else
	first_tx->flags |= (NETTXF_data_validated);
#endif /* CONFIG_NETFRONT_GSO */

	/* Make TX requests for the pbuf */
	tx = netfront_make_txreqs(dev, first_tx, p, &used);
	ASSERT(slots >= used);       /* we should have taken at most the number slots we required */
	first_tx->size = p->tot_len; /* first request contains total size of packet */

	push |= (((dev)->tx.req_prod_pvt - (dev)->tx.rsp_cons) <= NET_TX_RING_SIZE / 2);
	if (push)
		netfront_xmit_push(dev);

	dprintk("tx: %c%c%c %u bytes (%u slots)\n", gso ? 'S' : '-', tso ? 'C' : '-', push ? 'P' : '-', p->tot_len, slots);

	return ERR_OK;
}

void netfront_xmit_push(struct netfront_dev *dev)
{
	int flags;

	netfront_xmit_notify(dev);

	/* Collects any outstanding responses for more requests */
	local_irq_save(flags);
	netfront_tx_buf_gc(dev);
	local_irq_restore(flags);
}

void netfront_set_rx_pbuf_handler(struct netfront_dev *dev,
				  void (*thenetif_rx)(struct pbuf *p, void *arg),
				  void *arg)
{
	if (dev->netif_rx_pbuf && dev->netif_rx_pbuf != netif_rx_pbuf)
		printk("Replacing netif_rx_pbuf handler for dev %s\n", dev->nodename);

	dev->netif_rx = NULL;
	dev->netif_rx_pbuf = thenetif_rx;
	dev->netif_rx_arg = arg;

	/* Reset runtime state*/
	dev->pbuf = NULL;
	dev->pbuf_cur = NULL;
	dev->pbuf_off = 0;
}
#endif

static void free_netfront(struct netfront_dev *dev)
{
	int i;
	int separate_tx_rx_irq = (dev->tx_evtchn != dev->rx_evtchn);

	free(dev->mac);
	free(dev->backend);

#ifdef CONFIG_NETMAP
	if (dev->netmap)
		return;
#endif

	for(i=0; i<NET_TX_RING_SIZE; i++)
		down(&dev->tx_sem);

	mask_evtchn(dev->tx_evtchn);
	if (separate_tx_rx_irq)
		mask_evtchn(dev->rx_evtchn);

	gnttab_end_access(dev->rx_ring_ref);
	gnttab_end_access(dev->tx_ring_ref);

	free_page(dev->rx.sring);
	free_page(dev->tx.sring);

	unbind_evtchn(dev->tx_evtchn);
	if (separate_tx_rx_irq)
		unbind_evtchn(dev->rx_evtchn);

	for(i=0; i<NET_RX_RING_SIZE; i++) {
		gnttab_end_access(dev->rx_buffers[i].gref);
		free_page(dev->rx_buffers[i].page);
	}

	for(i=0; i<NET_TX_RING_SIZE; i++) {
		if (dev->tx_buffers[i].page) {
			gnttab_end_access(dev->tx_buffers[i].gref);
			free_page(dev->tx_buffers[i].page);
		}
	}
}

struct netfront_dev *init_netfront(char *_nodename,
				   void (*thenetif_rx)(unsigned char* data,
						       int len, void *arg),
				   unsigned char rawmac[6],
				   char **ip)
{
	char nodename[256];
	struct netfront_dev *dev;
	struct netfront_dev_list *ldev = NULL;
	struct netfront_dev_list *list = NULL;
	static int netfrontends = 0;

	if (!_nodename)
		snprintf(nodename, sizeof(nodename), "device/vif/%d", netfrontends);
	else {
		strncpy(nodename, _nodename, sizeof(nodename) - 1);
		nodename[sizeof(nodename) - 1] = 0;
	}

	/* Check if the device is already initialized */
	for ( list = dev_list; list != NULL; list = list->next) {
		if (strcmp(nodename, list->dev->nodename) == 0) {
			list->refcount++;
			dev = list->dev;
			if (thenetif_rx)
				netfront_set_rx_handler(dev, thenetif_rx, NULL);
			goto out;
		}
	}

	if (!thenetif_rx)
		thenetif_rx = netif_rx;

	dev = malloc(sizeof(*dev));
	memset(dev, 0, sizeof(*dev));
	dev->nodename = strdup(nodename);
#if defined(HAVE_LIBC) || defined(CONFIG_SELECT_POLL)
	dev->fd = -1;
#endif
	dev->netif_rx = thenetif_rx;
	dev->netif_rx_arg = NULL;

	ldev = malloc(sizeof(struct netfront_dev_list));
	memset(ldev, 0, sizeof(struct netfront_dev_list));

	if (_init_netfront(dev, ldev->rawmac, &(ldev->ip))) {
		ldev->dev = dev;
		ldev->refcount = 1;
		ldev->next = NULL;

		if (!dev_list) {
			dev_list = ldev;
		} else {
			for (list = dev_list; list->next != NULL; list = list->next);
			list->next = ldev;
		}

		netfrontends++;
	} else {
		free(dev->nodename);
		free(dev);
		free(ldev);
		dev = NULL;
		goto err;
	}

out:
	if (rawmac) {
		rawmac[0] = ldev->rawmac[0];
		rawmac[1] = ldev->rawmac[1];
		rawmac[2] = ldev->rawmac[2];
		rawmac[3] = ldev->rawmac[3];
		rawmac[4] = ldev->rawmac[4];
		rawmac[5] = ldev->rawmac[5];
	}
	if (ip) {
		*ip = malloc(strlen(ldev->ip) + 1);
		strncpy(*ip, ldev->ip, strlen(ldev->ip) + 1);
	}

err:
	return dev;
}

static struct netfront_dev *_init_netfront(struct netfront_dev *dev,
					   unsigned char rawmac[6],
					   char **ip)
{
	xenbus_transaction_t xbt;
	char* err = NULL;
	const char* message=NULL;
	struct netif_tx_sring *txs;
	struct netif_rx_sring *rxs;
	int feature_split_evtchn;
	int retry=0;
	int i;
	char* msg = NULL;
	char path[256];

	snprintf(path, sizeof(path), "%s/backend-id", dev->nodename);
	dev->dom = xenbus_read_integer(path);

	snprintf(path, sizeof(path), "%s/backend", dev->nodename);
	msg = xenbus_read(XBT_NIL, path, &dev->backend);
	snprintf(path, sizeof(path), "%s/mac", dev->nodename);
	msg = xenbus_read(XBT_NIL, path, &dev->mac);
	if ((dev->backend == NULL) || (dev->mac == NULL)) {
		printk("%s: backend/mac failed\n", __func__);
		goto error;
	}

#ifdef CONFIG_NETMAP
	snprintf(path, sizeof(path), "%s/feature-netmap", dev->backend);
	dev->netmap = xenbus_read_integer(path) > 0 ? 1 : 0;

	if (dev->netmap) {
			dev->na = init_netfront_netmap(dev, dev->netif_rx);
			goto skip;
	}
#endif
	/* Check feature-split-event-channels */
	snprintf(path, sizeof(path), "%s/feature-split-event-channels",
		 dev->backend);
	feature_split_evtchn = xenbus_read_integer(path) > 0 ? 1 : 0;
#ifdef HAVE_LIBC
	/* Force the use of a single event channel */
	if (dev->netif_rx == NETIF_SELECT_RX)
		feature_split_evtchn = 0;
#endif

	printk("************************ NETFRONT for %s **********\n\n\n",
	       dev->nodename);

	printk("net TX ring size %d\n", NET_TX_RING_SIZE);
	printk("net RX ring size %d\n", NET_RX_RING_SIZE);
	init_SEMAPHORE(&dev->tx_sem, NET_TX_RING_SIZE);
	for(i=0;i<NET_TX_RING_SIZE;i++)
	{
		add_id_to_freelist(i,dev->tx_freelist);
		dev->tx_buffers[i].page = (char*)alloc_page();
		dev->tx_buffers[i].gref = gnttab_grant_access(dev->dom,
							      virt_to_mfn(dev->tx_buffers[i].page), 1);
	}

	for(i=0;i<NET_RX_RING_SIZE;i++)
	{
	/* TODO: that's a lot of memory */
		dev->rx_buffers[i].page = (char*)alloc_page();
	}

	if (feature_split_evtchn) {
		evtchn_alloc_unbound(dev->dom, netfront_tx_handler, dev,
				     &dev->tx_evtchn);
		evtchn_alloc_unbound(dev->dom, netfront_rx_handler, dev,
				     &dev->rx_evtchn);
	} else {
#ifdef HAVE_LIBC
		if (dev->netif_rx == NETIF_SELECT_RX)
			evtchn_alloc_unbound(dev->dom, netfront_select_handler,
					     dev, &dev->tx_evtchn);
		else
#endif
			evtchn_alloc_unbound(dev->dom, netfront_handler,
					     dev, &dev->tx_evtchn);
		dev->rx_evtchn = dev->tx_evtchn;
	}


	txs = (struct netif_tx_sring *) alloc_page();
	rxs = (struct netif_rx_sring *) alloc_page();
	memset(txs,0,PAGE_SIZE);
	memset(rxs,0,PAGE_SIZE);


	SHARED_RING_INIT(txs);
	SHARED_RING_INIT(rxs);
	FRONT_RING_INIT(&dev->tx, txs, PAGE_SIZE);
	FRONT_RING_INIT(&dev->rx, rxs, PAGE_SIZE);

	dev->tx_ring_ref = gnttab_grant_access(dev->dom,virt_to_mfn(txs),0);
	dev->rx_ring_ref = gnttab_grant_access(dev->dom,virt_to_mfn(rxs),0);

	init_rx_buffers(dev);

	dev->events = NULL;

again:
	err = xenbus_transaction_start(&xbt);
	if (err) {
		printk("starting transaction\n");
		free(err);
	}

	err = xenbus_printf(xbt, dev->nodename, "tx-ring-ref","%u",
				dev->tx_ring_ref);
	if (err) {
		message = "writing tx ring-ref";
		goto abort_transaction;
	}
	err = xenbus_printf(xbt, dev->nodename, "rx-ring-ref","%u",
				dev->rx_ring_ref);
	if (err) {
		message = "writing rx ring-ref";
		goto abort_transaction;
	}

	if (feature_split_evtchn) {
		err = xenbus_printf(xbt, dev->nodename,
					"event-channel-tx", "%u", dev->tx_evtchn);
		if (err) {
			message = "writing event-channel-tx";
			goto abort_transaction;
		}
		err = xenbus_printf(xbt, dev->nodename,
					"event-channel-rx", "%u", dev->rx_evtchn);
		if (err) {
			message = "writing event-channel-rx";
			goto abort_transaction;
		}
	} else {
		err = xenbus_printf(xbt, dev->nodename,
					"event-channel", "%u", dev->tx_evtchn);
		if (err) {
			message = "writing event-channel";
			goto abort_transaction;
		}
	}

	err = xenbus_printf(xbt, dev->nodename, "feature-rx-notify", "%u", 1);

	if (err) {
		message = "writing feature-rx-notify";
		goto abort_transaction;
	}

#ifdef CONFIG_NETFRONT_PERSISTENT_GRANTS
	err = xenbus_printf(xbt, dev->nodename, "feature-persistent", "%u", 1);

	if (err) {
		message = "writing feature-persistent";
		goto abort_transaction;
	}
#endif

	err = xenbus_printf(xbt, dev->nodename, "request-rx-copy", "%u", 1);

	if (err) {
		message = "writing request-rx-copy";
		goto abort_transaction;
	}

#if defined(CONFIG_NETFRONT_GSO) && defined(HAVE_LWIP)
	err = xenbus_printf(xbt, dev->nodename, "feature-sg", "%u", 1);

	if (err) {
		message = "writing feature-sg";
		goto abort_transaction;
	}

	err = xenbus_printf(xbt, dev->nodename, "feature-gso-tcpv4", "%u", 1);

	if (err) {
		message = "writing feature-gso-tcpv4";
		goto abort_transaction;
	}

	err = xenbus_printf(xbt, dev->nodename, "feature-gso-tcpv6", "%u", 1);

	if (err) {
		message = "writing feature-gso-tcpv6";
		goto abort_transaction;
	}
#endif

	snprintf(path, sizeof(path), "%s/state", dev->nodename);
	err = xenbus_switch_state(xbt, path, XenbusStateConnected);
	if (err) {
		message = "switching state";
		goto abort_transaction;
	}

	err = xenbus_transaction_end(xbt, 0, &retry);
	free(err);
	if (retry) {
		goto again;
		printk("completing transaction\n");
	}

	goto done;

abort_transaction:
	free(err);
	err = xenbus_transaction_end(xbt, 1, &retry);
	printk("Abort transaction %s\n", message);
	goto error;

done:

	snprintf(path, sizeof(path), "%s/mac", dev->nodename);
	msg = xenbus_read(XBT_NIL, path, &dev->mac);

	if (dev->mac == NULL) {
		printk("%s: backend/mac failed\n", __func__);
		goto error;
	}

	printk("backend at %s\n",dev->backend);
	printk("mac is %s\n",dev->mac);

	{
		XenbusState state;
		char path[strlen(dev->backend) + strlen("/state") + 1];
		snprintf(path, sizeof(path), "%s/state", dev->backend);

		xenbus_watch_path_token(XBT_NIL, path, path, &dev->events);

		err = NULL;
		state = xenbus_read_integer(path);
		while (err == NULL && state < XenbusStateConnected)
			err = xenbus_wait_for_state_change(path, &state, &dev->events);
		if (state != XenbusStateConnected) {
			printk("backend not avalable, state=%d\n", state);
			xenbus_unwatch_path_token(XBT_NIL, path, path);
			goto error;
		}

		if (ip) {
			snprintf(path, sizeof(path), "%s/ip", dev->backend);
			xenbus_read(XBT_NIL, path, ip);
		}
	}

	printk("**************************\n");

	unmask_evtchn(dev->tx_evtchn);
	if (feature_split_evtchn)
		unmask_evtchn(dev->rx_evtchn);

#ifdef CONFIG_NETMAP
skip:
	if (dev->netmap)
		connect_netfront(dev);
#endif

	/* Special conversion specifier 'hh' needed for __ia64__. Without
	   this mini-os panics with 'Unaligned reference'. */
	if (rawmac)
		sscanf(dev->mac,"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
				&rawmac[0],
				&rawmac[1],
				&rawmac[2],
				&rawmac[3],
				&rawmac[4],
				&rawmac[5]);

#ifdef CONFIG_SELECT_POLL
	dev->fd = alloc_fd(FTYPE_TAP);
	files[dev->fd].read = 0;
#endif
	return dev;
error:
	free(msg);
	free(err);
	free_netfront(dev);
	return NULL;
}

void shutdown_netfront(struct netfront_dev *dev)
{
	struct netfront_dev_list *list = NULL;
	struct netfront_dev_list *to_del = NULL;

	/* Check this is a valid device */
	for (list = dev_list; list != NULL; list = list->next) {
		if (list->dev == dev)
			break;
	}

	if (!list) {
		printk("Trying to shutdown an invalid netfront device (%p)\n", dev);
		return;
	}

	list->refcount--;
	if (list->refcount == 0) {
		_shutdown_netfront(dev);
		free(dev->nodename);
		free(dev);

		to_del = list;
		if (to_del == dev_list) {
			free(to_del);
			dev_list = NULL;
		} else {
			for (list = dev_list; list->next != to_del; list = list->next);
			list->next = to_del->next;
			free(to_del);
		}
	}
}

static void _shutdown_netfront(struct netfront_dev *dev)
{
	char* err = NULL, *err2;
	XenbusState state;
	char path[strlen(dev->backend) + strlen("/state") + 1];
	char nodename[strlen(dev->nodename) + strlen("/request-rx-copy") + 1];

	printk("close network: backend at %s\n",dev->backend);

	snprintf(path, sizeof(path), "%s/state", dev->backend);
	snprintf(nodename, sizeof(nodename), "%s/state", dev->nodename);
#ifdef CONFIG_NETMAP
	if (dev->netmap)
		shutdown_netfront_netmap(dev);
#endif

	if ((err = xenbus_switch_state(XBT_NIL, nodename, XenbusStateClosing)) != NULL) {
		printk("shutdown_netfront: error changing state to %d: %s\n",
				XenbusStateClosing, err);
		goto close;
	}
	state = xenbus_read_integer(path);
	while (err == NULL && state < XenbusStateClosing)
		err = xenbus_wait_for_state_change(path, &state, &dev->events);
	free(err);

	if ((err = xenbus_switch_state(XBT_NIL, nodename, XenbusStateClosed)) != NULL) {
		printk("shutdown_netfront: error changing state to %d: %s\n",
				XenbusStateClosed, err);
		goto close;
	}
	state = xenbus_read_integer(path);
	while (state < XenbusStateClosed) {
		err = xenbus_wait_for_state_change(path, &state, &dev->events);
		free(err);
	}

	if ((err = xenbus_switch_state(XBT_NIL, nodename, XenbusStateInitialising)) != NULL) {
		printk("shutdown_netfront: error changing state to %d: %s\n",
				XenbusStateInitialising, err);
		goto close;
	}
	state = xenbus_read_integer(path);
	while (err == NULL && (state < XenbusStateInitWait || state >= XenbusStateClosed))
		err = xenbus_wait_for_state_change(path, &state, &dev->events);

close:
	free(err);
	err2 = xenbus_unwatch_path_token(XBT_NIL, path, path);
	free(err2);

	snprintf(nodename, sizeof(nodename), "%s/tx-ring-ref", dev->nodename);
	err2 = xenbus_rm(XBT_NIL, nodename);
	free(err2);
	snprintf(nodename, sizeof(nodename), "%s/rx-ring-ref", dev->nodename);
	err2 = xenbus_rm(XBT_NIL, nodename);
	free(err2);
	snprintf(nodename, sizeof(nodename), "%s/event-channel", dev->nodename);
	err2 = xenbus_rm(XBT_NIL, nodename);
	free(err2);
	snprintf(nodename, sizeof(nodename), "%s/request-rx-copy", dev->nodename);
	err2 = xenbus_rm(XBT_NIL, nodename);
	free(err2);

	if (!err)
		free_netfront(dev);
}

void suspend_netfront(void)
{
	struct netfront_dev_list *list;

	for (list = dev_list; list != NULL; list = list->next)
		_shutdown_netfront(list->dev);
}

void resume_netfront(void)
{
	struct netfront_dev_list *list;

	for (list = dev_list; list != NULL; list = list->next)
		_init_netfront(list->dev, NULL, NULL);
}

void init_rx_buffers(struct netfront_dev *dev)
{
	int i, requeue_idx;
	netif_rx_request_t *req;
	int notify;

	/* Rebuild the RX buffer freelist and the RX ring itself. */
	for (requeue_idx = 0, i = 0; i < NET_RX_RING_SIZE; i++) {
		struct net_buffer* buf = &dev->rx_buffers[requeue_idx];
		req = RING_GET_REQUEST(&dev->rx, requeue_idx);

		buf->gref = req->gref =
			gnttab_grant_access(dev->dom,virt_to_mfn(buf->page),0);

		req->id = requeue_idx;

		requeue_idx++;
	}

	dev->rx.req_prod_pvt = requeue_idx;

	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&dev->rx, notify);

	if (notify)
		notify_remote_via_evtchn(dev->rx_evtchn);

	dev->rx.sring->rsp_event = dev->rx.rsp_cons + 1;
}

#ifdef CONFIG_SELECT_POLL
int netfront_get_fd(struct netfront_dev *dev)
{
    return dev->fd;
}
#endif
