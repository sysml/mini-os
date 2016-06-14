/* Minimal network driver for Mini-OS.
 * Copyright (c) 2006-2007 Jacob Gorm Hansen, University of Copenhagen.
 * Copyright (c) 2014-2015 Joao Martins, NEC Europe Ltd.
 * Copyright (c) 2015-2016 Simon Kuenzer, NEC Europe Ltd.
 * Copyright (c) 2016      Kenichi Yasukata, NEC Europe Ltd.
 * Based on netfront.c from Xen Linux.
 */
#include <mini-os/os.h>
#include <mini-os/mm.h>
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
DECLARE_WAIT_QUEUE_HEAD(netfront_txqueue);

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

#ifndef CONFIG_NETFRONT_PERSISTENT_GRANTS
#if !defined CONFIG_NETFRONT_RX_BUFFERS || CONFIG_NETFRONT_RX_BUFFERS < 20
#define NET_RX_BUFFERS NET_RX_RING_SIZE
#else
#define NET_RX_BUFFERS CONFIG_NETFRONT_RX_BUFFERS
#endif
#endif

#define GRANT_INVALID_REF 0

struct netfront_dev;

struct net_txbuffer {
#if defined CONFIG_NETFRONT_PERSISTENT_GRANTS || !defined CONFIG_NETFRONT_LWIP_ONLY
	void* page;
#endif
	grant_ref_t gref;
#ifdef HAVE_LWIP
	struct pbuf *pbuf;
#endif
};

struct net_rxbuffer {
	void* page;
	grant_ref_t gref;
#ifndef CONFIG_NETFRONT_PERSISTENT_GRANTS
	unsigned short id;
#ifdef HAVE_LWIP
	struct netfront_dev *dev;
	struct pbuf_custom cpbuf;
#endif
#endif
};

#if !defined CONFIG_NETFRONT_PERSISTENT_GRANTS && defined HAVE_LWIP
#ifndef container_of
/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:        the pointer to the member.
 * @type:       the type of the container struct this is embedded in.
 * @member:     the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#define _upcast_pbuf2rxbuf(p) \
  (container_of(container_of(p, struct pbuf_custom, pbuf), struct net_rxbuffer, cpbuf))
#endif /* !CONFIG_NETFRONT_PERSISTENT_GRANTS && HAVE_LWIP */

struct netfront_dev {
	domid_t dom;

	unsigned short tx_freelist[NET_TX_RING_SIZE + 1];
	struct semaphore tx_sem;

	struct net_txbuffer tx_buffers[NET_TX_RING_SIZE];
#ifdef CONFIG_NETFRONT_PERSISTENT_GRANTS
	struct net_rxbuffer rx_buffers[NET_RX_RING_SIZE];
#else
	struct net_rxbuffer *rx_buffers[NET_RX_RING_SIZE];

	struct net_rxbuffer rx_buffer_pool[NET_RX_BUFFERS];
	unsigned short rx_freelist[NET_RX_BUFFERS + 1];
	unsigned short rx_avail;
#endif

	struct netif_tx_front_ring tx;
	struct netif_rx_front_ring rx;

	/* inflight response to be handled */
	struct netif_rx_response rsp;
	/* extras (if any) of the inflight buffer */
	struct netif_extra_info extras[XEN_NETIF_EXTRA_TYPE_MAX - 1];
	/* used by pbuf_copy_bits */
	struct pbuf *pbuf_cur;
#ifdef CONFIG_NETFRONT_PERSISTENT_GRANTS
	uint32_t pbuf_off;
#endif

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
static void netfront_fillup_rx_buffers(struct netfront_dev *dev);
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

#ifdef CONFIG_NETFRONT_PERSISTENT_GRANTS
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

	*p = q;
	*offset = q_ofs;
}

/* Allocates a pbuf and initializes dev->pbuf_cur, dev->pbuf_off */
static inline struct pbuf *netfront_alloc_pbuf(struct netfront_dev *dev, int32_t len)
{
  struct pbuf *p;

  if (unlikely((len) > (0xFFFF - ETH_PAD_SIZE) || len <= 0))
    return NULL; /* unsupported length: ignore */

  p = pbuf_alloc(PBUF_RAW, (u16_t) (len + ETH_PAD_SIZE), PBUF_POOL);
  dev->pbuf_cur = p;
  dev->pbuf_off = 0;

  return p;
}
#else /* CONFIG_NETFRONT_PERSISTENT_GRANTS */
static void netfront_release_rxbuffer(struct net_rxbuffer *buf, struct netfront_dev *dev);

static void netfront_free_rxpbuf(struct pbuf *p)
{
	struct net_rxbuffer *buf = _upcast_pbuf2rxbuf(p);
	struct netfront_dev *dev;

	dev = buf->dev;
	netfront_release_rxbuffer(buf, dev);
}

static inline struct pbuf *netfront_init_rxpbuf(struct net_rxbuffer *buf, struct netfront_dev *dev)
{
	struct pbuf *p;

	p = pbuf_alloced_custom(PBUF_RAW, PAGE_SIZE, PBUF_REF, &buf->cpbuf, buf->page, PAGE_SIZE);
	if (p == NULL)
		return NULL;

	buf->dev = dev;
	buf->cpbuf.custom_free_function = netfront_free_rxpbuf;
	return p;
}
#endif /* CONFIG_NETFRONT_PERSISTENT_GRANTS */
#endif /* HAVE_LWIP */

#ifndef CONFIG_NETFRONT_PERSISTENT_GRANTS
static struct net_rxbuffer *netfront_get_rxbuffer(struct netfront_dev *dev)
{
	struct net_rxbuffer *buf;
	unsigned short id;

	if (unlikely(dev->rx_avail == 0))
		return NULL; /* out of rx buffers */

	id = get_id_from_freelist(dev->rx_freelist);
	buf = &dev->rx_buffer_pool[id];
	buf->id = id;
#ifdef HAVE_LWIP
	if (unlikely(netfront_init_rxpbuf(buf, dev) == NULL)) {
		/* could not allocate custom pbuf */
		add_id_to_freelist(id, dev->rx_freelist);
		return NULL;
	}
#endif /* HAVE_LWIP */
	dev->rx_avail--;
	return buf;
}

static void netfront_release_rxbuffer(struct net_rxbuffer *buf, struct netfront_dev *dev)
{
	add_id_to_freelist(buf->id, dev->rx_freelist);
	dev->rx_avail++;
}
#endif

/*
 * Main entry point for handling a packet. If HAVE_LWIP is set
 * we allow passing up pbufs upon registering the appropriate
 * callback.
 */
static inline int handle_buffer(struct netfront_dev *dev,
				struct netif_rx_response *rx,
				struct net_rxbuffer *buf, int32_t realsize)
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
#ifdef HAVE_LWIP
	if (likely(dev->netif_rx_pbuf)) {
#ifdef CONFIG_NETFRONT_PERSISTENT_GRANTS
		pbuf_copy_bits(&dev->pbuf_cur, &dev->pbuf_off, (void *)((uintptr_t)buf->page+rx->offset), rx->status);
#else
		dev->pbuf_cur->tot_len = dev->pbuf_cur->len = rx->status;
		dev->pbuf_cur->payload = (void *)((uintptr_t)buf->page+rx->offset);
#endif /* CONFIG_NETFRONT_PERSISTENT_GRANTS */
		return 1;
	}
#endif
#ifndef CONFIG_NETFRONT_LWIP_ONLY
	if (dev->netif_rx)
		dev->netif_rx(page+rx->offset, rx->status, dev->netif_rx_arg);
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
#ifndef CONFIG_NETFRONT_PERSISTENT_GRANTS
	struct net_rxbuffer *buf;
#endif

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

#ifndef CONFIG_NETFRONT_PERSISTENT_GRANTS
		buf = dev->rx_buffers[netfront_rxidx(cons)];
		gnttab_end_access(buf->gref);
		buf->gref = GRANT_INVALID_REF;
		dev->rx_buffers[netfront_rxidx(cons)] = NULL;
		netfront_release_rxbuffer(buf, dev);
#endif
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
	int drop = 0;
#ifdef HAVE_LWIP
	struct pbuf *p;
	struct pbuf *first_p;
#endif

	dprintk("rx: ring: len %d %s\n", size,
		(flags & NETRXF_more_data ? "(more true) ": ""));

	BUG_ON(id >= NET_RX_RING_SIZE);

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

	dprintk("rx: %c%c- %"PRIi32" bytes\n",
		flags & NETRXF_extra_info ? 'S' : '-',
		flags & ((NETRXF_csum_blank) | (NETRXF_data_validated)) ? 'C' : '-',
		realsize);

#ifdef HAVE_LWIP
	if (likely(dev->netif_rx_pbuf)) {
#ifdef CONFIG_NETFRONT_PERSISTENT_GRANTS
	  first_p = p = netfront_alloc_pbuf(dev, realsize);
	  drop = (p == NULL);
#else
	  first_p = p = &dev->rx_buffers[id]->cpbuf.pbuf;
	  drop = 0;
	  dev->pbuf_cur = p;
#endif /* CONFIG_NETFRONT_PERSISTENT_GRANTS */

#if ETH_PAD_SIZE
	  if (likely(!drop))
	    pbuf_header(p, -ETH_PAD_SIZE); /* drop the padding word */
#endif /* ETH_PAD_SIZE */
	}
#endif /* HAVE_LWIP */

	for (;;) {
		if (unlikely(rsp->status < 0 ||
			     (rsp->offset + rsp->status > PAGE_SIZE))) {
			printk("rx: ring<%u>: status %d, flags %04x, offset %d\n",
			       cons + slots, size, flags, rsp->offset);
		} else if (likely(!drop)) {
#ifdef CONFIG_NETFRONT_PERSISTENT_GRANTS
			handle_buffer(dev, rsp, &dev->rx_buffers[id], realsize);
#else
			handle_buffer(dev, rsp, dev->rx_buffers[id], realsize);
#endif
		}

#ifndef CONFIG_NETFRONT_PERSISTENT_GRANTS
		BUG_ON(dev->rx_buffers[id]->gref == GRANT_INVALID_REF);
		gnttab_end_access(dev->rx_buffers[id]->gref);
		dev->rx_buffers[id]->gref = GRANT_INVALID_REF;
		dev->rx_buffers[id] = NULL;
#endif

		if (!(flags & NETRXF_more_data))
			break;

		if (dev->rx.sring->rsp_prod <= cons + slots)
			break;

		rsp = RING_GET_RESPONSE(&dev->rx, cons + slots);
		id = rsp->id;
		BUG_ON(id >= NET_RX_RING_SIZE);
		size = rsp->status;
		flags = rsp->flags;
		slots++;
#ifndef CONFIG_NETFRONT_PERSISTENT_GRANTS
		if (likely(dev->netif_rx_pbuf && (!drop))) {
			/* set tot_len */
			p->tot_len = realsize;
			realsize -= p->len;
			/* ..and link it to next pbuf */
			p->next = &dev->rx_buffers[id]->cpbuf.pbuf;
			dev->pbuf_cur = p = p->next;
		} else {
			netfront_release_rxbuffer(dev->rx_buffers[id], dev);
		}
#endif

		dprintk("rx: ring: len %d %s %s\n", size,
			(flags & NETRXF_more_data ? "(more true) ": ""),
			(drop ? "DROP" : ""));
	}

	BUG_ON(slots > dev->rx.sring->rsp_prod - dev->rx.rsp_cons);
	dev->rx.rsp_cons = cons + slots;

	if (unlikely(drop))
		goto err_drop;

#ifdef HAVE_LWIP
	if (likely(dev->netif_rx_pbuf)) {
#if ETH_PAD_SIZE
		pbuf_header(p, ETH_PAD_SIZE); /* reclaim the padding word */
#endif /* ETH_PAD_SIZE */
		if (first_p->ref != 1)
		  printk("first_p->ref = %u\n", first_p->ref);
		dev->netif_rx_pbuf(first_p, dev->netif_rx_arg);
	}
#endif /* HAVE_LWIP */
	return 1;

 err_drop:
	dprintk("  rx: dropped\n");
#ifdef HAVE_LWIP
	if (first_p) {
#ifdef CONFIG_NETFRONT_PERSISTENT_GRANTS
		pbuf_free(first_p);
#else /* CONFIG_NETFRONT_PERSISTENT_GRANTS */
		struct pbuf *next;

		/* unchain pbuf and release */
		p = first_p;
		while (p != NULL) {
			next = p->next;
			p->tot_len = p->len;
			p->next = NULL;
			netfront_free_rxpbuf(p);
			p = next;
		}
#endif /* CONFIG_NETFRONT_PERSISTENT_GRANTS */
	}
	if (likely(dev->netif_rx_pbuf))
		dev->netif_rx_pbuf(NULL, dev->netif_rx_arg); /* notify drop */
#endif
	return 0;
}

static void netfront_fillup_rx_buffers(struct netfront_dev *dev)
{
	RING_IDX prod;
	struct netif_rx_request *req;
	grant_ref_t ref;
	unsigned short id;
	int notify;
#ifndef CONFIG_NETFRONT_PERSISTENT_GRANTS
	struct net_rxbuffer* buf;
	int flags;
#endif

#ifndef CONFIG_NETFRONT_PERSISTENT_GRANTS
	local_irq_save(flags);
#endif
	/* fill-up slots again */
	for (prod = dev->rx.req_prod_pvt;
	     prod - dev->rx.rsp_cons < NET_RX_RING_SIZE;
	     prod++) {
		id = netfront_rxidx(prod);
#ifndef CONFIG_NETFRONT_PERSISTENT_GRANTS
		buf = netfront_get_rxbuffer(dev);
		if (buf == NULL)
			break; /* out of rx buffers */
		BUG_ON(buf->page == NULL);
		ref = gnttab_grant_access(dev->dom,virt_to_mfn(buf->page),0);
		buf->gref = ref;
		BUG_ON(ref == GRANT_INVALID_REF);
		dev->rx_buffers[id] = buf;
#else
		ref = dev->rx_buffers[id].gref;
#endif
		req = RING_GET_REQUEST(&dev->rx, prod);
		req->id = id;
		req->gref = ref;
	}
#ifndef CONFIG_NETFRONT_PERSISTENT_GRANTS
	local_irq_restore(flags);
#endif

	if (dev->rx.req_prod_pvt != prod) {
		dev->rx.req_prod_pvt = prod;
		wmb();
		RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&dev->rx, notify);
#ifdef CONFIG_SELECT_POLL
		files[dev->fd].read = 0;
#endif
		if (notify)
			notify_remote_via_evtchn(dev->rx_evtchn);
	}
}

void netfront_rx(struct netfront_dev *dev)
{
	RING_IDX rp, cons;
	struct netif_rx_response *rsp = &(dev->rsp);
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
		cons = dev->rx.rsp_cons;
	}

	dev->rx.rsp_cons = cons;
	RING_FINAL_CHECK_FOR_RESPONSES(&dev->rx, more);
	if(more)
		goto moretodo;

	netfront_fillup_rx_buffers(dev);
}

void netfront_rx_handler(evtchn_port_t port, struct pt_regs *regs, void *data)
{
	struct netfront_dev *dev = data;
	int fd __maybe_unused = dev->fd;

#ifdef CONFIG_SELECT_POLL
	if (fd != -1)
		files[fd].read = 1;

	wake_up(&netfront_queue);
#endif
}

void netfront_tx_handler(evtchn_port_t port, struct pt_regs *regs, void *data)
{
#if !(defined HAVE_LWIP) || (defined CONFIG_NETFRONT_PERSISTENT_GRANTS)
	int flags;
	struct netfront_dev *dev = data;

	local_irq_save(flags);
	netfront_tx_buf_gc(dev);
	local_irq_restore(flags);
#endif

#ifdef CONFIG_NETFRONT_WAITFORTX
	wake_up(&netfront_txqueue);
#endif
}

void netfront_handler(evtchn_port_t port, struct pt_regs *regs, void *data)
{
	netfront_tx_handler(port, regs, data);
	netfront_rx_handler(port, regs, data);
}

#ifdef HAVE_LIBC
void netfront_select_handler(evtchn_port_t port, struct pt_regs *regs, void *data)
{
	struct netfront_dev *dev = data;
	int fd = dev->fd;
#if !(defined HAVE_LWIP) || (defined CONFIG_NETFRONT_PERSISTENT_GRANTS)
	int flags;

	local_irq_save(flags);
	netfront_tx_buf_gc(dev);
	local_irq_restore(flags);
#endif

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

#ifndef CONFIG_NETFRONT_LWIP_ONLY
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
#endif

#ifdef CONFIG_NETFRONT_LWIP_ONLY
static
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
#ifndef CONFIG_NETFRONT_PERSISTENT_GRANTS
	struct net_txbuffer *buf;
#endif

	do {
		prod = dev->tx.sring->rsp_prod;
		rmb(); /* Ensure we see responses up to 'rp'. */

		for (cons = dev->tx.rsp_cons; cons != prod; cons++) {
			struct netif_tx_response *txrsp;

			txrsp = RING_GET_RESPONSE(&dev->tx, cons);
			if (txrsp->status == NETIF_RSP_NULL)
				continue;

			if (txrsp->status == NETIF_RSP_DROPPED)
				printk("netif drop for tx\n");

			if (txrsp->status == NETIF_RSP_ERROR)
				printk("netif error for tx\n");

			id  = txrsp->id;
			BUG_ON(id >= NET_TX_RING_SIZE);

#ifndef CONFIG_NETFRONT_PERSISTENT_GRANTS
			buf = &dev->tx_buffers[id];
			gnttab_end_access(buf->gref);
			buf->gref = GRANT_INVALID_REF;
			free_page(buf->page);
#ifdef HAVE_LWIP
			if (buf->pbuf) {
				pbuf_free(buf->pbuf);
				buf->pbuf = NULL;
			}
#endif /* HAVE_LWIP */
#endif /* CONFIG_NETFRONT_PERSISTENT_GRANTS */
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
	struct net_txbuffer* buf;
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
	tx->offset = 0;
	tx->size = 0;
	tx->id = id;
	tx->flags = 0;
#ifdef CONFIG_NETFRONT_PERSISTENT_GRANTS
	tx->gref = buf->gref;
#else
	tx->gref = buf->gref = GRANT_INVALID_REF;
#endif
#ifdef HAVE_LWIP
	buf->pbuf = NULL;
#endif
	return tx;
}

#define netfront_tx_available(dev, slots) \
  (((dev)->tx.req_prod_pvt - (dev)->tx.rsp_cons) < (NET_TX_RING_SIZE - (slots)))
#define netfront_tx_possible(dev, slots) \
  (0 < (NET_TX_RING_SIZE - (slots)))

static inline void netfront_xmit_notify(struct netfront_dev *dev)
{
	int notify;

	/* So that backend sees new requests and check notify */
	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&dev->tx, notify);
	if (notify)
		notify_remote_via_evtchn(dev->tx_evtchn);
}

#ifndef CONFIG_NETFRONT_LWIP_ONLY
/**
 * Transmit function for raw buffers (non-GSO/TCO)
 */
void netfront_xmit(struct netfront_dev *dev, unsigned char *data, int len)
{
	int flags;
	struct netif_tx_request *tx;
	struct net_txbuffer* buf;
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
	buf = &dev->tx_buffers[tx->id];
	page = buf->page;
#ifndef CONFIG_NETFRONT_PERSISTENT_GRANTS
	tx->gref = buf->gref = gnttab_grant_access(dev->dom,
						   virt_to_mfn(page), 0);
	BUG_ON(tx->gref == GRANT_INVALID_REF);
#endif
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
#endif

#ifdef HAVE_LWIP
#ifdef CONFIG_NETFRONT_PERSISTENT_GRANTS
#define netfront_count_pbuf_slots(dev, p) \
  DIV_ROUND_UP(((int)(p)->tot_len), PAGE_SIZE);

static inline struct netif_tx_request *netfront_make_txreqs_pgnt(struct netfront_dev *dev,
								 struct netif_tx_request *tx,
								 const struct pbuf *p, int *slots)
{
	struct netif_tx_request *first_tx = tx;
	const struct pbuf *first_p = p;
	register unsigned long page_off, page_left;
	register unsigned long p_off, p_left;
	register unsigned long len;
	register unsigned long tot_len;
	void *page;

	tot_len   = 0;
	p_off     = 0;
	p_left    = p->len;
	page      = dev->tx_buffers[tx->id].page;
	page_off  = tx->offset = 0;
	page_left = (PAGE_SIZE) - page_off;
	tx->size  = 0;

	for (;;) {
		len = min(page_left, p_left);

		dprintk("tx: make_txreqs_pgnt: slot %3u, id %3u: page@%12p, page_off: %4lu page_left: %4lu <-%4lu bytes-- p@%12p, p_off: %4lu, p_left: %4lu\n",
			*slots, tx->id, page, page_off, page_left, len, p->payload, p_off, p_left);
		NETIF_MEMCPY((void *)(((uintptr_t) page) + page_off),
			     (void *)(((uintptr_t) p->payload) + p_off),
			     len);
		p_off     += len;
		p_left    -= len;
		tx->size  += len;
		page_off  += len;
		page_left -= len;
		tot_len   += len;

		if (p_left == 0) {
			if (!p->next)
				break; /* we are done processing this pbuf chain */
			p = p->next;
			p_off  = 0;
			p_left = p->len;
		}
		if (page_left == 0) {
			tx->flags |= NETTXF_more_data;
			tx = netfront_get_page(dev); /* next page */
			BUG_ON(tx == NULL); /* out of memory -> this should have been catched
					       before calling this function */
			page      = dev->tx_buffers[tx->id].page;
			page_off  = tx->offset = 0;
			page_left = PAGE_SIZE;
			tx->size  = 0;
			(*slots)++;
		}
	}

	/*
	 * The first fragment has the entire packet
	 * size, subsequent fragments have just the
	 * fragment size. The backend works out the
	 * true size of the first fragment by
	 * subtracting the sizes of the other
	 * fragments.
	 */
	first_tx->size = tot_len;
	BUG_ON(first_p->tot_len != tot_len); /* broken pbuf?! */
	return tx;
}
#else /* CONFIG_NETFRONT_PERSISTENT_GRANTS */
#define _count_pages(len)						\
  ((len == 0) ? 0 : (1 + (len / PAGE_SIZE)))

static inline unsigned long netfront_count_pbuf_slots(struct netfront_dev *dev, const struct pbuf *p)
{
	const struct pbuf *q;
	unsigned long slots = 0;

	for (q = p; q != NULL; q = q->next)
	  slots += (unsigned long) _count_pages(q->len);
	return slots;
}

static inline struct netif_tx_request *netfront_make_txreqs(struct netfront_dev *dev,
							    struct netif_tx_request *tx,
							    struct pbuf *p, int *slots)
{
	struct netif_tx_request *first_tx = tx;
	struct net_txbuffer *buf;
	struct pbuf *first_p = p;
	struct pbuf *q;
	unsigned long tot_len;
	unsigned long s;
	void *page;
	int q_slots;
	size_t plen, left;

	tot_len = 0;
	buf = &dev->tx_buffers[tx->id];

	/* map pages of pbuf */
	for (q = p; q != NULL; q = q->next) {
		left = q->len;
		q_slots = (int) _count_pages(q->len);
		/* grant pages of pbuf */
		for (s = 0; s < q_slots; ++s) {
			/* read only mapping */
			page = (void *) alloc_page();
			buf->page = page;
			plen = min(PAGE_SIZE, left);
			memcpy(page, q->payload + s * PAGE_SIZE, plen);
			tx->gref = buf->gref = gnttab_grant_access(dev->dom, virtual_to_mfn(page), 0);
			BUG_ON(tx->gref == GRANT_INVALID_REF);

			tx->offset = 0;
			tx->size   = plen;

			tot_len += tx->size;
			left -= plen;

			if ((s + 1) < q_slots || q->next != NULL) {
				/* there will be a follow-up slot */
				tx->flags |= NETTXF_more_data;
				tx = netfront_get_page(dev); /* next slot */
				BUG_ON(tx == NULL); /* out of memory -> this should have been catched
						       before calling this function */
				(*slots)++;
				buf = &dev->tx_buffers[tx->id];
			}
		}
	}

	/*
	 * The first fragment has the entire packet
	 * size, subsequent fragments have just the
	 * fragment size. The backend works out the
	 * true size of the first fragment by
	 * subtracting the sizes of the other
	 * fragments.
	 */
	BUG_ON(first_p->tot_len != tot_len); /* broken pbuf?! */
	first_tx->size = tot_len;
	pbuf_ref(first_p); /* increase ref count */
	buf->pbuf = first_p; /* remember chain for later release on last buf */
	return tx;
}
#endif /* CONFIG_NETFRONT_PERSISTENT_GRANTS */

/**
 * Transmit function for pbufs which can handle checksum and segmentation offloading for TCPv4 and TCPv6
 */
err_t netfront_xmit_pbuf(struct netfront_dev *dev, struct pbuf *p, int co_type, int push)
{
	struct netif_tx_request *first_tx;
	struct netif_extra_info *gso;
	int slots;
	int used = 0;
#ifdef CONFIG_NETFRONT_GSO
	int sego;
#endif /* CONFIG_NETFRONT_GSO */
#ifdef CONFIG_NETFRONT_WAITFORTX
	unsigned long flags;
	DEFINE_WAIT(w);
#endif /* CONFIG_NETFRONT_WAITFORTX */

	/* Counts how many slots we require for this buf */
	slots = netfront_count_pbuf_slots(dev, p);
#ifdef CONFIG_NETFRONT_GSO
	sego = (p->flags & PBUF_FLAG_GSO) ? 1 : 0;
	/* GSO requires checksum offloading set */
	BUG_ON(sego && !(co_type & (XEN_NETIF_GSO_TYPE_TCPV4 | XEN_NETIF_GSO_TYPE_TCPV6)));
#endif /* CONFIG_NETFRONT_GSO */

	/* Checks if there are enough requests for this many slots (gso requires one slot more) */
#ifdef CONFIG_NETFRONT_GSO
	BUG_ON(!netfront_tx_possible(dev, slots + sego));
#else
	BUG_ON(!netfront_tx_possible(dev, slots));
#endif /* CONFIG_NETFRONT_GSO */

#ifdef CONFIG_NETFRONT_WAITFORTX
	local_irq_save(flags);
#endif /* CONFIG_NETFRONT_WAITFORTX */
#ifdef CONFIG_NETFRONT_GSO
	if (unlikely(!netfront_tx_available(dev, slots + sego))) {
#else
	if (unlikely(!netfront_tx_available(dev, slots))) {
#endif /* CONFIG_NETFRONT_GSO */
		netfront_xmit_push(dev);
#ifdef CONFIG_NETFRONT_WAITFORTX
 try_again:
#ifdef CONFIG_NETFRONT_GSO
		if (!netfront_tx_available(dev, slots + sego)) {
#else
		if (!netfront_tx_available(dev, slots)) {
#endif /* CONFIG_NETFRONT_GSO */
			add_waiter(w, netfront_txqueue); /* release thread until space is free'd */
			local_irq_restore(flags);
			schedule();
			local_irq_save(flags);
			goto try_again;
		}
		remove_waiter(w, netfront_txqueue); /* release thread until space is free'd */
#else
		return ERR_MEM;
#endif /* CONFIG_NETFRONT_WAITFORTX */
	}
#ifdef CONFIG_NETFRONT_WAITFORTX
	local_irq_restore(flags);
#endif /* CONFIG_NETFRONT_WAITFORTX */

	/* Set extras if packet is GSO kind */
	first_tx = netfront_get_page(dev);
	ASSERT(first_tx != NULL);
#ifdef CONFIG_NETFRONT_GSO
	if (sego) {
		gso = (struct netif_extra_info *) RING_GET_REQUEST(&dev->tx, dev->tx.req_prod_pvt++);

		first_tx->flags |= NETTXF_extra_info;
		gso->u.gso.size = p->gso_size; /* segmentation size */
		gso->u.gso.type = co_type; /* XEN_NETIF_GSO_TYPE_TCPV4, XEN_NETIF_GSO_TYPE_TCPV6 */
		gso->u.gso.pad = 0;
		gso->u.gso.features = 0;

		gso->type = XEN_NETIF_EXTRA_TYPE_GSO;
		gso->flags = 0;

		used++;
	}
#endif /* CONFIG_NETFRONT_GSO */

	/* Make TX requests for the pbuf */
#ifdef CONFIG_NETFRONT_PERSISTENT_GRANTS
	netfront_make_txreqs_pgnt(dev, first_tx, p, &used);
#else
	netfront_make_txreqs(dev, first_tx, p, &used);
#endif
	ASSERT(slots >= used); /* we should have taken at most the number slots that we estimated before */
	ASSERT(slots <= XEN_NETIF_NR_SLOTS_MIN); /* we should never take more slots than the backend supports */

	/* partially checksummed (offload enabled), or checksummed */
	first_tx->flags |= co_type ? ((NETTXF_csum_blank) | (NETTXF_data_validated)) : (NETTXF_data_validated);

	push |= (((dev)->tx.req_prod_pvt - (dev)->tx.rsp_cons) <= NET_TX_RING_SIZE / 2);
	if (push)
		netfront_xmit_push(dev);

	dprintk("tx: %c%c%c %u bytes (%u slots)\n", sego ? 'S' : '-', co_type ? 'C' : '-', push ? 'P' : '-', p->tot_len, slots);
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

#ifdef CONFIG_NETFRONT_PERSISTENT_GRANTS
	for(i=0; i<NET_RX_RING_SIZE; i++) {
		if (dev->rx_buffers[i].page) {
			gnttab_end_access(dev->rx_buffers[i].gref);
			free_page(dev->rx_buffers[i].page);
		}
	}
#else
	for(i=0; i<NET_RX_BUFFERS; i++) {
		if (dev->rx_buffer_pool[i].page) {
			if (dev->rx_buffer_pool[i].gref != GRANT_INVALID_REF)
				gnttab_end_access(dev->rx_buffer_pool[i].gref);
			free_page(dev->rx_buffer_pool[i].page);
		}
	}
#endif

#if defined CONFIG_NETFRONT_PERSISTENT_GRANTS || !defined CONFIG_NETFRONT_LWIP_ONLY
	for(i=0; i<NET_TX_RING_SIZE; i++) {
		if (dev->tx_buffers[i].page) {
#ifndef CONFIG_NETFRONT_PERSISTENT_GRANTS
			if (dev->tx_buffers[i].gref != GRANT_INVALID_REF)
#endif
			gnttab_end_access(dev->tx_buffers[i].gref);
			free_page(dev->tx_buffers[i].page);
		}
	}
#endif
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

	init_SEMAPHORE(&dev->tx_sem, NET_TX_RING_SIZE);
	for(i=0;i<NET_TX_RING_SIZE;i++)
	{
		add_id_to_freelist(i,dev->tx_freelist);
#if defined CONFIG_NETFRONT_PERSISTENT_GRANTS || !defined CONFIG_NETFRONT_LWIP_ONLY
		dev->tx_buffers[i].page = (void*)alloc_page();
		BUG_ON(dev->tx_buffers[i].page == NULL);
#ifdef CONFIG_NETFRONT_PERSISTENT_GRANTS
		dev->tx_buffers[i].gref = gnttab_grant_access(dev->dom,
							      virt_to_mfn(dev->tx_buffers[i].page), 0);
		BUG_ON(dev->tx_buffers[i].gref == GRANT_INVALID_REF);
		dprintk("tx[%d]: page = %p, gref=0x%x\n", i, dev->tx_buffers[i].page, dev->tx_buffers[i].gref);
#endif
#endif
	}
#if defined CONFIG_NETFRONT_PERSISTENT_GRANTS || !defined CONFIG_NETFRONT_LWIP_ONLY
	printk("net TX ring size %d, %lu KB\n", NET_TX_RING_SIZE, (unsigned long)(NET_TX_RING_SIZE * PAGE_SIZE)/1024);
#else
	printk("net TX ring size %d\n", NET_TX_RING_SIZE);
#endif

#ifdef CONFIG_NETFRONT_PERSISTENT_GRANTS
	for(i=0;i<NET_RX_RING_SIZE;i++)
	{
	/* TODO: that's a lot of memory */
		dev->rx_buffers[i].page = (void*)alloc_page();
		BUG_ON(dev->rx_buffers[i].page == NULL);
		dprintk("rx[%d]: page = %p\n", i, dev->rx_buffers[i].page);
	}
	printk("net RX ring size %d, %lu KB\n", NET_RX_RING_SIZE, (unsigned long)(NET_RX_RING_SIZE * PAGE_SIZE)/1024);
#else
	for(i=0;i<NET_RX_RING_SIZE;i++)
		dev->rx_buffers[i] = NULL;
	for(i=0;i<NET_RX_BUFFERS;i++)
	{
		/* allocate rx buffer pool */
		dev->rx_buffer_pool[i].page = (void*)alloc_page();
		BUG_ON(dev->rx_buffer_pool[i].page == NULL);
		dprintk("rx[%d]: page = %p\n", i, dev->rx_buffer_pool[i].page);
		add_id_to_freelist(i,dev->rx_freelist);
	}
	dev->rx_avail = NET_RX_BUFFERS;
	printk("net RX ring size %d, %lu KB buffer space\n", NET_RX_RING_SIZE, (unsigned long)(NET_RX_BUFFERS * PAGE_SIZE)/1024);
#endif

	if (feature_split_evtchn) {
		evtchn_alloc_unbound(dev->dom, netfront_tx_handler, dev,
				     &dev->tx_evtchn);
		evtchn_alloc_unbound(dev->dom, netfront_rx_handler, dev,
				     &dev->rx_evtchn);
		printk("split event channels enabled\n");
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

#ifdef CONFIG_NETFRONT_PERSISTENT_GRANTS
	printk("persistent grants enabled\n");
#endif

	txs = (struct netif_tx_sring *) alloc_page();
	rxs = (struct netif_rx_sring *) alloc_page();
	memset(txs,0,PAGE_SIZE);
	memset(rxs,0,PAGE_SIZE);


	SHARED_RING_INIT(txs);
	SHARED_RING_INIT(rxs);
	FRONT_RING_INIT(&dev->tx, txs, PAGE_SIZE);
	FRONT_RING_INIT(&dev->rx, rxs, PAGE_SIZE);

	dev->tx_ring_ref = gnttab_grant_access(dev->dom,virt_to_mfn(txs),0);
	BUG_ON(dev->tx_ring_ref == GRANT_INVALID_REF);
	dev->rx_ring_ref = gnttab_grant_access(dev->dom,virt_to_mfn(rxs),0);
	BUG_ON(dev->rx_ring_ref == GRANT_INVALID_REF);

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
	struct net_rxbuffer* buf;
	int i, requeue_idx;
	netif_rx_request_t *req;
	int notify;

	/* Rebuild the RX buffer freelist and the RX ring itself. */
	for (requeue_idx = 0, i = 0; i < NET_RX_RING_SIZE; i++) {
		req = RING_GET_REQUEST(&dev->rx, requeue_idx);

#ifndef CONFIG_NETFRONT_PERSISTENT_GRANTS
		buf = netfront_get_rxbuffer(dev);
		if (buf == NULL)
			break; /* out of rx buffers */
		dev->rx_buffers[requeue_idx] = buf;
#else
		buf = &dev->rx_buffers[requeue_idx];
#endif
		buf->gref = req->gref =
			gnttab_grant_access(dev->dom,virt_to_mfn(buf->page),0);
		BUG_ON(buf->gref == GRANT_INVALID_REF);

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
