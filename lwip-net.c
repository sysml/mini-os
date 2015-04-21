/*
 * Mini-OS netfront driver for lwIP
 *
 *   file: lwip-net.c
 *
 *          NEC Europe Ltd. PROPRIETARY INFORMATION
 *
 * This software is supplied under the terms of a license agreement
 * or nondisclosure agreement with NEC Europe Ltd. and may not be
 * copied or disclosed except in accordance with the terms of that
 * agreement. The software and its source code contain valuable trade
 * secrets and confidential information which have to be maintained in
 * confidence.
 * Any unauthorized publication, transfer to third parties or duplication
 * of the object or source code - either totally or in part – is
 * prohibited.
 *
 *      Copyright (c) 2015 NEC Europe Ltd. All Rights Reserved.
 *
 * Authors: Simon Kuenzer <simon.kuenzer@neclab.eu>
 *
 * NEC Europe Ltd. DISCLAIMS ALL WARRANTIES, EITHER EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE AND THE WARRANTY AGAINST LATENT
 * DEFECTS, WITH RESPECT TO THE PROGRAM AND THE ACCOMPANYING
 * DOCUMENTATION.
 *
 * No Liability For Consequential Damages IN NO EVENT SHALL NEC Europe
 * Ltd., NEC Corporation OR ANY OF ITS SUBSIDIARIES BE LIABLE FOR ANY
 * DAMAGES WHATSOEVER (INCLUDING, WITHOUT LIMITATION, DAMAGES FOR LOSS
 * OF BUSINESS PROFITS, BUSINESS INTERRUPTION, LOSS OF INFORMATION, OR
 * OTHER PECUNIARY LOSS AND INDIRECT, CONSEQUENTIAL, INCIDENTAL,
 * ECONOMIC OR PUNITIVE DAMAGES) ARISING OUT OF THE USE OF OR INABILITY
 * TO USE THIS PROGRAM, EVEN IF NEC Europe Ltd. HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 *
 *     THIS HEADER MAY NOT BE EXTRACTED OR MODIFIED IN ANY WAY.
 *
 * This file is based on Ethernet Interface skeleton (ethernetif.c)
 * provided by lwIP-1.4.1, copyrights as below.
 */
/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */
/*
 * Parts of this file are based on the previous lwip-net.c implementation:
 *
 * interface between lwIP's ethernet and Mini-os's netfront.
 * For now, support only one network interface, as mini-os does.
 *
 * Tim Deegan <Tim.Deegan@eu.citrix.net>, July 2007
 * based on lwIP's ethernetif.c skeleton file, copyrights as below.
 */

#include <lwip-net.h>
#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include <lwip/stats.h>
#include <lwip/snmp.h>

#define NETFRONTIF_NPREFIX 'e'
#define NETFRONTIF_SPEED 10000000000ul     /* 10 GBit/s */
#define NETFRONTIF_MTU 1500

/**
 * Helper macro
 */
#ifndef min
#define min(a, b)						\
    ({ __typeof__ (a) __a = (a);				\
       __typeof__ (b) __b = (b);				\
       __a < __b ? __a : __b; })
#endif

/**
 * This function does the actual transmission of a packet. The packet is
 * contained in the pbuf that is passed to the function. This pbuf
 * can be chained.
 *
 * @param netif
 *  the lwip network interface structure for this netfrontif
 * @param p
 *  the packet to send (e.g. IP packet including MAC addresses and type)
 * @return
 *  ERR_OK when the packet could be sent; an err_t value otherwise
 */
static inline err_t netfrontif_transmit(struct netif *netif, struct pbuf *p)
{
    struct netfrontif *nfi = netif->state;
    struct pbuf *q;
    unsigned char *cur;

    LWIP_DEBUGF(NETIF_DEBUG, ("netfrontif_transmit: %c%c: "
			      "Transmitting %u bytes\n",
			      netif->name[0], netif->name[1],
			      p->tot_len));

#if ETH_PAD_SIZE
    pbuf_header(p, -ETH_PAD_SIZE); /* drop the padding word */
#endif

    if (!p->next) {
        /* fast case: no further buffer allocation needed */
        netfront_xmit(nfi->dev, (unsigned char *) p->payload, p->len);
    } else {
        unsigned char data[p->tot_len];

        for(q = p, cur = data; q != NULL; cur += q->len, q = q->next)
            MEMCPY(cur, q->payload, q->len);

        netfront_xmit(nfi->dev, data, p->tot_len);
    }

#if ETH_PAD_SIZE
    pbuf_header(p, ETH_PAD_SIZE); /* reclaim the padding word */
#endif

    LINK_STATS_INC(link.xmit);
    return ERR_OK;
}

/**
 * Allocates a pbuf and copies data into it
 *
 * @param data
 *  the pointer to packet data to be copied into the pbuf
 * @param len
 *  the length of data in bytes
 * @return
 *  NULL when a pbuf could not be allocated; the pbuf otherwise
 */
static inline struct pbuf *netfrontif_mkpbuf(unsigned char *data, int len)
{
    struct pbuf *p, *q;
    unsigned char *cur;

    p = pbuf_alloc(PBUF_RAW, len + ETH_PAD_SIZE, PBUF_POOL);
    if (unlikely(!p))
        return NULL;

#if ETH_PAD_SIZE
    pbuf_header(p, -ETH_PAD_SIZE); /* drop the padding word */
#endif

    if (likely(!p->next)) {
        /* fast path */
        MEMCPY(p->payload, data, len);
    } else {
        /* pbuf chain */
        for(q = p, cur = data; q != NULL; cur += q->len, q = q->next)
            MEMCPY(q->payload, cur, q->len);
    }

#if ETH_PAD_SIZE
    pbuf_header(p, ETH_PAD_SIZE); /* reclaim the padding word */
#endif

    return p;
}

/**
 * Passes a pbuf to the lwIP stack for further processing.
 * The packet type is determined and checked before passing.
 * Note: When lwIP is built with threading, this pbuf will
 * be enqueued to lwIP's mailbox until it gets processed
 * by the tcpip thread.
 *
 * @param p
 *  the pointer to received packet data
 * @param netif
 *  the lwip network interface structure for this netfrontif
 */
static inline void netfrontif_input(struct pbuf *p, struct netif *netif)
{
    struct eth_hdr *ethhdr;
    err_t err;

    LWIP_DEBUGF(NETIF_DEBUG, ("netfrontif_input: %c%c: "
			      "Received %u bytes\n",
			      netif->name[0], netif->name[1],
			      p->tot_len));

    ethhdr = p->payload;
    switch (htons(ethhdr->type)) {
    /* IP or ARP packet? */
    case ETHTYPE_IP:
#if IPV6_SUPPORT
    case ETHTYPE_IPV6:
#endif
    case ETHTYPE_ARP:
#if PPPOE_SUPPORT
    case ETHTYPE_PPPOEDISC:
    case ETHTYPE_PPPOE:
#endif
    /* packet will be sent to lwIP stack for processing */
    /* Note: On threaded configuration packet buffer will be enqueued on
     *  a mailbox. The lwIP thread will do the packet processing when it gets
     *  scheduled. */
        err = netif->input(p, netif);
	if (unlikely(err != ERR_OK)) {
#ifndef CONFIG_LWIP_NOTHREADS
	    if (err == ERR_MEM)
	        LWIP_DEBUGF(NETIF_DEBUG, ("netfrontif_input: %c%c: ERROR %d: "
					  "Could not post packet to lwIP thread. Packet dropped\n",
					  netif->name[0], netif->name[1], err));
	    else
#endif /* CONFIG_LWIP_NOTHREADS */
	    LWIP_DEBUGF(NETIF_DEBUG, ("netfrontif_input: %c%c: ERROR %d: "
				      "Packet dropped\n",
				      netif->name[0], netif->name[1], err));
	    pbuf_free(p);
	}
	break;

    default:
        LWIP_DEBUGF(NETIF_DEBUG, ("netfrontif_input: %c%c: ERROR: "
				  "Dropped packet with unknown type 0x%04x\n",
				  netif->name[0], netif->name[1],
				  htons(ethhdr->type)));
	pbuf_free(p);
	break;
    }
}

/**
 * Callback to netfront that pushed a received packet to lwIP.
 * Is is called by netfrontif_poll() for each received packet.
 *
 * @param data
 *  the pointer to received packet data
 * @param len
 *  the length of data in bytes
 * @param argp
 *  pointer to netif
 */
static void netfrontif_rx_handler(unsigned char *data, int len, void *argp)
{
    struct netif *netif = argp;
    struct pbuf *p;

    p = netfrontif_mkpbuf(data, len);
    if (unlikely(!p)) {
        LWIP_DEBUGF(NETIF_DEBUG, ("netfrontif_rx_handler: %c%c: ERROR: "
				  "Packet dropped: Out of pbufs\n",
				  netif->name[0], netif->name[1]));
        LINK_STATS_INC(link.memerr);
        LINK_STATS_INC(link.drop);
        return;
    }
    LINK_STATS_INC(link.recv);
    netfrontif_input(p, netif);
}

#ifndef CONFIG_LWIP_NOTHREADS
/**
 * Network polling thread function
 *
 * @param argp
 *  pointer to netif
 */
/* TODO: Use mini-os's blocking poll */
static void netfrontif_thread(void *argp)
{
    struct netif *netif = argp;
    struct netfrontif *nfi = netif->state;
    struct netfront_dev *dev = nfi->dev;

    while (likely(!nfi->_thread_exit)) {
        network_rx(dev);
        schedule();
    }

    nfi->_thread_exit = 0;
}
#endif /* CONFIG_LWIP_NOTHREADS */

#if LWIP_NETIF_REMOVE_CALLBACK
/**
 * Closes a network interface.
 * This function is called by lwIP on netif_remove().
 *
 * @param netif
 *  the lwip network interface structure for this netfrontif
 */
static void netfrontif_exit(struct netif *netif)
{
    struct netfrontif *nfi = netif->state;

#ifndef CONFIG_LWIP_NOTHREADS
    LWIP_DEBUGF(NETIF_DEBUG, ("netfrontif_exit: wait for thread shutdown\n"));
    nfi->_thread_exit = 1; /* request exit */
    while (nfi->_thread_exit)
        schedule();
    LWIP_DEBUGF(NETIF_DEBUG, ("netfrontif_exit: thread was shutdown\n"));
#endif /* CONFIG_LWIP_NOTHREADS */

    if (nfi->_dev_is_private) {
        shutdown_netfront(nfi->dev);
        nfi->dev = NULL;
    }

    if (nfi->_state_is_private) {
	mem_free(nfi);
	netif->state = NULL;
    }
}
#endif /* LWIP_NETIF_REMOVE_CALLBACK */

/**
 * Initializes and sets up a netfront interface for lwIP.
 * This function should be passed as a parameter to netfrontif_add().
 *
 * @param netif
 *  the lwip network interface structure for this netfrontif
 * @return
 *  ERR_OK if the interface was successfully initialized;
 *  An err_t value otherwise
 */
err_t netfrontif_init(struct netif *netif)
{
    struct netfrontif *nfi;
    static uint8_t netfrontif_id = 0;

    LWIP_ASSERT("netif != NULL", (netif != NULL));

    if (!(netif->state)) {
	nfi = mem_calloc(1, sizeof(*nfi));
	if (!nfi) {
	    LWIP_DEBUGF(NETIF_DEBUG, ("netfrontif_init: "
				      "Could not allocate \n"));
	    goto err_out;
	}
	netif->state = nfi;
	nfi->_state_is_private = 1;
	nfi->_dev_is_private = 1;
	nfi->_hwaddr_is_private = 1;
    } else {
	nfi = netif->state;
	nfi->_state_is_private = 0;
	nfi->_dev_is_private = !(nfi->dev);
	nfi->_hwaddr_is_private = eth_addr_cmp(&nfi->hwaddr, &ethzero);
    }

    /* Netfront */
    if (nfi->_dev_is_private) {
	/* user did not provide an opened netfront, we need to do it here */
	if (!nfi->_state_is_private) {
	    /* use vif_id to open an specific NIC interface */
	    /* Note: netfront will duplicate the passed nodename */
	    char nodename[128];

	    snprintf(nodename, sizeof(nodename), "device/vif/%u", nfi->vif_id);
	    nfi->dev = init_netfront(nodename, NULL, NULL, NULL);
	} else {
	    /* open the next available net interface */
	    nfi->dev = init_netfront(NULL, NULL, NULL, NULL);
	}
	if (!nfi->dev) {
	    LWIP_DEBUGF(NETIF_DEBUG, ("netfrontif_init: "
				      "Could not init netfront\n"));
	    goto err_free_nfi;
	}
    }
    netfront_set_rx_handler(nfi->dev, netfrontif_rx_handler, netif);

    /* Interface identifier */
    netif->name[0] = NETFRONTIF_NPREFIX;
    netif->name[1] = '0' + netfrontif_id;
    netfrontif_id++;

    /* We directly use etharp_output() here to save a function call.
     * Instead, there could be function declared that calls etharp_output()
     * only if there is a link is available... */
    netif->output = etharp_output;
    netif->linkoutput = netfrontif_transmit;
#if LWIP_NETIF_REMOVE_CALLBACK
    netif->remove_callback = netfrontif_exit;
#endif /* CONFIG_NETIF_REMOVE_CALLBACK */

    /* Hardware address */
    if (nfi->_hwaddr_is_private) {
	if (!netfront_get_hwaddr(nfi->dev, &nfi->hwaddr)) {
	    LWIP_DEBUGF(NETIF_DEBUG, ("netfrontif_init: %c%c: "
				      "Could not retrieve hardware address\n",
				      netif->name[0], netif->name[1]));
	    goto err_shutdown_netfront;
	}
    } else {
	LWIP_DEBUGF(NETIF_DEBUG, ("netfrontif_init: %c%c: "
				  "Overwriting hardware address\n",
				  netif->name[0], netif->name[1]));
    }
    SMEMCPY(&netif->hwaddr, &nfi->hwaddr, ETHARP_HWADDR_LEN);
    netif->hwaddr_len = ETHARP_HWADDR_LEN;
    LWIP_DEBUGF(NETIF_DEBUG, ("netfrontif_init: %c%c: hardware address: "
			      "%02x:%02x:%02x:%02x:%02x:%02x\n",
			      netif->name[0], netif->name[1],
			      netif->hwaddr[0],
			      netif->hwaddr[1],
			      netif->hwaddr[2],
			      netif->hwaddr[3],
			      netif->hwaddr[4],
			      netif->hwaddr[5]));

    /* Initialize the snmp variables and counters inside the struct netif.
     * The last argument is the link speed, in units of bits per second. */
    NETIF_INIT_SNMP(netif, snmp_ifType_ethernet_csmacd, NETFRONTIF_SPEED);
    LWIP_DEBUGF(NETIF_DEBUG, ("netfrontif_init: %c%c: Link speed: %llu bps\n",
			      netif->name[0], netif->name[1], NETFRONTIF_SPEED));

    /* Device capabilities */
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;

    /* Maximum transfer unit */
    netif->mtu = NETFRONTIF_MTU;
    LWIP_DEBUGF(NETIF_DEBUG, ("netfrontif_init: %c%c: MTU: %u\n",
			      netif->name[0], netif->name[1], netif->mtu));

#if LWIP_NETIF_HOSTNAME
    /* Initialize interface hostname */
    if (!netif->hostname)
	netif->hostname = NULL;
#endif /* LWIP_NETIF_HOSTNAME */

#ifndef CONFIG_LWIP_NOTHREADS
  nfi->_thread_exit = 0;
  nfi->_thread_name[0] = netif->name[0];
  nfi->_thread_name[1] = netif->name[1];
  nfi->_thread_name[2] = '-';
  nfi->_thread_name[3] = 'r';
  nfi->_thread_name[4] = 'x';
  nfi->_thread_name[5] = '\0';
  create_thread(nfi->_thread_name, netfrontif_thread, netif);
#endif /* CONFIG_LWIP_NOTHREADS */

    return ERR_OK;

err_shutdown_netfront:
    shutdown_netfront(nfi->dev);
err_free_nfi:
    if (nfi->_state_is_private) {
	mem_free(nfi);
	netif->state = NULL;
    }
err_out:
    return ERR_IF;
}

/* -------------------------------------------------------------------------- */
#if defined CONFIG_START_NETWORK || defined CONFIG_INCLUDE_START_NETWORK
#include <lwip/ip_addr.h>
#include <lwip/inet.h>
#include <netif/etharp.h>
#include <lwip/tcpip.h>
#include <lwip/init.h>
#include <lwip/tcp.h>
#include <lwip/netif.h>
#include <lwip-net.h>
#include <lwip/ip_frag.h>
#include <lwip/tcp_impl.h>
#include <lwip/dns.h>

static struct netif *netif = NULL;

void start_networking(void)
{
    struct netfront_dev *dev;
    struct netif *_netif;
    struct netif *niret;
    struct netfrontif *nfi;
    struct ip_addr ip;
    struct ip_addr mask;
    struct ip_addr gw;
    char *ifip = NULL;

    ASSERT(netif == NULL);
    IP4_ADDR(&ip,   192, 168,   1, 128);
    IP4_ADDR(&mask, 255, 255, 255,   0);
    IP4_ADDR(&gw,     0,   0,   0,   0);

    tprintk("Starting networking\n");

    /* init netfront */
    dev = init_netfront(NULL, NULL, NULL, &ifip);
    if (!dev) {
        tprintk("Could not init netfront\n");
        goto err_out;
    }
    if (ifip) {
        tprintk("Got IP address %s\n", ifip);

        ip.addr = inet_addr(ifip);
	if (IN_CLASSA(ntohl(ip.addr))) {
	    tprintk("Use class A netmask (255.0.0.0)\n");
	    mask.addr = htonl(IN_CLASSA_NET);
	} else if (IN_CLASSB(ntohl(ip.addr))) {
	    mask.addr = htonl(IN_CLASSB_NET);
	    tprintk("Use class B netmask (255.255.0.0)\n");
	} else if (IN_CLASSC(ntohl(ip.addr))) {
	    mask.addr = htonl(IN_CLASSC_NET);
	    tprintk("Use class C netmask (255.255.255.0)\n");
	} else {
	    tprintk("Could not auto-detect IP class for %s,"
		    "use class C netmask (255.255.255.0)\n", ifip);
	}
    } else {
        tprintk("Set IP to 192.168.1.128, use class A netmask (255.0.0.0)\n");
    }

    /* allocate netif */
    _netif = mem_calloc(1, sizeof(*_netif));
    if (!_netif) {
        tprintk("Could not allocate netif\n");
        goto err_shutdown_netfront;
    }
    /* allocate netif state data */
    nfi = mem_calloc(1, sizeof(*nfi));
    if (!nfi) {
        tprintk("Could not allocate netfrontif\n");
        goto err_free_netif;
    }
    nfi->dev = dev;

    /* init lwIP */
#ifdef CONFIG_LWIP_NOTHREADS
    lwip_init();
    niret = netif_add(_netif, &ip, &mask, &gw, nfi,
                      netfrontif_init, ethernet_input);
#else
    tcpip_init(NULL, NULL);
    niret = netif_add(_netif, &ip, &mask, &gw, nfi,
                      netfrontif_init, tcpip_input);
#endif
    if (!niret) {
        tprintk("Could not initialize lwIP\n");
	goto err_free_nfi;
    }
    netif_set_default(_netif);
    netif_set_up(_netif);

    netif = _netif;
    tprintk("Networking started\n");
    return;

 err_free_nfi:
    mem_free(nfi);
 err_free_netif:
    mem_free(_netif);
 err_shutdown_netfront:
    shutdown_netfront(dev);
 err_out:
    return;
}

void stop_networking(void)
{
    struct netif *_netif = netif;
    struct netfront_dev *dev;
    struct netfrontif *nfi;

    if (!_netif)
        return;
    netif = NULL;

    tprintk("Stopping networking\n");

    netif_set_down(_netif);
    nfi = _netif->state;
    dev = nfi->dev;
    netif_remove(_netif);

    mem_free(nfi);
    mem_free(_netif);
    shutdown_netfront(dev);

    tprintk("Networking stopped\n");
}

#ifdef CONFIG_LWIP_NOTHREADS
#define TIMED(ts_now, ts_tmr, interval, func)				\
    do {								\
        if (unlikely(((ts_now) - (ts_tmr)) > (interval))) {		\
	    if ((ts_tmr))						\
	      (func);							\
	    (ts_tmr) = (ts_now);					\
	}								\
    } while(0)

static uint64_t ts_tcp = 0;
static uint64_t ts_etharp = 0;
static uint64_t ts_ipreass = 0;
static uint64_t ts_dns = 0;

void poll_networking(void)
{
    uint64_t now;

    if (!netif)
        return;

    /* poll interface */
    netfrontif_poll(netif, LWIP_NETIF_MAX_RXBURST_LEN);

    /* process lwIP timers */
    now = NSEC_TO_MSEC(NOW());
    TIMED(now, ts_etharp,  ARP_TMR_INTERVAL, etharp_tmr());
    TIMED(now, ts_ipreass, IP_TMR_INTERVAL,  ip_reass_tmr());
    TIMED(now, ts_tcp,     TCP_TMR_INTERVAL, tcp_tmr());
    TIMED(now, ts_dns,     DNS_TMR_INTERVAL, dns_tmr());
}
#endif /* CONFIG_LWIP_NOTHREADS */

void networking_set_addr(struct ip_addr *ipaddr, struct ip_addr *netmask, struct ip_addr *gw)
{
    netif_set_ipaddr(netif, ipaddr);
    netif_set_netmask(netif, netmask);
    netif_set_gw(netif, gw);
}
#endif /* CONFIG_START_NETWORK || CONFIG_INCLUDE_START_NETWORK */
