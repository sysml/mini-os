/*
 * Mini-OS netfront driver for lwIP
 *
 * Authors: Simon Kuenzer <simon.kuenzer@neclab.eu>
 *
 *
 * Copyright (c) 2013-2017, NEC Europe Ltd., NEC Corporation All rights reserved.
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

#if defined CONFIG_NETFRONT_GSO || defined CONFIG_LWIP_BATCHTX
#include "netif/etharp.h"
#include "lwip/ip4.h"
#if IPV6_SUPPORT
#include "lwip/ip6.h"
#endif
#include "lwip/tcp_impl.h"
#include "lwip/tcp.h"
#include <xen/io/netif.h>
#endif /* defined CONFIG_NETFRONT_GSO || defined CONFIG_LWIP_BATCHTX */

#include <lwip/stats.h>
#include <lwip/snmp.h>
#include <sys/time.h>
#include <unistd.h>

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

/*
static inline void printp(struct pbuf *p)
{
  u16_t left = p->tot_len;
  u16_t offset = 0;
  unsigned char o;
  u16_t i = 0;

  while (left) {
    if (offset == p->len) {
      p = p->next;
      offset = 0;
    }

    if (i && i % 2 == 0)
      printk(" ");
    if (i && i % 16 == 0)
      printk("\n");
    if (i % 16 == 0)
      printk(" %04x: ", offset);

    o = *(((typeof(o) *) p->payload) + offset);
    printk("%02x", (unsigned char) o);

    ++offset; ++i; --left;
  }
  printk("\n", o);
}
*/

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
 *  ERR_OK when the packet could be enqueued for sending; an err_t value otherwise
 */
static inline err_t netfrontif_transmit(struct netif *netif, struct pbuf *p)
{
    struct netfrontif *nfi = netif->state;
#if LWIP_CHECKSUM_PARTIAL || defined CONFIG_LWIP_BATCHTX
    s16_t ip_hdr_offset;
    const struct eth_hdr *ethhdr;
    const struct ip_hdr *iphdr;
#endif /* LWIP_CHECKSUM_PARTIAL || defined CONFIG_LWIP_BATCHTX */
#ifdef CONFIG_LWIP_BATCHTX
    const struct tcp_hdr *tcphdr;
#endif /* CONFIG_LWIP_BATCHTX */
    int tso = 0;
    int push = 1;
    err_t err;

    LWIP_DEBUGF(NETIF_DEBUG, ("netfrontif_transmit: %c%c: "
			      "Transmitting %u bytes\n",
			      netif->name[0], netif->name[1],
			      p->tot_len));

#if LWIP_CHECKSUM_PARTIAL || defined CONFIG_LWIP_BATCHTX
    /* detect if payload contains a TCP packet */
    /* NOTE: We assume here that all protocol headers are in the first pbuf of a pbuf chain! */
    ip_hdr_offset = SIZEOF_ETH_HDR;
    ethhdr = (struct eth_hdr *) p->payload;
#if ETHARP_SUPPORT_VLAN
    if (type == PP_HTONS(ETHTYPE_VLAN)) {
      type = ((struct eth_vlan_hdr*)(((uintptr_t)ethhdr) + SIZEOF_ETH_HDR))->tpid;
      ip_hdr_offset = SIZEOF_ETH_HDR + SIZEOF_VLAN_HDR;
    }
#endif /* ETHARP_SUPPORT_VLAN */
    /* TODO: PPP support? */

    switch (ethhdr->type) {
    case PP_HTONS(ETHTYPE_IP):
      iphdr = (struct ip_hdr *)((uintptr_t) p->payload + ip_hdr_offset);
      if (IPH_PROTO(iphdr) != IP_PROTO_TCP) {
	goto xmit; /* IPv4 but not TCP */
      }
#if LWIP_CHECKSUM_PARTIAL
      tso = XEN_NETIF_GSO_TYPE_TCPV4; /* TCPv4 segmentation and checksum offloading */
#endif /* LWIP_CHECKSUM_PARTIAL */
#ifdef CONFIG_LWIP_BATCHTX
      /* push only when FIN, RST, PSH, or URG flag is set */
      tcphdr = (struct tcp_hdr *)((uintptr_t) p->payload + ip_hdr_offset + (IPH_HL(iphdr) * 4));
      push = (TCPH_FLAGS(tcphdr) & (TCP_FIN | TCP_RST | TCP_PSH | TCP_URG));
#endif /* CONFIG_LWIP_BATCHTX */
      break;

#if IPV6_SUPPORT
    case PP_HTONS(ETHTYPE_IPV6):
      if (IP6H_NEXTH((struct ip6_hdr *)((uintptr_t) p->payload + ip_hdr_offset)) != IP6_NEXTH_TCP)
	goto xmit; /* IPv6 but not TCP */
#if LWIP_CHECKSUM_PARTIAL
      tso = XEN_NETIF_GSO_TYPE_TCPV6; /* TCPv6 segmentation and checksum offloading */
#endif /* LWIP_CHECKSUM_PARTIAL */
#ifdef CONFIG_LWIP_BATCHTX
      /* push only when FIN, RST, PSH, or URG flag is set */
      #error "TSOv6 is not yet supported. Please add it"
      tcphdr = NULL;
      push = (TCPH_FLAGS(tcphdr) & (TCP_FIN | TCP_RST | TCP_PSH | TCP_URG));
#endif /* CONFIG_LWIP_BATCHTX */
      break;
#endif /* IPV6_SUPPORT */

    default:
      break; /* non-IP packet */
    }
#endif /* LWIP_CHECKSUM_PARTIAL || defined CONFIG_LWIP_BATCHTX */

 xmit:
#if ETH_PAD_SIZE
    pbuf_header(p, -ETH_PAD_SIZE); /* drop the padding word */
#endif
    err = netfront_xmit_pbuf(nfi->dev, p, tso, push);
    if (likely(err == ERR_OK)) {
      LINK_STATS_INC(link.xmit);
    } else {
      LWIP_DEBUGF(NETIF_DEBUG, ("netfrontif_transmit: transmission failed, dropping packet: %d\n", err));
      LINK_STATS_INC(link.drop);
    }

#if ETH_PAD_SIZE
    pbuf_header(p, ETH_PAD_SIZE); /* reclaim the padding word */
#endif

    return err;
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
    switch (ethhdr->type) {
    /* IP or ARP packet? */
    case PP_HTONS(ETHTYPE_IP):
#if IPV6_SUPPORT
    case PP_HTONS(ETHTYPE_IPV6):
#endif
    case PP_HTONS(ETHTYPE_ARP):
#if PPPOE_SUPPORT
    case PP_HTONS(ETHTYPE_PPPOEDISC):
    case PP_HTONS(ETHTYPE_PPPOE):
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
 * Callback to netfront that pushed a received pbuf to lwIP.
 * Is is called by netfrontif_poll() for each received packet.
 *
 * @param p
 *  the pointer to received packet data
 * @param argp
 *  pointer to netif
 */
static void netfrontif_rx_handler(struct pbuf *p, void *argp)
{
    struct netif *netif = argp;

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

#ifdef CONFIG_SELECT_POLL
    int fd;
    fd_set rfds;
    struct timeval tv;

    fd = netfrontif_fd(netif);
    FD_ZERO(&rfds);

    tv.tv_sec = CONFIG_LWIP_SELECT_TIMEOUT;
    tv.tv_usec = 0;
#endif

    while (likely(!nfi->_thread_exit)) {
#ifdef CONFIG_SELECT_POLL
        FD_SET(fd, &rfds);
        select(fd + 1, &rfds, NULL, NULL, &tv);
#else
        schedule();
#endif
        network_rx(dev);
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
#ifdef CONFIG_SELECT_POLL
    wake(nfi->_thread);
#endif
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
	nfi->dev->netif = nfi;
    }

    netfront_set_rx_pbuf_handler(nfi->dev, netfrontif_rx_handler, netif);

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
  nfi->_thread = create_thread(nfi->_thread_name, netfrontif_thread, netif);
#endif /* CONFIG_LWIP_NOTHREADS */

    return ERR_OK;

err_shutdown_netfront:
    if (nfi->_dev_is_private) {
        shutdown_netfront(nfi->dev);
        nfi->dev = NULL;
    }
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
    dev->netif = nfi;

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

void netfrontif_thread_suspend(struct netfrontif *nfi)
{
    if (nfi && nfi->_thread)
        clear_runnable(nfi->_thread);
}

void netfrontif_thread_resume(struct netfrontif *nfi)
{
    if (nfi && nfi->_thread)
        set_runnable(nfi->_thread);
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
