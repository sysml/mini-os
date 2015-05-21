/*
 * lwipopts.h
 *
 * Configuration for lwIP running on mini-os
 *
 * Tim Deegan <Tim.Deegan@eu.citrix.net>, July 2007
 * Simon Kuenzer <simon.kuenzer@neclab.eu>, October 2013
 */
#ifndef __LWIP_LWIPOPTS_H__
#define __LWIP_LWIPOPTS_H__

/*
 * General options/System settings
 */
/* lightweight protection */
#define SYS_LIGHTWEIGHT_PROT 1

/* provide malloc/free by mini-os */
#ifdef CONFIG_LWIP_HEAP_ONLY
  /* Only use malloc/free for lwIP.
   * Every allocation is done by the heap.
   * Note: This setting results in the smallest binary
   *       size but leads to heavy malloc/free usage during
   *       network processing.
   */
  #define MEM_LIBC_MALLOC 1 /* enable heap */
  #define MEMP_MEM_MALLOC 1 /* pool allocations via malloc (thus not from pool in data segment) */
#elif defined CONFIG_LWIP_POOLS_ONLY
  /* Do not use the heap (malloc/free) at all.
   * Pools are used for pool allocations and all the rest of allocations.
   * Note: lwIP allocate pools on the data segment
   * Note: This setting might have the highest performance but
   *       increases the binary size the most
   */
  #define MEM_LIBC_MALLOC 0
  #define MEMP_MEM_MALLOC 0
  #define MEM_USE_POOLS 1 /* use pools instead of heap */
  #define MEM_USE_POOLS_TRY_BIGGER_POOL 1
  #define MEM_SIZE 2048 /* size of lwip's heap emulation */
  /* Note: Use LWIP_RAM_HEAP_POINTER to place the emulated heap somewhere else */
#else /* default */
  /* This is the default configuration (mixed).
   * Pools are used for pool allocations and the heap
   * is used for all the rest of allocations.
   * Note: Per design, lwIP allocates outgoing packet buffers
   *       from heap (via PBUF_RAM) and incoming from pools (via PBUF_POOL)
   *       CONFIG_LWIP_PBUF_POOL_SIZE defines the pool size for PBUF_POOL
   *       allocations
   * Note: lwIP allocate pools on the data segment
   */
  #define MEM_LIBC_MALLOC 1 /* enable heap */
  #define MEMP_MEM_MALLOC 0 /* pool allocations still via pool */
#endif

#define MEMP_SEPARATE_POOLS 1 /* for each pool use a separate aray in data segment */
#define MEM_ALIGNMENT 4

#if MEM_USE_POOLS
/* requires lwippools.h */
#define MEMP_USE_CUSTOM_POOLS 0
#endif

#if MEM_LIBC_MALLOC
#include <stddef.h> /* size_t */
void *lwip_malloc(size_t size);
void *lwip_calloc(int num, size_t size);
void lwip_free(void *ptr);

#define mem_malloc   lwip_malloc
#define mem_calloc   lwip_calloc
#define mem_free     lwip_free
#endif

#define MEMCPY(dst, src, len)  memcpy((dst), (src), (len))

/*
 * Feature selection
 */
#define LWIP_NETIF_REMOVE_CALLBACK 1
#define LWIP_TIMEVAL_PRIVATE 0
#define LWIP_DHCP 1
#define LWIP_SOCKET 1 /* required by lib/sys.c */
#define LWIP_IGMP 1
#define LWIP_DNS 1
#ifndef CONFIG_LWIP_MINIMAL
#define LWIP_SNMP 1
#define LWIP_PPP 1
#define LWIP_SLIP 1
#define LWIP_AUTOIP 1
#endif

/* disable BSD-style socket */
#define LWIP_COMPAT_SOCKETS 0

/*
 * Pool options
 */
/* PBUF pools */
#if !defined CONFIG_LWIP_PBUF_NUM_RX || !CONFIG_LWIP_PBUF_NUM_RX
#undef CONFIG_LWIP_PBUF_NUM_RX
#define CONFIG_LWIP_PBUF_NUM_RX 512
#endif
#if !defined CONFIG_LWIP_PBUF_NUM_REF || !CONFIG_LWIP_PBUF_NUM_REF
#undef CONFIG_LWIP_PBUF_NUM_REF
#define CONFIG_LWIP_PBUF_NUM_REF (MEMP_NUM_TCP_PCB * 24)
#endif
#define PBUF_POOL_SIZE CONFIG_LWIP_PBUF_NUM_RX
#define MEMP_NUM_PBUF CONFIG_LWIP_PBUF_NUM_REF

/*
 * Thread options
 */
#ifndef CONFIG_LWIP_NOTHREADS
#define TCPIP_THREAD_NAME "lwIP"
#define TCPIP_MBOX_SIZE 256
#define MEMP_NUM_TCPIP_MSG_INPKT 256
#endif

/*
 * ARP options
 */
#define MEMP_NUM_ARP_QUEUE 256
#define ETHARP_SUPPORT_STATIC_ENTRIES 1

/*
 * UDP options
 */
#define MEMP_NUM_UDP_PCB 16

/*
 * TCP options
 */
#if !defined CONFIG_LWIP_NUM_TCPCON || !CONFIG_LWIP_NUM_TCPCON
#undef CONFIG_LWIP_NUM_TCPCON
#define CONFIG_LWIP_NUM_TCPCON 512
#endif

#define TCP_MSS 1460
#define TCP_WND 32766 /* Ideally, TCP_WND should be link bandwidth multiplied by rtt */
#if defined CONFIG_LWIP_WND_SCALE
#define LWIP_WND_SCALE 1
#else
#define LWIP_WND_SCALE 0
#endif
#if LWIP_WND_SCALE
#if defined CONFIG_LWIP_WND_SCALE_FACTOR && CONFIG_LWIP_WND_SCALE_FACTOR >= 1
#define TCP_RCV_SCALE CONFIG_LWIP_WND_SCALE_FACTOR /* scaling factor 0..14 */
#else
#define TCP_RCV_SCALE 3
#endif
#define TCP_SND_BUF ((TCP_WND << TCP_RCV_SCALE) * 2)
#else
#define TCP_SND_BUF (TCP_WND * 2)
#endif
#define TCP_SND_QUEUELEN (4 * TCP_SND_BUF / TCP_MSS)
#define TCP_QUEUE_OOSEQ 1
#define MEMP_NUM_TCP_SEG CONFIG_LWIP_PBUF_NUM_REF
#define MEMP_NUM_FRAG_PBUF 32
#define LWIP_TCP_TIMESTAMPS 0
#define TCP_OVERSIZE TCP_MSS
#define LWIP_TCP_KEEPALIVE 1

#define MEMP_NUM_TCP_PCB CONFIG_LWIP_NUM_TCPCON /* max num of sim. TCP connections */
#define MEMP_NUM_TCP_PCB_LISTEN 32 /* max num of sim. TCP listeners */

/*
 * DNS options
 */
#define DNS_MAX_SERVERS 2
#define DNS_TABLE_SIZE 32
#define DNS_LOCAL_HOST_LIST 1
#define DNS_LOCAL_HOSTLIST_IS_DYNAMIC 1
//#define DNS_LOCAL_HOSTLIST_INIT {{"host1", 0x123}, {"host2", 0x234}}

/*
 * Checksum options
 */
#ifdef CONFIG_LWIP_CHECKSUM_NOGEN
#define CHECKSUM_GEN_IP 0
#define CHECKSUM_GEN_UDP 0
#define CHECKSUM_GEN_TCP 0
#define CHECKSUM_GEN_ICMP 0
#define CHECKSUM_GEN_ICMP6 0
#else
#define LWIP_CHECKSUM_ON_COPY 1
#endif

#ifdef CONFIG_LWIP_CHECKSUM_NOCHECK
#define CHECKSUM_CHECK_IP 0
#define CHECKSUM_CHECK_UDP 0
#define CHECKSUM_CHECK_TCP 0
#define CHECKSUM_CHECK_ICMP 0
#define CHECKSUM_CHECK_ICMP6 0
#endif

/*
 * Debugging options
 */
#ifdef LWIP_DEBUG
#define LWIP_MAINLOOP_DEBUG
#define LWIP_IF_DEBUG
#define LWIP_IP_DEBUG
#define LWIP_UDP_DEBUG
#define LWIP_TCP_DEBUG
#define LWIP_SYS_DEBUG
#define LWIP_API_DEBUG
#define LWIP_SERVICE_DEBUG
#endif /* LWIP_DEBUG */

#if defined LWIP_DEBUG || \
    defined LWIP_MAINLOOP_DEBUG || \
    defined LWIP_IF_DEBUG || \
    defined LWIP_IP_DEBUG || \
    defined LWIP_UDP_DEBUG || \
    defined LWIP_TCP_DEBUG || \
    defined LWIP_SYS_DEBUG || \
    defined LWIP_API_DEBUG || \
    defined LWIP_SERVICE_DEBUG
#undef LWIP_DEBUG
#define LWIP_DEBUG 1
#endif

#ifdef LWIP_MAINLOOP_DEBUG
#define IP_DEBUG LWIP_DBG_ON
#define TCPIP_DEBUG LWIP_DBG_ON
#define TIMERS_DEBUG LWIP_DBG_ON
#endif /* LWIP_MAINLOOP_DEBUG */

#ifdef LWIP_IF_DEBUG
#define NETIF_DEBUG LWIP_DBG_ON
#endif /* LWIP_IF_DEBUG */

#ifdef LWIP_IP_DEBUG
#define IP_DEBUG LWIP_DBG_ON
#define IP6_DEBUG LWIP_DBG_ON
#define IP_REASS_DEBUG LWIP_DBG_ON
#endif /* LWIP_IP_DEBUG */

#ifdef LWIP_UDP_DEBUG
#define UDP_DEBUG LWIP_DBG_ON
#endif /* LWIP_UDP_DEBUG */

#ifdef LWIP_TCP_DEBUG
#define TCP_DEBUG LWIP_DBG_ON
#define TCP_FR_DEBUG LWIP_DBG_ON
#define TCP_RTO_DEBUG LWIP_DBG_ON
#define TCP_CWND_DEBUG LWIP_DBG_ON
#define TCP_WND_DEBUG LWIP_DBG_ON
#define TCP_RST_DEBUG LWIP_DBG_ON
#define TCP_QLEN_DEBUG LWIP_DBG_ON
//#define TCP_OUTPUT_DEBUG LWIP_DBG_ON
//#define TCP_INPUT_DEBUG LWIP_DBG_ON
#if LWIP_CHECKSUM_ON_COPY
#define TCP_CHECKSUM_ON_COPY_SANITY_CHECK 1
#endif
#endif /* LWIP_TCP_DEBUG */

#ifdef LWIP_SYS_DEBUG
#define SYS_DEBUG LWIP_DBG_ON
#define PBUF_DEBUG LWIP_DBG_ON
#define MEM_DEBUG LWIP_DBG_ON
#define MEMP_DEBUG LWIP_DBG_ON
#endif /* LWIP_SYS_DEBUG */

#ifdef LWIP_API_DEBUG
#define SOCKETS_DEBUG LWIP_DBG_ON
#define RAW_DEBUG LWIP_DBG_ON
#define API_MSG_DEBUG LWIP_DBG_ON
#define API_LIB_DEBUG LWIP_DBG_ON
#endif /* LWIP_API_DEBUG */

#ifdef LWIP_SERVICE_DEBUG
#define ETHARP_DEBUG LWIP_DBG_ON
#define DNS_DEBUG LWIP_DBG_ON
#define AUTOIP_DEBUG LWIP_DBG_ON
#define DHCP_DEBUG LWIP_DBG_ON
#define ICMP_DEBUG LWIP_DBG_ON
#define SNMP_DEBUG LWIP_DBG_ON
#define SNMP_MSG_DEBUG LWIP_DBG_ON
#define SNMP_MIB_DEBUG LWIP_DBG_ON
#define PPP_DEBUG LWIP_DBG_ON
#define SLIP_DEBUG LWIP_DBG_ON
#endif /* LWIP_SERVICE_DEBUG */

#endif /* __LWIP_LWIPOPTS_H__ */
