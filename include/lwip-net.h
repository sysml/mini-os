/*
 * Mini-OS netfront driver for lwIP
 *
 *   file: lwip-net.h
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
 */
#ifndef __LWIP_NET_H__
#define __LWIP_NET_H__

#include <netfront.h>
#include "lwip/opt.h"
#include "netif/etharp.h"
#include "netif/ppp/pppoe.h"

/**
 * Helper struct to hold private data used to operate the ethernet interface.
 * The user can pre-initialize some values (e.g., providing a mac address,
 * passing a opened netfront_dev struct) and lwIP will use those passed data
 * instead. For values that are not set (e.g., dev is NULL, hwaddress is
 * zero), lwIP will retrieve them from the interface.
 *
 * If no netfrontif struct is passed (via netif->state), lwIP is opening and
 * managing one by itself. lwIP will only close self-opened devices on
 * netif_exit().
 */
struct netfrontif {
    uint8_t vif_id;
    struct netfront_dev *dev;
    struct eth_addr hwaddr;

    /* the following fields are used internally */
#ifndef CONFIG_LWIP_NOTHREADS
    volatile int _thread_exit;
    char _thread_name[6];
#endif
    int _state_is_private;
    int _dev_is_private;
    int _hwaddr_is_private;
};

#ifdef CONFIG_LWIP_NOTHREADS
/* NIC I/O handling: has to be called periodically
 * to get received by the lwIP stack.
 *
 * Note: On threaded configuration, this call
 * is executed by a thread created for the device.
 * In this case, it has just to be ensured that this
 * thread get scheduled frequently.
 */
#define netfrontif_poll(netif) \
  network_rx(((struct netfrontif *) ((netif)->state))->dev)
#endif

err_t netfrontif_init(struct netif *netif);

#ifdef CONFIG_SELECT_POLL
#define netfrontif_fd(netif) \
  netfront_get_fd(((struct netfrontif *) ((netif)->state))->dev)
#endif

#endif /* __LWIP_NET_H__ */
