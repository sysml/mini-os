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
    struct thread *_thread;
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
