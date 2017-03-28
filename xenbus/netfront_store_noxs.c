/*
 * netfront_store_noxs.c
 *
 *  Created on: Oct 10, 2016
 *      Author: wolf
 */

#include <mini-os/netfront.h>
#include <mini-os/events.h>



int netfront_store_dev_matches_id(struct netfront_dev *dev, void *store_id)
{
    int ret;
    int devid;
    noxs_vif_ctrl_page_t *vif_page;

    ret = 0;

    if (dev && store_id) {
        devid = *((int *) store_id);
        vif_page = dev->vif_page;

        ret = (vif_page != NULL && vif_page->vifid == devid);
    }

    return ret;
}

const char *netfront_store_dev_name(struct netfront_dev *dev)
{
    return dev->name;
}

int netfront_store_pre(struct netfront_dev *dev, void *store_id)
{
    return 0;
}

void netfront_store_post(struct netfront_dev *dev)
{
}

int netfront_store_init(struct netfront_dev *dev, int *is_split_evtchn)
{
    noxs_vif_ctrl_page_t *vif_page;
    char nodename[32];

    if (noxs_handle_init(&dev->noxs_dev_handle, noxs_dev_vif) != 0)
        return -1;

    dev->dom = dev->noxs_dev_handle.be_id;
    vif_page = dev->noxs_dev_handle.ctrl_page;

#ifdef CONFIG_NETMAP
    dev->netmap = vif_page->be_feat.netmap;
#endif
    if (is_split_evtchn)
        /* Check feature-split-event-channels */
        *is_split_evtchn = vif_page->be_feat.split_event_channels;

    snprintf(nodename, sizeof(nodename), "vif-%d", vif_page->hdr.devid);
    dev->name = strdup(nodename);

    dev->vif_page = vif_page;

    return 0;
}

void netfront_store_fini(struct netfront_dev *dev)
{
    noxs_handle_unwatch(&dev->noxs_dev_handle);

    if (dev->name) {
        free(dev->name);
        dev->name = NULL;
    }
}

int netfront_store_front_data_create(struct netfront_dev *dev, int split_evtchn)
{
    noxs_vif_ctrl_page_t *vif_page = dev->vif_page;

    vif_page->tx_ring_ref = dev->tx_ring_ref;
    vif_page->rx_ring_ref = dev->rx_ring_ref;

    if (split_evtchn) {
        vif_page->event_channel_tx = dev->tx_evtchn;
        vif_page->event_channel_rx = dev->rx_evtchn;
    } else {
        vif_page->event_channel_rx = dev->tx_evtchn;
        vif_page->event_channel_tx = dev->tx_evtchn;
    }

    vif_page->fe_feat.rx_notify = 1;

#ifdef CONFIG_NETFRONT_PERSISTENT_GRANTS
    vif_page->fe_feat.persistent = 1;
#endif

    vif_page->request_rx_copy = 1;

#if defined(CONFIG_NETFRONT_GSO) && defined(HAVE_LWIP)
    vif_page->fe_feat.sg = 1;
    vif_page->fe_feat.gso_tcpv4 = 1;
    vif_page->fe_feat.gso_tcpv6 = 1;
#endif

    return 0;
}

int netfront_store_front_data_destroy(struct netfront_dev *dev)
{
    return 0;
}

int netfront_store_wait_be_connect(struct netfront_dev *dev)
{
    noxs_vif_ctrl_page_t *vif_page;
    struct noxs_dev_handle *h;
    XenbusState state;
    int ret;

    vif_page = dev->vif_page;
    h = &dev->noxs_dev_handle;

    /* Switch to Connected */
    noxs_handle_watch(h);
    vif_page->hdr.fe_state = XenbusStateConnected;
    ret = notify_remote_via_evtchn(h->listener.evtchn);
    if (ret)
        goto out;
    /* Wait BE change */
    state = vif_page->hdr.be_state;
    while (state < XenbusStateConnected)
        noxs_wait_for_state_change(h, &state);

    if (state != XenbusStateConnected) {
        printk("net backend not available, state=%d\n", state);
        ret = -1;
    }

out:
    noxs_handle_unwatch(h);

    return ret;
}

int netfront_store_wait_be_disconnect(struct netfront_dev *dev)
{
    noxs_vif_ctrl_page_t *vif_page;
    struct noxs_dev_handle *h;
    XenbusState state;
    int ret;

    vif_page = dev->vif_page;
    h = &dev->noxs_dev_handle;

    /* Switch to Closing */
    noxs_handle_watch(h);
    vif_page->hdr.fe_state = XenbusStateClosing;
    ret = notify_remote_via_evtchn(h->listener.evtchn);
    if (ret)
        goto out;
    /* Wait BE change */
    state = vif_page->hdr.be_state;
    while (state < XenbusStateClosing)
        noxs_wait_for_state_change(h, &state);

    /* Switch to Closed */
    noxs_handle_watch(h);
    vif_page->hdr.fe_state = XenbusStateClosed;
    ret = notify_remote_via_evtchn(h->listener.evtchn);
    if (ret)
        goto out;
    /* Wait BE change */
    state = vif_page->hdr.be_state;
    while (state < XenbusStateClosed)
        noxs_wait_for_state_change(h, &state);

    /* Switch to Initialising */
    noxs_handle_watch(h);
    vif_page->hdr.fe_state = XenbusStateInitialising;
    ret = notify_remote_via_evtchn(h->listener.evtchn);
    if (ret)
        goto out;
    /* Wait BE change */
    state = vif_page->hdr.be_state;
    while (state < XenbusStateInitWait || state >= XenbusStateClosed)
        noxs_wait_for_state_change(h, &state);

out:
    noxs_handle_unwatch(h);

    return ret;
}

int netfront_store_read_mac(struct netfront_dev *dev, unsigned char rawmac[6])
{
    memcpy(rawmac, dev->vif_page->mac, sizeof(dev->vif_page->mac));
    return 0;
}

void netfront_store_read_ip(struct netfront_dev *dev, void *out)
{
    u32_t *ip = out;
    *ip = dev->vif_page->ip;
}
