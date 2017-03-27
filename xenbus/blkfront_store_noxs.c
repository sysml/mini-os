/*
 * blkfront_store_xenbus.c
 *
 *  Created on: Feb 7, 2017
 *      Author: wolf
 */
#include <xen/io/protocols.h>
#include <mini-os/blkfront.h>
#include <mini-os/events.h>
#include <fcntl.h>


int blkfront_store_preinit(struct blkfront_dev *dev, int id, void *arg)
{
    return 0;
}

int blkfront_store_init(struct blkfront_dev *dev)
{
    struct noxs_vbd_ctrl_page *vbd_page;

    if (noxs_handle_init(&dev->noxs_dev_handle, noxs_dev_vbd) != 0)
        return -1;

    dev->dom = dev->noxs_dev_handle.be_id;
    vbd_page = dev->noxs_dev_handle.ctrl_page;

    dev->handle = vbd_page->hdr.devid;

    dev->vbd_page = vbd_page;

    return 0;
}

void blkfront_store_fini(struct blkfront_dev *dev)
{
    noxs_handle_unwatch(&dev->noxs_dev_handle);
}

int blkfront_store_front_data_create(struct blkfront_dev *dev)
{
    noxs_vbd_ctrl_page_t *vbd_page = dev->vbd_page;
    noxs_ring_t *ring = &vbd_page->rings_start_addr[0];

    strcpy(vbd_page->protocol, XEN_IO_PROTO_ABI_NATIVE);

#ifdef CONFIG_BLKFRONT_PERSISTENT_GRANTS
    vbd_page->fe_feat.persistent = 1;
#endif

    ring->evtchn = dev->evtchn;
    ring->refs[0] = dev->ring_ref;

    return 0;
}

int blkfront_store_front_data_destroy(struct blkfront_dev *dev)
{
    return 0;
}

int blkfront_store_wait_be_connect(struct blkfront_dev *dev)
{
    struct noxs_vbd_ctrl_page *vbd_page;
    struct noxs_dev_handle *h;
    XenbusState state;
    int ret;

    vbd_page = dev->vbd_page;
    h = &dev->noxs_dev_handle;

    /* Switch to Connected */
    noxs_handle_watch(h);
    vbd_page->hdr.fe_state = XenbusStateConnected;
    ret = notify_remote_via_evtchn(h->listener.evtchn);
    if (ret)
        goto out;
    /* Wait BE change */
    state = vbd_page->hdr.be_state;
    while (state < XenbusStateConnected)
        noxs_wait_for_state_change(h, &state);

    if (state != XenbusStateConnected) {
        printk("blk backend not available, state=%d\n", state);
        ret = -1;
    }

out:
    noxs_handle_unwatch(h);

    return ret;
}

int blkfront_store_wait_be_disconnect(struct blkfront_dev *dev)
{
    struct noxs_vbd_ctrl_page *vbd_page;
    struct noxs_dev_handle *h;
    XenbusState state;
    int ret;

    vbd_page = dev->vbd_page;
    h = &dev->noxs_dev_handle;

    /* Switch to Closing */
    noxs_handle_watch(h);
    vbd_page->hdr.fe_state = XenbusStateClosing;
    ret = notify_remote_via_evtchn(h->listener.evtchn);
    if (ret)
        goto out;
    /* Wait BE change */
    state = vbd_page->hdr.be_state;
    while (state < XenbusStateClosing)
        noxs_wait_for_state_change(h, &state);

    /* Switch to Closed */
    noxs_handle_watch(h);
    vbd_page->hdr.fe_state = XenbusStateClosed;
    ret = notify_remote_via_evtchn(h->listener.evtchn);
    if (ret)
        goto out;
    /* Wait BE change */
    state = vbd_page->hdr.be_state;
    while (state < XenbusStateClosed)
        noxs_wait_for_state_change(h, &state);

    /* Switch to Initialising */
    noxs_handle_watch(h);
    vbd_page->hdr.fe_state = XenbusStateInitialising;
    ret = notify_remote_via_evtchn(h->listener.evtchn);
    if (ret)
        goto out;
    /* Wait BE change */
    state = vbd_page->hdr.be_state;
    while (state < XenbusStateInitWait || state >= XenbusStateClosed)
        noxs_wait_for_state_change(h, &state);

out:
    noxs_handle_unwatch(h);

    return ret;
}

int blkfront_store_read_be_info(struct blkfront_dev *dev)
{
    struct noxs_vbd_ctrl_page *vbd_page;
    int ret = 0;

    vbd_page = dev->vbd_page;

    if (vbd_page->mode == noxs_vbd_mode_rdwr)
        dev->info.mode = O_RDWR;
    else if (vbd_page->mode == noxs_vbd_mode_rdonly)
        dev->info.mode = O_RDONLY;
    else {
        ret = -1;
        goto error;
    }

    dev->info.info = vbd_page->info;
    // FIXME: read_integer returns an int, so disk size limited to 1TB for now
    dev->info.sectors = vbd_page->sectors;
    dev->info.sector_size = vbd_page->sector_size;

#ifdef CONFIG_BLKFRONT_PERSISTENT_GRANTS
    if (vbd_page->be_feat.persistent != 1) {
        printk("backend does not support persistent grants\n");
        ret = -1;
        goto error;
    }

    /* fast copy only usable if devices sector size is multiple of 256 */
    if (dev->info.sector_size & 0xFF) {
        printk("unsupported device sector size: %d\n", dev->info.sector_size);
        ret = -1;
        goto error;
    }
#endif

    dev->info.barrier = vbd_page->be_feat.barrier;
    dev->info.flush = vbd_page->be_feat.flush_cache;

error:
    return ret;
}
