/*
 * blkfront_store_xenbus.c
 *
 *  Created on: Feb 7, 2017
 *      Author: wolf
 */
#include <xen/io/protocols.h>
#include <mini-os/blkfront.h>
#include <fcntl.h>
#include <mini-os/lib.h>
#include <mini-os/xmalloc.h>


int blkfront_store_preinit(struct blkfront_dev *dev, int id, void *arg)
{
    char nodename[256];

    if (!arg)
        snprintf(nodename, sizeof(nodename), "device/vbd/%d", id);
    else {
        strncpy(nodename, (char *) arg, sizeof(nodename) - 1);
        nodename[sizeof(nodename) - 1] = 0;
    }

    dev->nodename = strdup(nodename);
    dev->events = NULL;

    return 0;
}

int blkfront_store_init(struct blkfront_dev *dev)
{
    char* msg = NULL;
    char path[256];
    int ret = 0;

    dev->handle = strtoul(strrchr(dev->nodename, '/') + 1, NULL, 0);

    snprintf(path, sizeof(path), "%s/backend-id", dev->nodename);
    dev->dom = xenbus_read_integer(path);

    snprintf(path, sizeof(path), "%s/backend", dev->nodename);
    msg = xenbus_read(XBT_NIL, path, &dev->backend);
    if (msg) {
        printk("Error %s when reading the backend path %s\n", msg, path);
        free(msg);
        ret = -1;
        goto error;
    }

    printk("backend at %s\n", dev->backend);

error:
    return ret;
}

void blkfront_store_fini(struct blkfront_dev *dev)
{
}

int blkfront_store_front_data_create(struct blkfront_dev *dev)
{
    xenbus_transaction_t xbt;
    char *err;
    char *message = NULL;
    int retry = 0;
    char fe_state_path[256];
    int ret = 0;

again:
    err = xenbus_transaction_start(&xbt);
    if (err) {
        printk("starting transaction\n");
        free(err);
    }

#ifdef CONFIG_BLKFRONT_PERSISTENT_GRANTS
    err = xenbus_printf(xbt, dev->nodename, "feature-persistent", "%u", 1);
    if (err) {
        message = "writing feature-persistent";
        goto abort_transaction;
    }
#endif
    err = xenbus_printf(xbt, dev->nodename, "ring-ref","%u",
                dev->ring_ref);
    if (err) {
        message = "writing ring-ref";
        goto abort_transaction;
    }
    err = xenbus_printf(xbt, dev->nodename,
                "event-channel", "%u", dev->evtchn);
    if (err) {
        message = "writing event-channel";
        goto abort_transaction;
    }
    err = xenbus_printf(xbt, dev->nodename,
                "protocol", "%s", XEN_IO_PROTO_ABI_NATIVE);
    if (err) {
        message = "writing protocol";
        goto abort_transaction;
    }

    /* Switch to Connected */
    snprintf(fe_state_path, sizeof(fe_state_path), "%s/state", dev->nodename);
    err = xenbus_switch_state(xbt, fe_state_path, XenbusStateConnected);
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
    ret = -1;

done:
    free(err);

    return ret;
}

int blkfront_store_front_data_destroy(struct blkfront_dev *dev)
{
    char nodename[strlen(dev->nodename) + strlen("/event-channel") + 1];
    char *err;

    snprintf(nodename, sizeof(nodename), "%s/ring-ref", dev->nodename);
    err = xenbus_rm(XBT_NIL, nodename);
    free(err);

    snprintf(nodename, sizeof(nodename), "%s/event-channel", dev->nodename);
    err = xenbus_rm(XBT_NIL, nodename);
    free(err);

    return 0;
}

int blkfront_store_wait_be_connect(struct blkfront_dev *dev)
{
    XenbusState state;
    char *msg;

    char path[strlen(dev->backend) + strlen("/state") + 1];
    snprintf(path, sizeof(path), "%s/state", dev->backend);

    xenbus_watch_path_token(XBT_NIL, path, path, &dev->events);

    msg = NULL;
    state = xenbus_read_integer(path);
    while (msg == NULL && state < XenbusStateConnected)
        msg = xenbus_wait_for_state_change(path, &state, &dev->events);
    if (msg != NULL || state != XenbusStateConnected) {
        printk("blk backend not available, state=%d\n", state);
        xenbus_unwatch_path_token(XBT_NIL, path, path);
        return -1;
    }

    return 0;
}

int blkfront_store_wait_be_disconnect(struct blkfront_dev *dev)
{
    XenbusState state;
    char *err = NULL, *err2;

    char be_path[strlen(dev->backend)  + strlen("/state") + 1];
    char fe_path[strlen(dev->nodename) + strlen("/state") + 1];

    printk("close network: backend at %s\n",dev->backend);

    snprintf(be_path, sizeof(be_path), "%s/state", dev->backend);
    snprintf(fe_path, sizeof(fe_path), "%s/state", dev->nodename);

    /* Switch to Closing */
    if ((err = xenbus_switch_state(XBT_NIL, fe_path, XenbusStateClosing)) != NULL) {
        printk("shutdown_blkfront: error changing state to %d: %s\n",
                XenbusStateClosing, err);
        goto close;
    }
    /* Wait BE change */
    state = xenbus_read_integer(be_path);
    while (err == NULL && state < XenbusStateClosing)
        err = xenbus_wait_for_state_change(be_path, &state, &dev->events);
    free(err);

    /* Switch to Closed */
    if ((err = xenbus_switch_state(XBT_NIL, fe_path, XenbusStateClosed)) != NULL) {
        printk("shutdown_blkfront: error changing state to %d: %s\n",
                XenbusStateClosed, err);
        goto close;
    }
    /* Wait BE change */
    state = xenbus_read_integer(be_path);
    while (state < XenbusStateClosed) {
        err = xenbus_wait_for_state_change(be_path, &state, &dev->events);
        free(err);
    }

    /* Switch to Initialising */
    if ((err = xenbus_switch_state(XBT_NIL, fe_path, XenbusStateInitialising)) != NULL) {
        printk("shutdown_blkfront: error changing state to %d: %s\n",
                XenbusStateInitialising, err);
        goto close;
    }
    /* Wait BE change */
    state = xenbus_read_integer(be_path);
    while (err == NULL && (state < XenbusStateInitWait || state >= XenbusStateClosed))
        err = xenbus_wait_for_state_change(be_path, &state, &dev->events);

close:
    free(err);
    err2 = xenbus_unwatch_path_token(XBT_NIL, be_path, be_path);
    free(err2);

    return (err != NULL);
}

int blkfront_store_read_be_info(struct blkfront_dev *dev)
{
    char path[strlen(dev->backend) + strlen("/feature-flush-cache") + 1];
    char *msg, *c;
    int ret = 0;


    snprintf(path, sizeof(path), "%s/mode", dev->backend);
    msg = xenbus_read(XBT_NIL, path, &c);
    if (msg) {
        printk("Error %s when reading the mode\n", msg);
        free(msg);
        ret = -1;
        goto error;
    }
    if (*c == 'w')
        dev->info.mode = O_RDWR;
    else
        dev->info.mode = O_RDONLY;
    free(c);

    snprintf(path, sizeof(path), "%s/info", dev->backend);
    dev->info.info = xenbus_read_integer(path);

    snprintf(path, sizeof(path), "%s/sectors", dev->backend);
    // FIXME: read_integer returns an int, so disk size limited to 1TB for now
    dev->info.sectors = xenbus_read_integer(path);

    snprintf(path, sizeof(path), "%s/sector-size", dev->backend);
    dev->info.sector_size = xenbus_read_integer(path);

#ifdef CONFIG_BLKFRONT_PERSISTENT_GRANTS
    snprintf(path, sizeof(path), "%s/feature-persistent", dev->backend);
    if (xenbus_read_integer(path) != 1) {
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

    snprintf(path, sizeof(path), "%s/feature-barrier", dev->backend);
    dev->info.barrier = xenbus_read_integer(path);

    snprintf(path, sizeof(path), "%s/feature-flush-cache", dev->backend);
    dev->info.flush = xenbus_read_integer(path);

error:
    return ret;
}
