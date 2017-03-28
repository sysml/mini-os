/*
 * netfront_store_xenbus.c
 *
 *  Created on: Oct 10, 2016
 *      Author: wolf
 */

#include <mini-os/netfront.h>
#include <mini-os/xmalloc.h>


static int netfrontends = 0;


int netfront_store_dev_matches_id(struct netfront_dev *dev, void *store_id)
{
    int ret;

    ret = -1;

    if (dev && store_id) {
        ret = strcmp(dev->nodename, (char *) store_id);
    }

    return (ret == 0);
}

const char *netfront_store_dev_name(struct netfront_dev *dev)
{
    return dev->nodename;
}

int netfront_store_pre(struct netfront_dev *dev, void *store_id)
{
    char nodename[256];

    if (!store_id) {
        /* allocate new frontend id */
        snprintf(nodename, sizeof(nodename), "device/vif/%d", netfrontends);
        netfrontends++;

    } else {
        strncpy(nodename, (char *) store_id, sizeof(nodename) - 1);
        nodename[sizeof(nodename) - 1] = 0;
    }

    dev->nodename = strdup(nodename);
    dev->events = NULL;

    return 0;
}

void netfront_store_post(struct netfront_dev *dev)
{
    if (dev->nodename) {
        free(dev->nodename);
        dev->nodename = NULL;
    }
}

int netfront_store_init(struct netfront_dev *dev, int *is_split_evtchn)
{
    char* msg = NULL;
    char path[256];

    snprintf(path, sizeof(path), "%s/backend-id", dev->nodename);
    dev->dom = xenbus_read_integer(path);

    snprintf(path, sizeof(path), "%s/backend", dev->nodename);
    msg = xenbus_read(XBT_NIL, path, &dev->backend);
    free(msg);

    snprintf(path, sizeof(path), "%s/mac", dev->nodename);
    msg = xenbus_read(XBT_NIL, path, &dev->mac);
    free(msg);

    if ((dev->backend == NULL) || (dev->mac == NULL)) {
        printk("%s: backend/mac failed\n", __func__);
        return -1;
    }

    printk("backend at %s\n",dev->backend);
    printk("mac is %s\n",dev->mac);

#ifdef CONFIG_NETMAP
    snprintf(path, sizeof(path), "%s/feature-netmap", dev->backend);
    dev->netmap = xenbus_read_integer(path) > 0 ? 1 : 0;
#endif
    if (is_split_evtchn) {
        /* Check feature-split-event-channels */
        snprintf(path, sizeof(path), "%s/feature-split-event-channels",
                dev->backend);
        *is_split_evtchn = xenbus_read_integer(path) > 0 ? 1 : 0;
    }

    return 0;
}

void netfront_store_fini(struct netfront_dev *dev)
{
    if (dev->backend) {
        free(dev->backend);
        dev->backend = NULL;
    }
    if (dev->mac) {
        free(dev->mac);
        dev->mac = NULL;
    }
}

int netfront_store_front_data_create(struct netfront_dev *dev, int split_evtchn)
{
    xenbus_transaction_t xbt;
    char *err;
    char *message = NULL;
    int retry = 0;
    char path[256];
    int ret = 0;

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

    if (split_evtchn) {
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
    err = xenbus_transaction_end(xbt, 1, &retry);
    printk("Abort transaction %s\n", message);
    ret = -1;
done:
    free(err);

    return ret;
}

int netfront_store_front_data_destroy(struct netfront_dev *dev)
{
    char nodename[strlen(dev->nodename) + strlen("/request-rx-copy") + 1];
    char *err;

    snprintf(nodename, sizeof(nodename), "%s/tx-ring-ref", dev->nodename);
    err = xenbus_rm(XBT_NIL, nodename);
    free(err);

    snprintf(nodename, sizeof(nodename), "%s/rx-ring-ref", dev->nodename);
    err = xenbus_rm(XBT_NIL, nodename);
    free(err);

    snprintf(nodename, sizeof(nodename), "%s/event-channel", dev->nodename);
    err = xenbus_rm(XBT_NIL, nodename);
    free(err);

    snprintf(nodename, sizeof(nodename), "%s/request-rx-copy", dev->nodename);
    err = xenbus_rm(XBT_NIL, nodename);
    free(err);

    return 0;
}

int netfront_store_wait_be_connect(struct netfront_dev *dev)
{
    XenbusState state;
    char *err;

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
        return -1;
    }

    return 0;
}

int netfront_store_wait_be_disconnect(struct netfront_dev *dev)
{
    XenbusState state;
    char *err = NULL, *err2;

    char path[strlen(dev->backend) + strlen("/state") + 1];
    char nodename[strlen(dev->nodename) + strlen("/request-rx-copy") + 1];

    printk("close network: backend at %s\n",dev->backend);

    snprintf(path, sizeof(path), "%s/state", dev->backend);
    snprintf(nodename, sizeof(nodename), "%s/state", dev->nodename);

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

    return (err != NULL);
}

int netfront_store_read_mac(struct netfront_dev *dev, unsigned char rawmac[6])
{
    int rc;

    /* Special conversion specifier 'hh' needed for __ia64__. Without
       this mini-os panics with 'Unaligned reference'. */
    rc = sscanf(dev->mac,"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
            &rawmac[0],
            &rawmac[1],
            &rawmac[2],
            &rawmac[3],
            &rawmac[4],
            &rawmac[5]);

    return -(rc != 6);
}

void netfront_store_read_ip(struct netfront_dev *dev, void *out)
{
    char path[256];
    char **ip = (char **) out;

    snprintf(path, sizeof(path), "%s/ip", dev->backend);
    xenbus_read(XBT_NIL, path, ip);
}
