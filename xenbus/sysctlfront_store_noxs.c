#include <mini-os/os.h>
#include <mini-os/noxs.h>
#include <mini-os/xmalloc.h>
#include <mini-os/sysctlfront.h>
#include <mini-os/events.h>
#include <mini-os/lib.h>

static noxs_sysctl_ctrl_page_t *sysctl_page = NULL;
static struct noxs_dev_handle noxs_dev_handle;


static int sysctlfront_store_wait_be_connect(struct noxs_dev_handle *h)
{
    noxs_sysctl_ctrl_page_t *ctrl_page;
    XenbusState state;
    int ret;

    ctrl_page = h->ctrl_page;

    /* Switch to Connected */
    noxs_handle_watch(h);
    ctrl_page->hdr.fe_state = XenbusStateConnected;
    ret = notify_remote_via_evtchn(h->listener.evtchn);
    if (ret) {
        noxs_handle_unwatch(h);
        return -1;
    }
    /* Wait BE change */
    state = ctrl_page->hdr.be_state;
    while (state < XenbusStateConnected)
        noxs_wait_for_state_change(h, &state);

    if (state != XenbusStateConnected) {
        printk("sysctl backend not available, state=%d\n", state);
        noxs_handle_unwatch(h);//TODO ??
        return -1;
    }

    return 0;
}

static int sysctlfront_store_wait_be_disconnect(struct noxs_dev_handle *h)
{
    noxs_sysctl_ctrl_page_t *ctrl_page;
    XenbusState state;
    int ret;

    ctrl_page = h->ctrl_page;

    /* Switch to Closing */
    noxs_handle_watch(h);
    ctrl_page->hdr.fe_state = XenbusStateClosing;
    ret = notify_remote_via_evtchn(h->listener.evtchn);
    if (ret)
        goto out;
    /* Wait BE change */
    state = ctrl_page->hdr.be_state;
    while (state < XenbusStateClosing)
        noxs_wait_for_state_change(h, &state);

    /* Switch to Closed */
    noxs_handle_watch(h);
    ctrl_page->hdr.fe_state = XenbusStateClosed;
    ret = notify_remote_via_evtchn(h->listener.evtchn);
    if (ret)
        goto out;
    /* Wait BE change */
    state = ctrl_page->hdr.be_state;
    while (state < XenbusStateClosed)
        noxs_wait_for_state_change(h, &state);

    /* Switch to Initialising */
    noxs_handle_watch(h);
    ctrl_page->hdr.fe_state = XenbusStateInitialising;
    ret = notify_remote_via_evtchn(h->listener.evtchn);
    if (ret)
        goto out;
    /* Wait BE change */
    state = ctrl_page->hdr.be_state;
    while (state < XenbusStateInitWait || state >= XenbusStateClosed)
        noxs_wait_for_state_change(h, &state);

out:
    noxs_handle_unwatch(h);

    return ret;
}

int sysctlfront_store_init(void)
{
    if (noxs_handle_init(&noxs_dev_handle, noxs_dev_sysctl) != 0)
        return -1;

    sysctl_page = noxs_dev_handle.ctrl_page;
    sysctl_page->status = 0;

    return sysctlfront_store_wait_be_connect(&noxs_dev_handle);
}

void sysctlfront_store_fini(void)
{
    sysctlfront_store_wait_be_disconnect(&noxs_dev_handle);
    noxs_handle_destroy(&noxs_dev_handle);
    sysctl_page = NULL;
}

static int stop_waiting = 0;

int sysctlfront_store_wait(void)
{
    noxs_handle_watch(&noxs_dev_handle);

    while (!stop_waiting && sysctl_page->status == 0)
        noxs_wait_for_watch(&noxs_dev_handle);

    noxs_handle_unwatch(&noxs_dev_handle);

    if (stop_waiting)
        return -1;

    noxs_handle_watch(&noxs_dev_handle);

    if (sysctl_page->bits.poweroff)
        return SHUTDOWN_poweroff;
    else if (sysctl_page->bits.reboot)
        return SHUTDOWN_reboot;
    else if (sysctl_page->bits.suspend)
        return SHUTDOWN_suspend;
    else if (sysctl_page->bits.watchdog)
        return SHUTDOWN_watchdog;
    else
        return SHUTDOWN_crash;
}

void sysctlfront_store_stop_waiting(void)
{
    stop_waiting = 1;
    noxs_release_wait_for_watch(&noxs_dev_handle);
}
