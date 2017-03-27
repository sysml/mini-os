/*
 * noxs.c
 *
 *  Created on: Aug 30, 2016
 *      Author: wolf
 */
#include <inttypes.h>
#include <mini-os/os.h>
#include <mini-os/lib.h>
#include <mini-os/noxs.h>
#include <mini-os/events.h>
#include <mini-os/sched.h>
#include <mini-os/wait.h>
#include <mini-os/xmalloc.h>


#ifdef NOXS_DEBUG
#define DEBUG(_f, _a...) \
    printk("MINI_OS(file=noxs.c, line=%3d) " _f , __LINE__, ## _a)

static const char *const _xenbus_state_str[] = {
    [ XenbusStateUnknown       ] = "Unknown",
    [ XenbusStateInitialising  ] = "Initialising",
    [ XenbusStateInitWait      ] = "InitWait",
    [ XenbusStateInitialised   ] = "Initialised",
    [ XenbusStateConnected     ] = "Connected",
    [ XenbusStateClosing       ] = "Closing",
    [ XenbusStateClosed        ] = "Closed",
    [ XenbusStateReconfiguring ] = "Reconfiguring",
    [ XenbusStateReconfigured  ] = "Reconfigured",
};
static const char *xenbus_state_str(enum xenbus_state s)
{
    return (s < ARRAY_SIZE(_xenbus_state_str)) ? _xenbus_state_str[s] : "INVALID";
}

static const char *const _noxs_dev_type_str[] = {
    [ noxs_dev_none    ] = "None",
    [ noxs_dev_sysctl  ] = "sysctl",
    [ noxs_dev_console ] = "console",
    [ noxs_dev_vif     ] = "vif",
    [ noxs_dev_vbd     ] = "vbd",
};
static const char *noxs_dev_type_str(noxs_dev_type_t t)
{
    return (t < ARRAY_SIZE(_noxs_dev_type_str)) ? _noxs_dev_type_str[t] : "INVALID";
}

#else
#define DEBUG(_f, _a...)    ((void)0)
#endif

static noxs_dev_page_t *noxs_devpage;


void noxs_wait_for_watch(struct noxs_dev_handle *h)
{
    struct noxs_watch_event *event;
    DEFINE_WAIT(w);

    DEBUG("[%d] waiting for watch\n", h->dev_idx);

    while (!(event = h->listener.watch_events)) {
        add_waiter(w, h->listener.watch_waitq);
        schedule();
    }
    remove_waiter(w, h->listener.watch_waitq);
    h->listener.watch_events = event->next;
    free(event);
}

void noxs_wait_for_state_change(struct noxs_dev_handle *h, XenbusState *state)
{
    struct noxs_ctrl_hdr *ctrl_hdr = h->ctrl_page;

    DEBUG("[%d] waiting for state != %s\n",
          h->dev_idx, xenbus_state_str(*state));

    for (;;) {
        if (ctrl_hdr->be_state == *state)
            noxs_wait_for_watch(h);
        else {
            *state = ctrl_hdr->be_state;
            break;
        }
    }
}

void noxs_release_wait_for_watch(struct noxs_dev_handle *h)
{
    struct noxs_watch_event *watch_event;

    watch_event = malloc(sizeof(*watch_event));
    watch_event->next = h->listener.watch_events;
    h->listener.watch_events = watch_event;

    wake_up(&h->listener.watch_waitq);
}

static void noxs_thread_func(void *arg)
{
    struct noxs_dev_handle *h;
    noxs_ctrl_hdr_t *ctrl_hdr;

    h = (struct noxs_dev_handle *) arg;
    ctrl_hdr = h->ctrl_page;

    for (;;) {
        wait_event(h->listener.thread_waitq, \
                h->listener.thread_exit || ctrl_hdr->fe_watch_state == noxs_watch_updated);

        if (h->listener.thread_exit)
            break;

        DEBUG("[%d] Received event be_state=%s.\n",
              h->dev_idx, xenbus_state_str(ctrl_hdr->be_state));

        noxs_release_wait_for_watch(h);
        ctrl_hdr->fe_watch_state = noxs_watch_none;
    }
}

static void noxs_evtchn_handler(evtchn_port_t port, struct pt_regs *regs,
				  void *arg)
{
    struct noxs_dev_handle *h;

    h = (struct noxs_dev_handle *) arg;
    wake_up(&h->listener.thread_waitq);
}

static unsigned long noxs_usage_bm[NOXS_DEV_COUNT_MAX / (8 * sizeof(unsigned long)) + 1];


static void init_noxs_dev_page(void)
{
    noxs_devpage = HYPERVISOR_device_page;
    DEBUG("noxs device page at %p.\n", noxs_devpage);
    DEBUG("dev_count=%d\n", noxs_devpage->dev_count);
}

/* Initialise noxs. */
void init_noxs(void)
{
    DEBUG("init_noxs called.\n");
    init_noxs_dev_page();

    memset(noxs_usage_bm, 0, sizeof(noxs_usage_bm));
}

void fini_noxs(void)
{
    DEBUG("fini_noxs called.\n");
}

void suspend_noxs(void)
{
    /*TODO if (noxs_thread)
        clear_runnable(noxs_thread);*/
}

void resume_noxs(void)
{
    init_noxs_dev_page();

    /*TODO if (noxs_thread)
        set_runnable(noxs_thread);*/
}

static int next_available_index(noxs_dev_type_t type)
{
    int i;
    noxs_dev_page_entry_t *ent;

    for (i = 0; i < noxs_devpage->dev_count; i++) {
        ent = &noxs_devpage->devs[i];

        if (ent->type == type && !synch_const_test_bit(i, &noxs_usage_bm[0]))
            break;
    }

    return i;
}

int noxs_handle_init(struct noxs_dev_handle *h, noxs_dev_type_t type)
{
    int ret, dev_idx;
    noxs_dev_page_entry_t *ent;

    dev_idx = next_available_index(type);
    if (dev_idx == noxs_devpage->dev_count) {
        printk("No available device for type=%d.\n", type);
        goto out_err;
    }

    DEBUG("Device init type=%s, idx=%d, evtchn=%d\n",
          noxs_dev_type_str(type), dev_idx, h->listener.evtchn);

    ent = &noxs_devpage->devs[dev_idx];
    synch_set_bit(dev_idx, &noxs_usage_bm[0]);

    h->dev_idx = dev_idx;
    h->be_id = ent->be_id;

    /* map device page */
    gntmap_init(&h->gntmap);

    uint32_t domids[1] = { ent->be_id };
    uint32_t refs[1] = { ent->comm.grant };
    h->ctrl_page = gntmap_map_grant_refs(&h->gntmap, 1, domids, 1, refs, 1);
    if (!h->ctrl_page) {
        printk("Error mapping grant.\n");
        goto out_err;
    }

    /* bind event channel */
    ret = evtchn_bind_interdomain(ent->be_id, ent->comm.evtchn,
            noxs_evtchn_handler, h, &h->listener.evtchn);
    if (ret) {
        printk("Error binding evtchn.\n");
        goto out_unmap;
    }

    /* create listening thread */
    sprintf(h->listener.thread_name, "noxs-%02d-%02d", dev_idx, type);

    h->listener.thread = create_thread(h->listener.thread_name, noxs_thread_func, h);
    if (!h->listener.thread) {
        printk("Error creating thread.\n");
        goto out_unmap;
    }

    init_waitqueue_head(&h->listener.thread_waitq);

    h->listener.thread_exit = 0;

    init_waitqueue_head(&h->listener.watch_waitq);
    h->listener.watch_events = NULL;

    /* roll it */
    unmask_evtchn(h->listener.evtchn);

    DEBUG("Device initialized.\n");

    return 0;

out_unmap:
    gntmap_munmap(&h->gntmap, (unsigned long) h->ctrl_page, 1);
out_err:
    return -1;
}

int noxs_handle_destroy(struct noxs_dev_handle *h)
{
    mask_evtchn(h->listener.evtchn);
    unbind_evtchn(h->listener.evtchn);

    h->listener.thread_exit = 1;
    wake(h->listener.thread);

    //TODO clear watch_events, clear waitq
    DEBUG("Device destroy idx=%d, evtchn=%d\n", h->dev_idx, h->listener.evtchn);

    /* unmap device page */
    gntmap_munmap(&h->gntmap, (unsigned long) h->ctrl_page, 1);
    h->ctrl_page = NULL;

    gntmap_fini(&h->gntmap);

    synch_clear_bit(h->dev_idx, &noxs_usage_bm[0]);

    return 0;
}

void noxs_handle_watch(struct noxs_dev_handle *h)
{
    noxs_ctrl_hdr_t *ctrl_hdr = h->ctrl_page;

    ctrl_hdr->fe_watch_state = noxs_watch_requested;
}

void noxs_handle_unwatch(struct noxs_dev_handle *h)
{
    noxs_ctrl_hdr_t *ctrl_hdr = h->ctrl_page;

    ctrl_hdr->fe_watch_state = noxs_watch_none;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * End:
 */
