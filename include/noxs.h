#ifndef NOXS_H__
#define NOXS_H__

#include <xen/io/noxs.h>
#include <mini-os/os.h>
#include <mini-os/gntmap.h>
#include <mini-os/waittypes.h>


#ifdef CONFIG_NOXS
/* Initialize the noxs system. */
void init_noxs(void);
/* Reset the noxs system. */
void fini_noxs(void);

void suspend_noxs(void);
void resume_noxs(void);
#else
static inline void get_noxs(void *p)
{
}
static inline void init_noxs(void)
{
}
static inline void fini_noxs(void)
{
}
static inline void suspend_noxs(void)
{
}
static inline void resume_noxs(void)
{
}
#endif

/* Watch event queue */
struct noxs_watch_event {
    struct noxs_watch_event *next;
};
typedef struct noxs_watch_event *noxs_watch_event_queue;

struct noxs_event_listener {
    evtchn_port_t evtchn;

    char thread_name[16];
    struct thread *thread;
    struct wait_queue_head thread_waitq;
    int thread_exit;

    struct wait_queue_head watch_waitq;
    noxs_watch_event_queue watch_events;
};

struct noxs_dev_handle {
    uint16_t dev_idx;
    domid_t be_id;
    struct gntmap gntmap;
    void *ctrl_page;
    struct noxs_event_listener listener;
};

int noxs_handle_init(struct noxs_dev_handle *h, noxs_dev_type_t type);
int noxs_handle_destroy(struct noxs_dev_handle *h);
void noxs_handle_watch(struct noxs_dev_handle *h);
void noxs_handle_unwatch(struct noxs_dev_handle *h);
void noxs_wait_for_watch(struct noxs_dev_handle *h);
void noxs_wait_for_state_change(struct noxs_dev_handle *h, XenbusState *state);
void noxs_release_wait_for_watch(struct noxs_dev_handle *h);

#if 0
/* Utility function to figure out our domain id */
domid_t xenbus_get_self_id(void);

#endif

#endif /* NOXS_H__ */
