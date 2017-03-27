#include <mini-os/os.h>
#include <mini-os/xenbus.h>
#include <mini-os/xmalloc.h>
#include <mini-os/sysctlfront.h>
#include <mini-os/lib.h>

#define SYSCTL_PATH "control/shutdown"

static int sysctl_init = 0;
static xenbus_event_queue events = NULL;

int sysctlfront_store_init(void)
{
    if (sysctl_init)
        return -1;

    xenbus_watch_path_token(XBT_NIL, SYSCTL_PATH, SYSCTL_PATH, &events);
    sysctl_init = 1;

    return 0;
}

void sysctlfront_store_fini(void)
{
    char *err;

    if (!sysctl_init)
        return;

    err = xenbus_unwatch_path_token(XBT_NIL, SYSCTL_PATH, SYSCTL_PATH);
    if (err) {
        free(err);
        do_exit();
    }

    sysctl_init = 0;
}

static int stop_waiting = 0;

int sysctlfront_store_wait(void)
{
    char *shutdown = NULL, *err;
    int shutdown_reason;

    while (!stop_waiting &&
           ((err = xenbus_read(XBT_NIL, SYSCTL_PATH, &shutdown)) != NULL || !strcmp(shutdown, "")))
    {
        if (err) {
            free(err);
            do_exit();
        }
        if (shutdown) {
            /* Avoid spurious event on xenbus (shutdown == "") */
            /* FIXME: investigate the reason of the spurious event */
            free(shutdown);
            shutdown = NULL;
        }
        xenbus_wait_for_watch(&events);
    }

    if (stop_waiting)
        return -1;

    printk("Shutting down (%s)\n", shutdown);

    if (!strcmp(shutdown, "poweroff"))
        shutdown_reason = SHUTDOWN_poweroff;
    else if (!strcmp(shutdown, "reboot"))
        shutdown_reason = SHUTDOWN_reboot;
    else if (!strcmp(shutdown, "suspend"))
        shutdown_reason = SHUTDOWN_suspend;
    else
        /* Unknown */
        shutdown_reason = SHUTDOWN_crash;

    free(shutdown);

    /* Acknowledge shutdown request */
    err = xenbus_write(XBT_NIL, SYSCTL_PATH, "");
    if (err) {
        free(err);
        do_exit();
    }

    return shutdown_reason;
}

void sysctlfront_store_stop_waiting(void)
{
    stop_waiting = 1;
    xenbus_release_wait_for_watch(&events);
}
