#include <mini-os/os.h>
#include <mini-os/events.h>
#include <mini-os/kernel.h>
#include <mini-os/sched.h>
#include <mini-os/shutdown.h>
#include <mini-os/xenbus.h>
#include <mini-os/xmalloc.h>


/* This should be overridden by the application we are linked against. */
__attribute__((weak)) void app_shutdown(unsigned reason)
{
    printk("Shutdown requested: %d\n", reason);
}

static void shutdown_thread(void *p)
{
    const char *path = "control/shutdown";
    const char *token = path;
    xenbus_event_queue events = NULL;
    char *shutdown, *err;
    unsigned int shutdown_reason;
    xenbus_watch_path_token(XBT_NIL, path, token, &events);
    while ((err = xenbus_read(XBT_NIL, path, &shutdown)) != NULL)
    {
        free(err);
        xenbus_wait_for_watch(&events);
    }
    err = xenbus_unwatch_path_token(XBT_NIL, path, token);
    free(err);
    err = xenbus_write(XBT_NIL, path, "");
    free(err);
    printk("Shutting down (%s)\n", shutdown);

    if (!strcmp(shutdown, "poweroff"))
        shutdown_reason = SHUTDOWN_poweroff;
    else if (!strcmp(shutdown, "reboot"))
        shutdown_reason = SHUTDOWN_reboot;
    else
        /* Unknown */
        shutdown_reason = SHUTDOWN_crash;
    app_shutdown(shutdown_reason);
    free(shutdown);
}

void init_shutdown(void)
{
    create_thread("shutdown", shutdown_thread, NULL);
}

void kernel_shutdown(int reason)
{
    char* reason_str = NULL;

    switch(reason) {
        case SHUTDOWN_poweroff:
            reason_str = "poweroff";
            break;
        case SHUTDOWN_reboot:
            reason_str = "poweroff";
            break;
        case SHUTDOWN_crash:
            reason_str = "crash";
            break;
        default:
            do_exit();
            break;
    }

    printk("MiniOS will shutdown (reason = %s) ...\n", reason_str);

    stop_kernel();

    for ( ;; ) {
        struct sched_shutdown sched_shutdown = { .reason = SHUTDOWN_poweroff };
        HYPERVISOR_sched_op(SCHEDOP_shutdown, &sched_shutdown);
    }
}

