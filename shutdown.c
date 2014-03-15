#include <mini-os/os.h>
#include <mini-os/events.h>
#include <mini-os/kernel.h>
#include <mini-os/sched.h>
#include <mini-os/shutdown.h>
#include <mini-os/xenbus.h>
#include <mini-os/xmalloc.h>


static start_info_t *start_info_ptr;

static const char *path = "control/shutdown";
static const char *token = "control/shutdown";
static xenbus_event_queue events = NULL;
static int end_shutdown_thread = 0;

/* This should be overridden by the application we are linked against. */
__attribute__((weak)) void app_shutdown(unsigned reason)
{
    printk("Shutdown requested: %d\n", reason);
}

static void shutdown_thread(void *p)
{
    char *shutdown, *err;
    unsigned int shutdown_reason;

    xenbus_watch_path_token(XBT_NIL, path, token, &events);

    for ( ;; ) {
        xenbus_wait_for_watch(&events);
        if ((err = xenbus_read(XBT_NIL, path, &shutdown))) {
            free(err);
            do_exit();
        }

        if (end_shutdown_thread)
            break;

        if (!strcmp(shutdown, "")) {
            /* Avoid spurious event on xenbus */
            /* FIXME: investigate the reason of the spurious event */
            free(shutdown);
            continue;
        } else if (!strcmp(shutdown, "poweroff")) {
            shutdown_reason = SHUTDOWN_poweroff;
        } else if (!strcmp(shutdown, "reboot")) {
            shutdown_reason = SHUTDOWN_reboot;
        } else if (!strcmp(shutdown, "suspend")) {
            shutdown_reason = SHUTDOWN_suspend;
        } else {
            shutdown_reason = SHUTDOWN_crash;
        }
        free(shutdown);

        /* Acknowledge shutdown request */
        if ((err = xenbus_write(XBT_NIL, path, ""))) {
            free(err);
            do_exit();
        }

        app_shutdown(shutdown_reason);
    }
}

static void fini_shutdown(void)
{
    char *err;

    end_shutdown_thread = 1;
    xenbus_release_wait_for_watch(&events);
    err = xenbus_unwatch_path_token(XBT_NIL, path, token);
    if (err) {
        free(err);
        do_exit();
    }
}

void init_shutdown(start_info_t *si)
{
    start_info_ptr = si;

    end_shutdown_thread = 0;
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
        case SHUTDOWN_suspend:
            reason_str = "suspend";
            break;
        case SHUTDOWN_crash:
            reason_str = "crash";
            break;
        default:
            do_exit();
            break;
    }

    printk("MiniOS will shutdown (reason = %s) ...\n", reason_str);

    fini_shutdown();

    stop_kernel();

    for ( ;; ) {
        struct sched_shutdown sched_shutdown = { .reason = SHUTDOWN_poweroff };
        HYPERVISOR_sched_op(SCHEDOP_shutdown, &sched_shutdown);
    }
}

void kernel_suspend(void)
{
    int rc;

    printk("MiniOS will suspend ...\n");

    pre_suspend();
    arch_pre_suspend();

    /*
     * This hypercall returns 1 if the suspend
     * was cancelled and 0 if resuming in a new domain
     */
    rc = HYPERVISOR_suspend(virt_to_mfn(start_info_ptr));

    arch_post_suspend(rc);
    post_suspend();

    if (rc) {
        printk("MiniOS suspend canceled!");
    } else {
        printk("MiniOS resumed from suspend!\n");
    }
}
