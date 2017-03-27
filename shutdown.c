/*
 *          MiniOS
 *
 *   file: fromdevice.cc
 *
 *          NEC Europe Ltd. PROPRIETARY INFORMATION
 *
 * This software is supplied under the terms of a license agreement
 * or nondisclosure agreement with NEC Europe Ltd. and may not be
 * copied or disclosed except in accordance with the terms of that
 * agreement. The software and its source code contain valuable trade
 * secrets and confidential information which have to be maintained in
 * confidence.
 * Any unauthorized publication, transfer to third parties or duplication
 * of the object or source code - either totally or in part – is
 * prohibited.
 *
 *      Copyright (c) 2014 NEC Europe Ltd. All Rights Reserved.
 *
 * Authors: Filipe Manco <filipe.manco@neclab.eu>
 *
 * NEC Europe Ltd. DISCLAIMS ALL WARRANTIES, EITHER EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE AND THE WARRANTY AGAINST LATENT
 * DEFECTS, WITH RESPECT TO THE PROGRAM AND THE ACCOMPANYING
 * DOCUMENTATION.
 *
 * No Liability For Consequential Damages IN NO EVENT SHALL NEC Europe
 * Ltd., NEC Corporation OR ANY OF ITS SUBSIDIARIES BE LIABLE FOR ANY
 * DAMAGES WHATSOEVER (INCLUDING, WITHOUT LIMITATION, DAMAGES FOR LOSS
 * OF BUSINESS PROFITS, BUSINESS INTERRUPTION, LOSS OF INFORMATION, OR
 * OTHER PECUNIARY LOSS AND INDIRECT, CONSEQUENTIAL, INCIDENTAL,
 * ECONOMIC OR PUNITIVE DAMAGES) ARISING OUT OF THE USE OF OR INABILITY
 * TO USE THIS PROGRAM, EVEN IF NEC Europe Ltd. HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 *
 *     THIS HEADER MAY NOT BE EXTRACTED OR MODIFIED IN ANY WAY.
 */
#include <mini-os/os.h>
#include <mini-os/events.h>
#include <mini-os/kernel.h>
#include <mini-os/sched.h>
#include <mini-os/shutdown.h>
#include <mini-os/sysctlfront.h>
#include <mini-os/xmalloc.h>


static start_info_t *start_info_ptr;
static struct thread* _thread = NULL;

/* This should be overridden by the application we are linked against. */
__attribute__((weak)) void app_shutdown(unsigned reason)
{
    printk("Shutdown requested: %d\n", reason);
}

static void shutdown_thread(void *p)
{
    int shutdown_reason;

    for ( ;; ) {

        sysctlfront_store_init();
        shutdown_reason = sysctlfront_store_wait();
        sysctlfront_store_fini();

        if (shutdown_reason < 0)
            continue;

        app_shutdown(shutdown_reason);

        if (shutdown_reason != SHUTDOWN_suspend)
            break;

        clear_runnable(_thread);
        schedule();
    }
}

static void fini_shutdown(void)
{
    sysctlfront_store_stop_waiting();
}

void init_shutdown(start_info_t *si)
{
    start_info_ptr = si;

    _thread = create_thread("shutdown", shutdown_thread, NULL);
}

void kernel_shutdown(int reason)
{
    char* reason_str = NULL;

    switch(reason) {
        case SHUTDOWN_poweroff:
            reason_str = "poweroff";
            break;
        case SHUTDOWN_reboot:
            reason_str = "reboot";
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
        struct sched_shutdown sched_shutdown = { .reason = reason };
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
    post_suspend(rc);

    wake(_thread);

    if (rc) {
        printk("MiniOS suspend canceled!\n");
    } else {
        printk("MiniOS resumed from suspend!\n");
    }
}
