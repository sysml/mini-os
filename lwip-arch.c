/*
 * lwip-arch.c
 *
 * Arch-specific semaphores and mailboxes for lwIP running on mini-os
 *
 * Tim Deegan <Tim.Deegan@eu.citrix.net>, July 2007
 * Simon Kuenzer <Simon.Kuenzer@neclab.eu>, October 2014
 */

#include <os.h>
#include <time.h>
#include <console.h>
#include <xmalloc.h>
#include <lwip/sys.h>
#include <stdarg.h>

#ifndef CONFIG_NETFRONT_PERSISTENT_GRANTS
/* For avoiding that an ether header is splited into two pages. */
#define MIN_ALIGN 64
#else
#define MIN_ALIGN 8
#endif

/* Initializes a new semaphore. The "count" argument specifies
 * the initial state of the semaphore. */
err_t sys_sem_new(sys_sem_t *sem, u8_t count)
{
    init_SEMAPHORE(&sem->sem, count);
    sem->valid = 1;
    return ERR_OK;
}

int sys_sem_valid(sys_sem_t *sem)
{
    return (sem->valid == 1);
}

void sys_sem_set_invalid(sys_sem_t *sem)
{
    sem->valid = 0;
}

/* Deallocates a semaphore. */
void sys_sem_free(sys_sem_t *sem)
{
    /* allocated on stack -> no op */
    sys_sem_set_invalid(sem);
}

/* Signals a semaphore. */
void sys_sem_signal(sys_sem_t *sem)
{
    up(&sem->sem);
}

/* Blocks the thread while waiting for the semaphore to be
 * signaled. If the "timeout" argument is non-zero, the thread should
 * only be blocked for the specified time (measured in
 * milliseconds).
 *
 * If the timeout argument is non-zero, the return value is the number of
 * milliseconds spent waiting for the semaphore to be signaled. If the
 * semaphore wasn't signaled within the specified time, the return value is
 * SYS_ARCH_TIMEOUT. If the thread didn't have to wait for the semaphore
 * (i.e., it was already signaled), the function may return zero. */
u32_t sys_arch_sem_wait(sys_sem_t *sem, u32_t timeout)
{
    /* Slightly more complicated than the normal minios semaphore:
     * need to wake on timeout *or* signal */
    int flags;
    int64_t then = NOW();
    int64_t deadline;

    if (timeout == 0)
	deadline = 0;
    else
	deadline = then + MILLISECS(timeout);

    while(1) {
        wait_event_deadline(sem->sem.wait, (sem->sem.count > 0), deadline);

        local_irq_save(flags);
	/* Atomically check that we can proceed */
	if (sem->sem.count > 0 || (deadline && NOW() >= deadline))
	    break;
        local_irq_restore(flags);
    }

    if (sem->sem.count > 0) {
        sem->sem.count--;
        local_irq_restore(flags);
        return NSEC_TO_MSEC(NOW() - then);
    }

    local_irq_restore(flags);
    return SYS_ARCH_TIMEOUT;
}

/* Creates an empty mailbox. */
err_t sys_mbox_new(sys_mbox_t *mbox, int size)
{
    ASSERT(size >= 0);

    if (!size)
        size = 32;
    mbox->count = size + 1;
    mbox->messages = xmalloc_array(void*, size + 1);
    if (!mbox->messages)
        return ERR_MEM;
    init_SEMAPHORE(&mbox->read_sem, 0);
    mbox->reader = 0;
    init_SEMAPHORE(&mbox->write_sem, size);
    mbox->writer = 0;
    mbox->valid = 1;
    return ERR_OK;
}

int sys_mbox_valid(sys_mbox_t *mbox)
{
    return (mbox->valid == 1);
}

void sys_mbox_set_invalid(sys_mbox_t *mbox)
{
    mbox->valid = 0;
}

/* Deallocates a mailbox. If there are messages still present in the
 * mailbox when the mailbox is deallocated, it is an indication of a
 * programming error in lwIP and the developer should be notified. */
void sys_mbox_free(sys_mbox_t *mbox)
{
    ASSERT(mbox->reader == mbox->writer);
    sys_mbox_set_invalid(mbox);
    if (mbox->messages) {
        xfree(mbox->messages);
        mbox->messages = NULL;
    }
}

/* Posts the "msg" to the mailbox, internal version that actually does the
 * post. */
static void do_mbox_post(sys_mbox_t *mbox, void *msg)
{
    /* The caller got a semaphore token, so we are now allowed to increment
     * writer, but we still need to prevent concurrency between writers
     * (interrupt handler vs main) */
    int flags;

    local_irq_save(flags);
    mbox->messages[mbox->writer] = msg;
    mbox->writer = (mbox->writer + 1) % mbox->count;
    ASSERT(mbox->reader != mbox->writer);
    local_irq_restore(flags);
    up(&mbox->read_sem);
}

/* Posts the "msg" to the mailbox. */
void sys_mbox_post(sys_mbox_t *mbox, void *msg)
{
    down(&mbox->write_sem);
    do_mbox_post(mbox, msg);
}

/* Try to post the "msg" to the mailbox. */
err_t sys_mbox_trypost(sys_mbox_t *mbox, void *msg)
{
    if (!trydown(&mbox->write_sem))
        return ERR_MEM;
    do_mbox_post(mbox, msg);
    return ERR_OK;
}

/*
 * Fetch a message from a mailbox. Internal version that actually does the
 * fetch.
 */
static void do_mbox_fetch(sys_mbox_t *mbox, void **msg)
{
    /* The caller got a semaphore token, so we are now allowed to increment
     * reader, but we may still need to prevent concurrency between readers.
     * FIXME: can there be concurrent readers? */
    int flags;

    local_irq_save(flags);
    ASSERT(mbox->reader != mbox->writer);
    if (msg != NULL)
        *msg = mbox->messages[mbox->reader];
    mbox->reader = (mbox->reader + 1) % mbox->count;
    local_irq_restore(flags);
    up(&mbox->write_sem);
}

/* Blocks the thread until a message arrives in the mailbox, but does
 * not block the thread longer than "timeout" milliseconds (similar to
 * the sys_arch_sem_wait() function). The "msg" argument is a result
 * parameter that is set by the function (i.e., by doing "*msg =
 * ptr"). The "msg" parameter maybe NULL to indicate that the message
 * should be dropped.
 *
 * The return values are the same as for the sys_arch_sem_wait() function:
 * Number of milliseconds spent waiting or SYS_ARCH_TIMEOUT if there was a
 * timeout. */
u32_t sys_arch_mbox_fetch(sys_mbox_t *mbox, void **msg, u32_t timeout)
{
    int flags;
    int64_t then = NOW();
    int64_t deadline;

    if (timeout == 0)
	deadline = 0;
    else
	deadline = then + MILLISECS(timeout);

    while(1) {
        wait_event_deadline(mbox->read_sem.wait, (mbox->read_sem.count > 0), deadline);

        local_irq_save(flags);
	/* Atomically check that we can proceed */
	if (mbox->read_sem.count > 0 || (deadline && NOW() >= deadline))
	    break;
        local_irq_restore(flags);
    }

    if (mbox->read_sem.count <= 0) {
      local_irq_restore(flags);
      return SYS_ARCH_TIMEOUT;
    }

    mbox->read_sem.count--;
    local_irq_restore(flags);
    do_mbox_fetch(mbox, msg);
    return 0;
}

/* This is similar to sys_arch_mbox_fetch, however if a message is not
 * present in the mailbox, it immediately returns with the code
 * SYS_MBOX_EMPTY. On success 0 is returned.
 *
 * To allow for efficient implementations, this can be defined as a
 * function-like macro in sys_arch.h instead of a normal function. For
 * example, a naive implementation could be:
 *   #define sys_arch_mbox_tryfetch(mbox,msg) \
 *     sys_arch_mbox_fetch(mbox,msg,1)
 * although this would introduce unnecessary delays. */

u32_t sys_arch_mbox_tryfetch(sys_mbox_t *mbox, void **msg) {
    if (!trydown(&mbox->read_sem))
	return SYS_MBOX_EMPTY;

    do_mbox_fetch(mbox, msg);
    return 0;
}

/* Starts a new thread with priority "prio" that will begin its execution in the
 * function "thread()". The "arg" argument will be passed as an argument to the
 * thread() function. The id of the new thread is returned. Both the id and
 * the priority are system dependent. */
sys_thread_t sys_thread_new(const char *name, lwip_thread_fn thread, void *arg, int stacksize, int prio)
{
    static struct thread *t;
    if (stacksize > STACK_SIZE) {
	printk("Can't start lwIP thread: stack size %d is too large for our %d\n", stacksize, STACK_SIZE);
	do_exit();
    }
    t = create_thread((char *) name, thread, arg);
    return t;
}

/* This function is called before the any other sys_arch-function is
 * called and is meant to be used to initialize anything that has to
 * be up and running for the rest of the functions to work. for
 * example to set up a pool of semaphores. */
void sys_init(void)
{
    return;
}

u32_t sys_now(void)
{
    return ((u32_t) NOW());
}

#if MEM_LIBC_MALLOC
/* mini-os malloc/free wrapper */
#include <limits.h> /* required by <mini-os/xmalloc.h> */
#include <mini-os/xmalloc.h>

void *lwip_malloc(size_t size)
{
    void *obj = _xmalloc(size, MIN_ALIGN);
#ifdef LWIP_DEBUG_MALLOC
    printk("lwip-malloc: %p, %lu B\n", obj, size);
#endif
    return obj;
}

void *lwip_calloc(int num, size_t size)
{
    void *obj = _xmalloc((size) * (num), MIN_ALIGN);
#ifdef LWIP_DEBUG_MALLOC
    printk("lwip-calloc: %p, %d * %lu B (= %lu B)\n", obj, num, size, num * size);
#endif
    if(obj)
        memset(obj, 0, (num) * (size));
    return obj;
}

void lwip_free(void *ptr)
{
#ifdef LWIP_DEBUG_MALLOC
    printk("lwip-free:   %p\n", ptr);
#endif
    xfree(ptr);
}
#endif
