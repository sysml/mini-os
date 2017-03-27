/* Minimal block driver for Mini-OS. 
 * Copyright (c) 2007-2008 Samuel Thibault.
 * Based on netfront.c.
 */

#include <stdint.h>
#include <mini-os/os.h>
#include <mini-os/xenbus.h>
#include <mini-os/events.h>
#include <errno.h>
#include <xen/io/blkif.h>
#include <xen/io/protocols.h>
#include <mini-os/gnttab.h>
#include <mini-os/xmalloc.h>
#include <time.h>
#include <mini-os/blkfront.h>
#include <mini-os/lib.h>
#include <fcntl.h>
#if (defined CONFIG_BLKFRONT_PERSISTENT_GRANTS) && (defined __SSE2__)
#include <xmmintrin.h> /* SSE */
#include <emmintrin.h> /* SSE2 */
#endif

#ifndef HAVE_LIBC
#define strtoul simple_strtoul
#endif

/* Note: we generally don't need to disable IRQs since we hardly do anything in
 * the interrupt handler.  */

/* Note: we really suppose non-preemptive threads.  */

DECLARE_WAIT_QUEUE_HEAD(blkfront_queue);




#define BLK_RING_SIZE __RING_SIZE((struct blkif_sring *)0, PAGE_SIZE)
#define GRANT_INVALID_REF 0
#ifdef CONFIG_BLKFRONT_PERSISTENT_GRANTS
#define BLK_BUFFER_PAGES_N BLK_RING_SIZE * BLKIF_MAX_PRSNT_GNT_SEGMENTS_PER_REQUEST
#else
#define BLK_BUFFER_PAGES_N BLK_RING_SIZE * BLKIF_MAX_SEGMENTS_PER_REQUEST
#endif

struct blk_buffer {
    void* page;
    grant_ref_t gref;
#ifdef CONFIG_BLKFRONT_PERSISTENT_GRANTS
    int inflight;
#endif
};

void blkfront_handler(evtchn_port_t port, struct pt_regs *regs, void *data)
{
#ifdef HAVE_LIBC
    struct blkfront_dev *dev = data;
    int fd = dev->fd;

    if (fd != -1)
        files[fd].read = 1;
#endif
    wake_up(&blkfront_queue);
}

static void free_blkfront(struct blkfront_dev *dev)
{
#ifdef CONFIG_BLKFRONT_PERSISTENT_GRANTS
	int iter;
	if (dev->pt_pool != NULL) {
		for (iter = 0; iter < BLK_BUFFER_PAGES_N; iter++) {
			if (dev->pt_pool[iter].inflight)
				printk("gnttab_end_access %d -- %u\n", iter, dev->pt_pool[iter].gref);
			gnttab_end_access(dev->pt_pool[iter].gref);
			free_page(dev->pt_pool[iter].page);
		}
		free(dev->pt_pool);
	}
#endif
    mask_evtchn(dev->evtchn);

    free(dev->backend);

    gnttab_end_access(dev->ring_ref);
    free_page(dev->ring.sring);

    unbind_evtchn(dev->evtchn);

    free(dev->nodename);
    free(dev);
}

struct blkfront_dev *init_blkfront(char *_nodename, struct blkfront_info *info)
{
    xenbus_transaction_t xbt;
    char* err;
    char* message=NULL;
    struct blkif_sring *s;
    int retry=0;
    char* msg = NULL;
    char* c;
    char* nodename = _nodename ? _nodename : "device/vbd/768";

    struct blkfront_dev *dev;

    char path[strlen(nodename) + strlen("/backend-id") + 1];

    printk("******************* BLKFRONT for %s **********\n\n\n", nodename);

    dev = malloc(sizeof(*dev));
    memset(dev, 0, sizeof(*dev));
    dev->nodename = strdup(nodename);
#ifdef HAVE_LIBC
    dev->fd = -1;
#endif

    snprintf(path, sizeof(path), "%s/backend-id", nodename);
    dev->dom = xenbus_read_integer(path); 
    evtchn_alloc_unbound(dev->dom, blkfront_handler, dev, &dev->evtchn);

    s = (struct blkif_sring*) alloc_page();
    memset(s,0,PAGE_SIZE);


    SHARED_RING_INIT(s);
    FRONT_RING_INIT(&dev->ring, s, PAGE_SIZE);

#ifdef CONFIG_BLKFRONT_PERSISTENT_GRANTS
    int iter;
    dev->pt_pool = xmalloc_array(struct blk_buffer, BLK_BUFFER_PAGES_N);
    for (iter = 0; iter < BLK_BUFFER_PAGES_N; iter++) {
        dev->pt_pool[iter].page = (char*)alloc_page();
        *(char*)(dev->pt_pool[iter].page) = 0; /* Trigger CoW if needed */
        barrier();
        dev->pt_pool[iter].gref = gnttab_grant_access(dev->dom, virt_to_mfn(dev->pt_pool[iter].page), 0);
        dev->pt_pool[iter].inflight = 0;
    }
    printk("persistent grants: %d pages allocated, %d KB overhead, max %d pages per request\n",
           BLK_BUFFER_PAGES_N, (BLK_BUFFER_PAGES_N * (sizeof(struct blk_buffer) + PAGE_SIZE)) / 1024, BLKIF_MAX_PRSNT_GNT_SEGMENTS_PER_REQUEST);
#endif

    dev->ring_ref = gnttab_grant_access(dev->dom,virt_to_mfn(s),0);

    dev->events = NULL;

again:
    err = xenbus_transaction_start(&xbt);
    if (err) {
        printk("starting transaction\n");
        free(err);
    }

#ifdef CONFIG_BLKFRONT_PERSISTENT_GRANTS
    err = xenbus_printf(xbt, nodename, "feature-persistent", "%u", 1);
    if (err) {
        message = "writing feature-persistent";
        goto abort_transaction;
    }
#endif
    err = xenbus_printf(xbt, nodename, "ring-ref","%u",
                dev->ring_ref);
    if (err) {
        message = "writing ring-ref";
        goto abort_transaction;
    }
    err = xenbus_printf(xbt, nodename,
                "event-channel", "%u", dev->evtchn);
    if (err) {
        message = "writing event-channel";
        goto abort_transaction;
    }
    err = xenbus_printf(xbt, nodename,
                "protocol", "%s", XEN_IO_PROTO_ABI_NATIVE);
    if (err) {
        message = "writing protocol";
        goto abort_transaction;
    }

    snprintf(path, sizeof(path), "%s/state", nodename);
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
    free(err);
    err = xenbus_transaction_end(xbt, 1, &retry);
    printk("Abort transaction %s\n", message);
    goto error;

done:

    snprintf(path, sizeof(path), "%s/backend", nodename);
    msg = xenbus_read(XBT_NIL, path, &dev->backend);
    if (msg) {
        printk("Error %s when reading the backend path %s\n", msg, path);
        goto error;
    }

    printk("backend at %s\n", dev->backend);

    dev->handle = strtoul(strrchr(nodename, '/')+1, NULL, 0);

    {
        XenbusState state;
        char path[strlen(dev->backend) + strlen("/feature-flush-cache") + 1];
        snprintf(path, sizeof(path), "%s/mode", dev->backend);
        msg = xenbus_read(XBT_NIL, path, &c);
        if (msg) {
            printk("Error %s when reading the mode\n", msg);
            goto error;
        }
        if (*c == 'w')
            dev->info.mode = O_RDWR;
        else
            dev->info.mode = O_RDONLY;
        free(c);

        snprintf(path, sizeof(path), "%s/state", dev->backend);

        xenbus_watch_path_token(XBT_NIL, path, path, &dev->events);

        msg = NULL;
        state = xenbus_read_integer(path);
        while (msg == NULL && state < XenbusStateConnected)
            msg = xenbus_wait_for_state_change(path, &state, &dev->events);
        if (msg != NULL || state != XenbusStateConnected) {
            printk("backend not available, state=%d\n", state);
            xenbus_unwatch_path_token(XBT_NIL, path, path);
            goto error;
        }

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
            goto error;
        }

        /* fast copy only usable if devices sector size is multiple of 256 */
        if (dev->info.sector_size & 0xFF) {
            printk("unsupported device sector size: %d\n", dev->info.sector_size);
            goto error;
        }
#endif

        snprintf(path, sizeof(path), "%s/feature-barrier", dev->backend);
        dev->info.barrier = xenbus_read_integer(path);

        snprintf(path, sizeof(path), "%s/feature-flush-cache", dev->backend);
        dev->info.flush = xenbus_read_integer(path);

        *info = dev->info;
    }
    unmask_evtchn(dev->evtchn);

    printk("%u sectors of %u bytes\n", dev->info.sectors, dev->info.sector_size);
    printk("**************************\n");

    return dev;

error:
    free(msg);
    free(err);
    free_blkfront(dev);
    return NULL;
}

void shutdown_blkfront(struct blkfront_dev *dev)
{
    char* err = NULL, *err2;
    XenbusState state;

    char path[strlen(dev->backend) + strlen("/state") + 1];
    char nodename[strlen(dev->nodename) + strlen("/event-channel") + 1];

    blkfront_sync(dev);

    printk("close blk: backend=%s node=%s\n", dev->backend, dev->nodename);

    snprintf(path, sizeof(path), "%s/state", dev->backend);
    snprintf(nodename, sizeof(nodename), "%s/state", dev->nodename);

    if ((err = xenbus_switch_state(XBT_NIL, nodename, XenbusStateClosing)) != NULL) {
        printk("shutdown_blkfront: error changing state to %d: %s\n",
                XenbusStateClosing, err);
        goto close;
    }
    state = xenbus_read_integer(path);
    while (err == NULL && state < XenbusStateClosing)
        err = xenbus_wait_for_state_change(path, &state, &dev->events);
    free(err);

    if ((err = xenbus_switch_state(XBT_NIL, nodename, XenbusStateClosed)) != NULL) {
        printk("shutdown_blkfront: error changing state to %d: %s\n",
                XenbusStateClosed, err);
        goto close;
    }
    state = xenbus_read_integer(path);
    while (state < XenbusStateClosed) {
        err = xenbus_wait_for_state_change(path, &state, &dev->events);
        free(err);
    }

    if ((err = xenbus_switch_state(XBT_NIL, nodename, XenbusStateInitialising)) != NULL) {
        printk("shutdown_blkfront: error changing state to %d: %s\n",
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

    snprintf(nodename, sizeof(nodename), "%s/ring-ref", dev->nodename);
    err2 = xenbus_rm(XBT_NIL, nodename);
    free(err2);
    snprintf(nodename, sizeof(nodename), "%s/event-channel", dev->nodename);
    err2 = xenbus_rm(XBT_NIL, nodename);
    free(err2);

    if (!err)
        free_blkfront(dev);
}

#ifdef CONFIG_BLKFRONT_PERSISTENT_GRANTS
/* fast memcpy version for 256-bytes aligned buffers
 * Note: len has to be a multiple of 256  */
#include <inttypes.h>
static inline void _fmemcpy256(void *dst, const void *src, size_t len)
{
#if (defined __SSE2__) && (!defined DEBUG_BUILD)
#warning "SSE2-based memcpy enabled for persistent grants"
#define __ptr_offset(ptr, size, idx) \
  ((uintptr_t)(ptr) + ((idx) * (size)))

    __m128i s128;

    ASSERT(((uintptr_t)src & 0x0F) == 0);
    ASSERT(((uintptr_t)dst & 0x0F) == 0);
    ASSERT((len & 0xFF) == 0);

    while (len) {
        s128 = _mm_load_si128((const __m128i *)(__ptr_offset(src, 16, 0)));
        _mm_store_si128((__m128i *)(__ptr_offset(dst, 16, 0)), s128);
        s128 = _mm_load_si128((const __m128i *)(__ptr_offset(src, 16, 1)));
        _mm_store_si128((__m128i *)(__ptr_offset(dst, 16, 1)), s128);
        s128 = _mm_load_si128((const __m128i *)(__ptr_offset(src, 16, 2)));
        _mm_store_si128((__m128i *)(__ptr_offset(dst, 16, 2)), s128);
        s128 = _mm_load_si128((const __m128i *)(__ptr_offset(src, 16, 3)));
        _mm_store_si128((__m128i *)(__ptr_offset(dst, 16, 3)), s128);

        s128 = _mm_load_si128((const __m128i *)(__ptr_offset(src, 16, 4)));
        _mm_store_si128((__m128i *)(__ptr_offset(dst, 16, 4)), s128);
        s128 = _mm_load_si128((const __m128i *)(__ptr_offset(src, 16, 5)));
        _mm_store_si128((__m128i *)(__ptr_offset(dst, 16, 5)), s128);
        s128 = _mm_load_si128((const __m128i *)(__ptr_offset(src, 16, 6)));
        _mm_store_si128((__m128i *)(__ptr_offset(dst, 16, 6)), s128);
        s128 = _mm_load_si128((const __m128i *)(__ptr_offset(src, 16, 7)));
        _mm_store_si128((__m128i *)(__ptr_offset(dst, 16, 7)), s128);

        s128 = _mm_load_si128((const __m128i *)(__ptr_offset(src, 16, 8)));
        _mm_store_si128((__m128i *)(__ptr_offset(dst, 16, 8)), s128);
        s128 = _mm_load_si128((const __m128i *)(__ptr_offset(src, 16, 9)));
        _mm_store_si128((__m128i *)(__ptr_offset(dst, 16, 9)), s128);
        s128 = _mm_load_si128((const __m128i *)(__ptr_offset(src, 16, 10)));
        _mm_store_si128((__m128i *)(__ptr_offset(dst, 16, 10)), s128);
        s128 = _mm_load_si128((const __m128i *)(__ptr_offset(src, 16, 11)));
        _mm_store_si128((__m128i *)(__ptr_offset(dst, 16, 11)), s128);

        s128 = _mm_load_si128((const __m128i *)(__ptr_offset(src, 16, 12)));
        _mm_store_si128((__m128i *)(__ptr_offset(dst, 16, 12)), s128);
        s128 = _mm_load_si128((const __m128i *)(__ptr_offset(src, 16, 13)));
        _mm_store_si128((__m128i *)(__ptr_offset(dst, 16, 13)), s128);
        s128 = _mm_load_si128((const __m128i *)(__ptr_offset(src, 16, 14)));
        _mm_store_si128((__m128i *)(__ptr_offset(dst, 16, 14)), s128);
        s128 = _mm_load_si128((const __m128i *)(__ptr_offset(src, 16, 15)));
        _mm_store_si128((__m128i *)(__ptr_offset(dst, 16, 15)), s128);

        src = (void *)((uintptr_t)src + 256);
        dst = (void *)((uintptr_t)dst + 256);
        len -= 256;
    }
#else
    register const uint64_t *s64;
    register uint64_t *d64;

    ASSERT(((uintptr_t)src & 0x07) == 0);
    ASSERT(((uintptr_t)dst & 0x07) == 0);
    ASSERT((len & 0xFF) == 0);

    s64 = (const uint64_t *) src;
    d64 = (uint64_t *) dst;

    while (len) {
        (*d64++) = (*s64++);
        (*d64++) = (*s64++);
        (*d64++) = (*s64++);
        (*d64++) = (*s64++);
        (*d64++) = (*s64++);
        (*d64++) = (*s64++);
        (*d64++) = (*s64++);
        (*d64++) = (*s64++);

        (*d64++) = (*s64++);
        (*d64++) = (*s64++);
        (*d64++) = (*s64++);
        (*d64++) = (*s64++);
        (*d64++) = (*s64++);
        (*d64++) = (*s64++);
        (*d64++) = (*s64++);
        (*d64++) = (*s64++);

        (*d64++) = (*s64++);
        (*d64++) = (*s64++);
        (*d64++) = (*s64++);
        (*d64++) = (*s64++);
        (*d64++) = (*s64++);
        (*d64++) = (*s64++);
        (*d64++) = (*s64++);
        (*d64++) = (*s64++);

        (*d64++) = (*s64++);
        (*d64++) = (*s64++);
        (*d64++) = (*s64++);
        (*d64++) = (*s64++);
        (*d64++) = (*s64++);
        (*d64++) = (*s64++);
        (*d64++) = (*s64++);
        (*d64++) = (*s64++);

        len -= 256;
    }
#endif
}
#endif

void blkfront_wait_slot(struct blkfront_dev *dev)
{
    /* Wait for a slot */
    if (RING_FULL(&dev->ring)) {
	unsigned long flags;
	DEFINE_WAIT(w);
	local_irq_save(flags);
	while (1) {
	    blkfront_aio_poll(dev);
	    if (!RING_FULL(&dev->ring))
		break;
	    /* Really no slot, go to sleep. */
	    add_waiter(w, blkfront_queue);
	    local_irq_restore(flags);
	    schedule();
	    local_irq_save(flags);
	}
	remove_waiter(w, blkfront_queue);
	local_irq_restore(flags);
    }
}

void blkfront_wait_slot_nosched(struct blkfront_dev *dev)
{
    /* Wait for a slot */
    if (RING_FULL(&dev->ring)) {
	unsigned long flags;
	local_irq_save(flags);
	while (1) {
	    blkfront_aio_poll(dev);
	    if (!RING_FULL(&dev->ring))
		break;
	    local_irq_restore(flags);
	    local_irq_save(flags);
	}
	local_irq_restore(flags);
    }
}

/* Issue an aio */
void blkfront_aio(struct blkfront_aiocb *aiocbp, int write)
{
    struct blkfront_dev *dev = aiocbp->aio_dev;

    blkfront_wait_slot(dev);
    blkfront_aio_enqueue(aiocbp, write);
    blkfront_aio_submit(dev);
}

void blkfront_aio_nosched(struct blkfront_aiocb *aiocbp, int write)
{
    struct blkfront_dev *dev = aiocbp->aio_dev;

    blkfront_wait_slot_nosched(dev);
    blkfront_aio_enqueue(aiocbp, write);
    blkfront_aio_submit(dev);
}

#define blkfront_req_available(dev, n) \
  (((dev)->ring.req_prod_pvt - (dev)->ring.rsp_cons) < (BLK_RING_SIZE - (n)))

int blkfront_aio_enqueue(struct blkfront_aiocb *aiocbp, int write)
{
    struct blkfront_dev *dev = aiocbp->aio_dev;
    struct blkif_request *req;
    RING_IDX i;
    int n, j;
#ifdef CONFIG_BLKFRONT_PERSISTENT_GRANTS
    struct blk_buffer *buffer;
    int p;
#else
    uintptr_t start, end;
#endif
    uintptr_t data;

    // Can't io at non-sector-aligned location
    ASSERT(!(aiocbp->aio_offset & (dev->info.sector_size-1)));
    // Can't io non-sector-sized amounts
    ASSERT(!(aiocbp->aio_nbytes & (dev->info.sector_size-1)));
    // Can't io non-sector-aligned buffer
    ASSERT(!((uintptr_t) aiocbp->aio_buf & (dev->info.sector_size-1)));

#if CONFIG_BLKFRONT_PERSISTENT_GRANTS
    aiocbp->n = n = (aiocbp->aio_nbytes + PAGE_SIZE - 1) >> PAGE_SHIFT;
#else
    start = (uintptr_t)aiocbp->aio_buf & PAGE_MASK;
    end = ((uintptr_t)aiocbp->aio_buf + aiocbp->aio_nbytes + PAGE_SIZE - 1) & PAGE_MASK;
    aiocbp->n = n = (end - start) / PAGE_SIZE;
#endif

    /* qemu's IDE max multsect is 16 (8KB) and SCSI max DMA was set to 32KB,
     * so max 44KB can't happen. on persistent grants, we will not have an
     * offset thus max 32KB can happen there */
#ifdef CONFIG_BLKFRONT_PERSISTENT_GRANTS
    ASSERT(n <= BLKIF_MAX_PRSNT_GNT_SEGMENTS_PER_REQUEST);
#else
    ASSERT(n <= BLKIF_MAX_SEGMENTS_PER_REQUEST);
#endif

    if (unlikely(!blkfront_req_available(dev, n))) {
        /* try to free up space by calling aio_poll() */
        blkfront_aio_poll(dev);
        if (!blkfront_req_available(dev, n)) {
            /* we still don't have space, the caller should try again later... */
            return -EBUSY;
        }
    }
    i = dev->ring.req_prod_pvt;
    req = RING_GET_REQUEST(&dev->ring, i);

    req->operation = write ? BLKIF_OP_WRITE : BLKIF_OP_READ;
    req->nr_segments = n;
    req->handle = dev->handle;
    req->id = (uintptr_t) aiocbp;
    req->sector_number = aiocbp->aio_offset / 512;

#ifdef CONFIG_BLKFRONT_PERSISTENT_GRANTS
    for (j = 0; j < n; j++) {
        req->seg[j].first_sect = 0;
        req->seg[j].last_sect = PAGE_SIZE / 512 - 1;
    }
    req->seg[n-1].last_sect = (((uintptr_t) aiocbp->aio_nbytes - 1) & ~PAGE_MASK) / 512;
#else
    for (j = 0; j < n; j++) {
        req->seg[j].first_sect = 0;
        req->seg[j].last_sect = PAGE_SIZE / 512 - 1;
    }
    req->seg[0].first_sect = ((uintptr_t)aiocbp->aio_buf & ~PAGE_MASK) / 512;
    req->seg[n-1].last_sect = (((uintptr_t)aiocbp->aio_buf + aiocbp->aio_nbytes - 1) & ~PAGE_MASK) / 512;
#endif
#ifdef CONFIG_BLKFRONT_PERSISTENT_GRANTS
    for (j = 0, p = ((i) % BLK_RING_SIZE) * BLKIF_MAX_PRSNT_GNT_SEGMENTS_PER_REQUEST;
         j < n;
         ++j, ++p) {
        buffer = &dev->pt_pool[p];
        ASSERT(buffer->inflight == 0);
        aiocbp->prst_buffer[j] = buffer;
        req->seg[j].gref = buffer->gref;
        buffer->inflight = 1;
        if (write) {
            data = (uintptr_t)aiocbp->aio_buf + j * PAGE_SIZE;
            _fmemcpy256(buffer->page, (void *) data, PAGE_SIZE);
        }
    }
#else
    for (j = 0; j < n; j++) {
        data = start + j * PAGE_SIZE;
        if (!write) {
            /* Trigger CoW if needed */
            *(char*)(data + (req->seg[j].first_sect << 9)) = 0;
            barrier();
        }
	aiocbp->gref[j] = req->seg[j].gref =
            gnttab_grant_access(dev->dom, virtual_to_mfn(data), write);
    }
#endif

    dev->ring.req_prod_pvt = i + 1;

    wmb();
    return 0;
}

void blkfront_aio_submit(struct blkfront_dev *dev)
{
    int notify;

    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&dev->ring, notify);

    if(notify) notify_remote_via_evtchn(dev->evtchn);
}

static void blkfront_aio_cb(struct blkfront_aiocb *aiocbp, int ret)
{
    aiocbp->data = (void*) 1;
    aiocbp->aio_cb = NULL;
}

void blkfront_io(struct blkfront_aiocb *aiocbp, int write)
{
    unsigned long flags;
    DEFINE_WAIT(w);

    ASSERT(!aiocbp->aio_cb);
    aiocbp->aio_cb = blkfront_aio_cb;
    blkfront_aio(aiocbp, write);
    aiocbp->data = NULL;

    local_irq_save(flags);
    while (1) {
	blkfront_aio_poll(aiocbp->aio_dev);
	if (aiocbp->data)
	    break;

	add_waiter(w, blkfront_queue);
	local_irq_restore(flags);
	schedule();
	local_irq_save(flags);
    }
    remove_waiter(w, blkfront_queue);
    local_irq_restore(flags);
}

static void blkfront_push_operation(struct blkfront_dev *dev, uint8_t op, uint64_t id)
{
    int i;
    struct blkif_request *req;
    int notify;

    blkfront_wait_slot(dev);
    i = dev->ring.req_prod_pvt;
    req = RING_GET_REQUEST(&dev->ring, i);
    req->operation = op;
    req->nr_segments = 0;
    req->handle = dev->handle;
    req->id = id;
    /* Not needed anyway, but the backend will check it */
    req->sector_number = 0;
    dev->ring.req_prod_pvt = i + 1;
    wmb();
    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&dev->ring, notify);
    if (notify) notify_remote_via_evtchn(dev->evtchn);
}

void blkfront_aio_push_operation(struct blkfront_aiocb *aiocbp, uint8_t op)
{
    struct blkfront_dev *dev = aiocbp->aio_dev;
    blkfront_push_operation(dev, op, (uintptr_t) aiocbp);
}

void blkfront_sync(struct blkfront_dev *dev)
{
    unsigned long flags;
    DEFINE_WAIT(w);

    if (dev->info.mode == O_RDWR) {
        if (dev->info.barrier == 1)
            blkfront_push_operation(dev, BLKIF_OP_WRITE_BARRIER, 0);

        if (dev->info.flush == 1)
            blkfront_push_operation(dev, BLKIF_OP_FLUSH_DISKCACHE, 0);
    }

    /* Note: This won't finish if another thread enqueues requests.  */
    local_irq_save(flags);
    while (1) {
	blkfront_aio_poll(dev);
	if (RING_FREE_REQUESTS(&dev->ring) == RING_SIZE(&dev->ring))
	    break;

	add_waiter(w, blkfront_queue);
	local_irq_restore(flags);
	schedule();
	local_irq_save(flags);
    }
    remove_waiter(w, blkfront_queue);
    local_irq_restore(flags);
}

int blkfront_aio_poll(struct blkfront_dev *dev)
{
    RING_IDX rp, cons;
    struct blkif_response *rsp;
    int more;
    int nr_consumed;

moretodo:
#ifdef HAVE_LIBC
    if (dev->fd != -1) {
        files[dev->fd].read = 0;
        mb(); /* Make sure to let the handler set read to 1 before we start looking at the ring */
    }
#endif

    rp = dev->ring.sring->rsp_prod;
    rmb(); /* Ensure we see queued responses up to 'rp'. */
    cons = dev->ring.rsp_cons;

    nr_consumed = 0;
    while ((cons != rp))
    {
        struct blkfront_aiocb *aiocbp;
        int status;

	rsp = RING_GET_RESPONSE(&dev->ring, cons);
	nr_consumed++;

        aiocbp = (void*) (uintptr_t) rsp->id;
        status = rsp->status;

        if (status != BLKIF_RSP_OKAY)
            printk("block error %d for op %d\n", status, rsp->operation);

        switch (rsp->operation) {
        case BLKIF_OP_READ:
#ifdef CONFIG_BLKFRONT_PERSISTENT_GRANTS
            {
                size_t left    = aiocbp->aio_nbytes;
                uintptr_t data = (uintptr_t)aiocbp->aio_buf;
                struct blk_buffer *buffer;
                int j = 0;

                while (left > PAGE_SIZE) {
                    buffer = aiocbp->prst_buffer[j];
                    ASSERT(buffer->inflight == 1);
                    _fmemcpy256((void *) data, buffer->page, PAGE_SIZE);
                    buffer->inflight = 0;
                    data += PAGE_SIZE;
                    left -= PAGE_SIZE;
                    ++j;
                }
                if (left) {
                    buffer = aiocbp->prst_buffer[j];
                    ASSERT(buffer->inflight == 1);
                    _fmemcpy256((void *) data, buffer->page, left);
                    buffer->inflight = 0;
                    ++j;
                }
                ASSERT(j == aiocbp->n);
            }
            break;
#endif
        case BLKIF_OP_WRITE:
        {
            int j;

            for (j = 0; j < aiocbp->n; j++)
            {
#ifdef CONFIG_BLKFRONT_PERSISTENT_GRANTS
                aiocbp->prst_buffer[j]->inflight = 0;
#else
                gnttab_end_access(aiocbp->gref[j]);
#endif
            }

            break;
        }

        case BLKIF_OP_WRITE_BARRIER:
        case BLKIF_OP_FLUSH_DISKCACHE:
            break;

        default:
            printk("unrecognized block operation %d response\n", rsp->operation);
        }

        dev->ring.rsp_cons = ++cons;
        /* Nota: callback frees aiocbp itself */
        if (aiocbp && aiocbp->aio_cb)
            aiocbp->aio_cb(aiocbp, status ? -EIO : 0);
        if (dev->ring.rsp_cons != cons)
            /* We reentered, we must not continue here */
            break;
    }

    RING_FINAL_CHECK_FOR_RESPONSES(&dev->ring, more);
    if (more) goto moretodo;

    return nr_consumed;
}

#ifdef HAVE_LIBC
int blkfront_open(struct blkfront_dev *dev)
{
    /* Silently prevent multiple opens */
    if(dev->fd != -1) {
       return dev->fd;
    }
    dev->fd = alloc_fd(FTYPE_BLK);
    printk("blk_open(%s) -> %d\n", dev->nodename, dev->fd);
    files[dev->fd].blk.dev = dev;
    files[dev->fd].blk.offset = 0;
    return dev->fd;
}

int blkfront_posix_rwop(int fd, uint8_t* buf, size_t count, int write)
{
   struct blkfront_dev* dev = files[fd].blk.dev;
   off_t offset = files[fd].blk.offset;
   struct blkfront_aiocb aiocb;
   unsigned long long disksize = dev->info.sectors * dev->info.sector_size;
   unsigned int blocksize = dev->info.sector_size;

   int blknum;
   int blkoff;
   size_t bytes;
   int rc = 0;
   int alignedbuf = 0;
   uint8_t* copybuf = NULL;

   /* RW 0 bytes is just a NOP */
   if(count == 0) {
      return 0;
   }
   /* Check for NULL buffer */
   if( buf == NULL ) {
      errno = EFAULT;
      return -1;
   }

   /* Write mode checks */
   if(write) {
      /*Make sure we have write permission */
      if(dev->info.info & VDISK_READONLY 
            || (dev->info.mode != O_RDWR  && dev->info.mode !=  O_WRONLY)) {
         errno = EACCES;
         return -1;
      }
      /*Make sure disk is big enough for this write */
      if(offset + count > disksize) {
         errno = ENOSPC;
         return -1;
      }
   }
   /* Read mode checks */
   else
   {
      /* Reading past the disk? Just return 0 */
      if(offset >= disksize) {
         return 0;
      }

      /*If the requested read is bigger than the disk, just
       * read as much as we can until the end */
      if(offset + count > disksize) {
         count = disksize - offset;
      }
   }
   /* Determine which block to start at and at which offset inside of it */
   blknum = offset / blocksize;
   blkoff = offset % blocksize;

   /* Optimization: We need to check if buf is aligned to the sector size.
    * This is somewhat tricky code. We have to add the blocksize - block offset
    * because the first block may be a partial block and then for every subsequent
    * block rw the buffer will be offset.*/
   if(!((uintptr_t) (buf +(blocksize -  blkoff)) & (dev->info.sector_size-1))) {
      alignedbuf = 1;
   }

   /* Setup aiocb block object */
   aiocb.aio_dev = dev;
   aiocb.aio_offset = blknum * blocksize;
   aiocb.aio_cb = NULL;
   aiocb.data = NULL;

   /* If our buffer is unaligned or its aligned but we will need to rw a partial block
    * then a copy will have to be done */
   if(!alignedbuf || blkoff != 0 || count % blocksize != 0) {
      copybuf = _xmalloc(blocksize, dev->info.sector_size);
   }

   rc = count;
   while(count > 0) {
      /* determine how many bytes to read/write from/to the current block buffer */
      if(!alignedbuf || blkoff != 0 || count < blocksize) {
         /* This is the case for unaligned R/W or partial block */
         bytes = count < blocksize - blkoff ? count : blocksize - blkoff;
         aiocb.aio_nbytes = blocksize;
      } else {
         /* We can optimize further if buffer is page aligned */
         int not_page_aligned = 0;
         if(((uintptr_t)buf) & (PAGE_SIZE -1)) {
            not_page_aligned = 1;
         }

         /* For an aligned R/W we can read up to the maximum transfer size */
         bytes = count > (BLKIF_MAX_SEGMENTS_PER_REQUEST-not_page_aligned)*PAGE_SIZE 
            ? (BLKIF_MAX_SEGMENTS_PER_REQUEST-not_page_aligned)*PAGE_SIZE
            : count & ~(blocksize -1);
         aiocb.aio_nbytes = bytes;
      }

      /* read operation */
      if(!write) {
         if (alignedbuf && bytes >= blocksize) {
            /* If aligned and were reading a whole block, just read right into buf */
            aiocb.aio_buf = buf;
            blkfront_read(&aiocb);
         } else {
            /* If not then we have to do a copy */
            aiocb.aio_buf = copybuf;
            blkfront_read(&aiocb);
            memcpy(buf, &copybuf[blkoff], bytes);
         }
      }
      /* Write operation */
      else {
         if(alignedbuf && bytes >= blocksize) {
            /* If aligned and were writing a whole block, just write directly from buf */
            aiocb.aio_buf = buf;
            blkfront_write(&aiocb);
         } else {
            /* If not then we have to do a copy. */
            aiocb.aio_buf = copybuf;
            /* If we're writing a partial block, we need to read the current contents first
             * so we don't overwrite the extra bits with garbage */
            if(blkoff != 0 || bytes < blocksize) {
               blkfront_read(&aiocb);
            }
            memcpy(&copybuf[blkoff], buf, bytes);
            blkfront_write(&aiocb);
         }
      }
      /* Will start at beginning of all remaining blocks */
      blkoff = 0;

      /* Increment counters and continue */
      count -= bytes;
      buf += bytes;
      if(bytes < blocksize) {
         //At minimum we read one block
         aiocb.aio_offset += blocksize;
      } else {
         //If we read more than a block, was a multiple of blocksize
         aiocb.aio_offset += bytes;
      }
   }

   free(copybuf);
   files[fd].blk.offset += rc;
   return rc;

}

int blkfront_posix_fstat(int fd, struct stat* buf)
{
   struct blkfront_dev* dev = files[fd].blk.dev;

   buf->st_mode = dev->info.mode;
   buf->st_uid = 0;
   buf->st_gid = 0;
   buf->st_size = dev->info.sectors * dev->info.sector_size;
   buf->st_atime = buf->st_mtime = buf->st_ctime = time(NULL);

   return 0;
}
#endif
