/******************************************************************************
 * common.c
 * 
 * Common stuff special to x86 goes here.
 * 
 * Copyright (c) 2002-2003, K A Fraser & R Neugebauer
 * Copyright (c) 2005, Grzegorz Milos, Intel Research Cambridge
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
 * DEALINGS IN THE SOFTWARE.
 *
 */

#include <mini-os/os.h>
#include <mini-os/lib.h> /* for printk, memcpy */

/*
 * Shared page for communicating with the hypervisor.
 * Events flags go here, for example.
 */
shared_info_t *HYPERVISOR_shared_info;

/*
 * This pointer holds a reference to the copy of the start_info struct.
 */
static start_info_t *start_info_ptr;

/*
 * This structure contains start-of-day info, such as pagetable base pointer,
 * address of the shared_info structure, and things like that.
 */
union start_info_union start_info_union;

/*
 * Just allocate the kernel stack here. SS:ESP is set up to point here
 * in head.S.
 */
char stack[2*STACK_SIZE];

extern char shared_info[PAGE_SIZE];

/* Assembler interface fns in entry.S. */
void hypervisor_callback(void);
void failsafe_callback(void);

#if defined(__x86_64__)
#define __pte(x) ((pte_t) { (x) } )
#else
#define __pte(x) ({ unsigned long long _x = (x);        \
    ((pte_t) {(unsigned long)(_x), (unsigned long)(_x>>32)}); })
#endif

static
shared_info_t *map_shared_info(unsigned long pa)
{
    int rc;

    if (!xen_feature(XENFEAT_auto_translated_physmap)) {
        if ( (rc = HYPERVISOR_update_va_mapping(
                        (unsigned long)shared_info, __pte(pa | 7), UVMF_INVLPG)) )
        {
            printk("Failed to map shared_info!! rc=%d\n", rc);
            do_exit();
        }
	    return (shared_info_t *)shared_info;
    }
    else
		return (shared_info_t *)to_virt(start_info.shared_info);
}

static
void unmap_shared_info(void)
{
    int rc;

    if ( (rc = HYPERVISOR_update_va_mapping((unsigned long)HYPERVISOR_shared_info,
            __pte((virt_to_mfn(shared_info)<<L1_PAGETABLE_SHIFT)| L1_PROT), UVMF_INVLPG)) )
    {
        printk("Failed to unmap shared_info page!! rc=%d\n", rc);
        do_exit();
    }
}

static inline void fpu_init(void) {
	asm volatile("fninit");
}

#ifdef __SSE__
static inline void sse_init(void) {
	unsigned long status = 0x1f80;
	asm volatile("ldmxcsr %0" : : "m" (status));
}
#else
#define sse_init()
#endif

void
arch_init(start_info_t *si)
{
	/*Initialize floating point unit */
        fpu_init();

	/* Initialize SSE */
    if (xen_feature(XENFEAT_hvm_callback_vector))
        enable_osfxsr();
    sse_init();

	/* Copy the start_info struct to a globally-accessible area. */
	/* WARN: don't do printk before here, it uses information from
	   shared_info. Use xprintk instead. */
	memcpy(&start_info, si, sizeof(*si));
	start_info_ptr = si;

	/* set up minimal memory infos */
	if (!xen_feature(XENFEAT_auto_translated_physmap))
	    phys_to_machine_mapping = (unsigned long *)start_info.mfn_list;

	/* Grab the shared_info pointer and put it in a safe place. */
	HYPERVISOR_shared_info = map_shared_info(start_info.shared_info);

	/* Set up event and failsafe callback addresses. */
    if (!xen_feature(XENFEAT_hvm_callback_vector)) {
#ifdef __i386__
        HYPERVISOR_set_callbacks(
                __KERNEL_CS, (unsigned long)hypervisor_callback,
                __KERNEL_CS, (unsigned long)failsafe_callback);
#else
        HYPERVISOR_set_callbacks(
                (unsigned long)hypervisor_callback,
                (unsigned long)failsafe_callback, 0);
#endif
    }


}

void
arch_pre_suspend(void)
{
    arch_mm_pre_suspend();

    unmap_shared_info();

    /* Replace xenstore and console pfns with the correspondent mfns */
    start_info_ptr->store_mfn =
        machine_to_phys_mapping[start_info_ptr->store_mfn];
    start_info_ptr->console.domU.mfn =
        machine_to_phys_mapping[start_info_ptr->console.domU.mfn];

}

void
arch_post_suspend(int canceled)
{
    if (canceled) {
        start_info_ptr->store_mfn = pfn_to_mfn(start_info_ptr->store_mfn);
        start_info_ptr->console.domU.mfn = pfn_to_mfn(start_info_ptr->console.domU.mfn);
    } else {
        memcpy(&start_info, start_info_ptr, sizeof(start_info_t));
    }

    HYPERVISOR_shared_info = map_shared_info(start_info_ptr->shared_info);

    arch_mm_post_suspend(canceled);
}

void
arch_fini(void)
{
#ifdef __i386__
	HYPERVISOR_set_callbacks(0, 0, 0, 0);
#else
	HYPERVISOR_set_callbacks(0, 0, 0);
#endif
}

void
arch_print_info(void)
{
	printk("  stack:      %p-%p\n", stack, stack + sizeof(stack));
}


