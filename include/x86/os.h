/******************************************************************************
 * os.h
 * 
 * random collection of macros and definition
 */

#ifndef _OS_H_
#define _OS_H_

#if __GNUC__ == 2 && __GNUC_MINOR__ < 96
#define __builtin_expect(x, expected_value) (x)
#endif
#define unlikely(x)  __builtin_expect(!!(x),0)
#define likely(x)  __builtin_expect(!!(x),1)

#define smp_processor_id() 0


#ifndef __ASSEMBLY__
#include <mini-os/types.h>
#include <mini-os/hypervisor.h>
#include <mini-os/kernel.h>
#ifdef CONFIG_NOXS
#include <xen/io/noxs.h>
#endif

#define USED    __attribute__ ((used))

#define BUG do_exit

#endif
#include <xen/xen.h>



#define __KERNEL_CS  FLAT_KERNEL_CS
#define __KERNEL_DS  FLAT_KERNEL_DS
#define __KERNEL_SS  FLAT_KERNEL_SS

#define TRAP_divide_error      0
#define TRAP_debug             1
#define TRAP_nmi               2
#define TRAP_int3              3
#define TRAP_overflow          4
#define TRAP_bounds            5
#define TRAP_invalid_op        6
#define TRAP_no_device         7
#define TRAP_double_fault      8
#define TRAP_copro_seg         9
#define TRAP_invalid_tss      10
#define TRAP_no_segment       11
#define TRAP_stack_error      12
#define TRAP_gp_fault         13
#define TRAP_page_fault       14
#define TRAP_spurious_int     15
#define TRAP_copro_error      16
#define TRAP_alignment_check  17
#define TRAP_machine_check    18
#define TRAP_simd_error       19
#define TRAP_deferred_nmi     31

/* Everything below this point is not included by assembler (.S) files. */
#ifndef __ASSEMBLY__

extern shared_info_t *HYPERVISOR_shared_info;
#ifdef CONFIG_NOXS
extern noxs_dev_page_t *HYPERVISOR_device_page;
#endif

void trap_init(void);
void trap_fini(void);

void arch_init(start_info_t *si);
void arch_print_info(void);
void arch_pre_suspend(void);
void arch_post_suspend(int canceled);
void arch_fini(void);





/* 
 * The use of 'barrier' in the following reflects their use as local-lock
 * operations. Reentrancy must be prevented (e.g., __cli()) /before/ following
 * critical operations are executed. All critical operations must complete
 * /before/ reentrancy is permitted (e.g., __sti()). Alpha architecture also
 * includes these barriers, for example.
 */

#define xen_irq_disable()               \
do {									\
	vcpu_info_t *_vcpu;						\
	_vcpu = &HYPERVISOR_shared_info->vcpu_info[smp_processor_id()];	\
	_vcpu->evtchn_upcall_mask = 1;					\
	barrier();							\
} while (0)

#define xen_irq_enable()                \
do {									\
	vcpu_info_t *_vcpu;						\
	barrier();							\
	_vcpu = &HYPERVISOR_shared_info->vcpu_info[smp_processor_id()];	\
	_vcpu->evtchn_upcall_mask = 0;					\
	barrier(); /* unmask then check (avoid races) */		\
	if ( unlikely(_vcpu->evtchn_upcall_pending) )			\
		force_evtchn_callback();				\
} while (0)

/* xen_save_fl interface is different from native_save_fl for now */
#define xen_save_fl(x)                  \
do {									\
	vcpu_info_t *_vcpu;						\
	_vcpu = &HYPERVISOR_shared_info->vcpu_info[smp_processor_id()];	\
	(x) = _vcpu->evtchn_upcall_mask;				\
} while (0)

#define xen_restore_fl(x)               \
do {									\
	vcpu_info_t *_vcpu;						\
	barrier();							\
	_vcpu = &HYPERVISOR_shared_info->vcpu_info[smp_processor_id()];	\
	if ((_vcpu->evtchn_upcall_mask = (x)) == 0) {			\
		barrier(); /* unmask then check (avoid races) */	\
		if ( unlikely(_vcpu->evtchn_upcall_pending) )		\
			force_evtchn_callback();			\
	}\
} while (0)

#define xen_safe_halt()     HYPERVISOR_sched_op(SCHEDOP_block, 0)

#define xen_irqs_disabled()			\
    HYPERVISOR_shared_info->vcpu_info[smp_processor_id()].evtchn_upcall_mask

#define xen_read_cr2() \
        (HYPERVISOR_shared_info->vcpu_info[smp_processor_id()].arch.cr2)

#define xen_flush_tlb_global() \
do {    \
    mmuext_op_t op = {                  \
        .cmd = MMUEXT_TLB_FLUSH_ALL,    \
    };                                  \
    int count;                          \
    HYPERVISOR_mmuext_op(&op, 1, &count, DOMID_SELF);   \
} while(0)

#define xen_flush_tlb() \
do {    \
    mmuext_op_t op = {                  \
        .cmd = MMUEXT_TLB_FLUSH_LOCAL,  \
    };                                  \
    int count;                          \
    HYPERVISOR_mmuext_op(&op, 1, &count, DOMID_SELF);   \
} while(0)

#define xen_flush_tlb_single(addr)  \
do {    \
    mmuext_op_t op = {                          \
        .cmd = MMUEXT_INVLPG_LOCAL,             \
        .arg1.linear_addr = addr & PAGE_MASK,   \
    };                                          \
    int count;                                  \
    HYPERVISOR_mmuext_op(&op, 1, &count, DOMID_SELF);   \
} while(0)


#ifndef CONFIG_PVH
#define __cli()             xen_irq_disable()
#define __sti()             xen_irq_enable()
#define __save_flags(x)     xen_save_fl(x)
#define __restore_flags(x)  xen_restore_fl(x)
#define safe_halt()         xen_safe_halt()
#define __save_and_cli(x)   \
do {  \
    xen_save_fl(x);         \
    xen_irq_disable();      \
} while (0)
#define irqs_disabled()     xen_irqs_disabled()
#define read_cr2()          xen_read_cr2()
#define flush_tlb_global()  xen_flush_tlb_global()
#define flush_tlb()         xen_flush_tlb()
#define flush_tlb_single(addr)  xen_flush_tlb_single(addr)
#define pvh_early_init()
#define enable_osfxsr()
#else
extern unsigned long __force_order;

static inline unsigned long native_read_cr0(void)
{
	unsigned long val;
	asm volatile("mov %%cr0,%0\n\t" : "=r" (val), "=m" (__force_order));
	return val;
}       

static inline void native_write_cr0(unsigned long val)
{
	asm volatile("mov %0,%%cr0": : "r" (val), "m" (__force_order));
} 

static inline unsigned long native_read_cr2(void)
{
    unsigned long val;
    asm volatile("mov %%cr2,%0\n\t" : "=r" (val), "=m" (__force_order));
    return val;
}

static inline unsigned long native_read_cr3(void)
{
    unsigned long val;
    asm volatile("mov %%cr3,%0\n\t" : "=r" (val), "=m" (__force_order));
    return val;
}   

static inline void native_write_cr3(unsigned long val)
{   
    asm volatile("mov %0,%%cr3": : "r" (val), "m" (__force_order));
}

static inline unsigned long native_read_cr4(void)
{
    unsigned long val;
    asm volatile("mov %%cr4,%0\n\t" : "=r" (val), "=m" (__force_order));
    return val;
}

static inline void native_write_cr4(unsigned long val)
{
    asm volatile("mov %0,%%cr4": : "r" (val), "m" (__force_order));
}

static inline unsigned long native_save_fl(void)
{
    unsigned long flags;

    /*
     * "=rm" is safe here, because "pop" adjusts the stack before
     * it evaluates its effective address -- this is part of the
     * documented behavior of the "pop" instruction.
     */
    asm volatile("# __raw_save_flags\n\t"
            "pushf ; pop %0"
            : "=rm" (flags)
            : /* no input */
            : "memory");

    return flags;
}

static inline void native_restore_fl(unsigned long flags)
{       
    asm volatile("push %0 ; popf"
            : /* no output */
            :"g" (flags)
            :"memory", "cc");
}   

static inline void native_irq_disable(void)
{
    asm volatile("cli": : :"memory");
}   

static inline void native_irq_enable(void)
{   
    asm volatile("sti": : :"memory");
}

static inline void native_safe_halt(void)
{   
    asm volatile("sti; hlt": : :"memory");
}

static inline int native_irqs_disabled(void)
{
    return !((native_save_fl() >> 9 /* IF */) & 0x1);
}

static inline void native_flush_tlb(void)
{
    native_write_cr3(native_read_cr3());
}

static inline void native_flush_tlb_global(void)
{
    unsigned long cr4, flags;

    flags = native_save_fl();

    cr4 = native_read_cr4();
    /* clear PGE */
    native_write_cr4(cr4 & ~(1UL << 7));
    /* write old PGE again and flush TLBs */
    native_write_cr4(cr4);

    native_restore_fl(flags);
}

static inline void native_flush_tlb_single(unsigned long addr)
{
    asm volatile("invlpg (%0)" ::"r" (addr) : "memory");
}

#define __cli()								\
do {									\
    if (xen_feature(XENFEAT_hvm_callback_vector))   \
        native_irq_disable();   \
    else                        \
        xen_irq_disable();      \
} while (0)

#define __sti()								\
do {									\
    if (xen_feature(XENFEAT_hvm_callback_vector))   \
        native_irq_enable();    \
    else                        \
        xen_irq_enable();       \
} while (0)

#define __save_flags(x)							\
do {									\
    if (xen_feature(XENFEAT_hvm_callback_vector))   \
        (x) = native_save_fl();     \
    else                            \
        xen_save_fl(x);             \
} while (0)

#define __restore_flags(x)						\
do {									\
    if (xen_feature(XENFEAT_hvm_callback_vector))   \
        native_restore_fl(x);   \
    else                        \
        xen_restore_fl(x);      \
} while (0)

#define safe_halt()                     \
do {            \
    if (xen_feature(XENFEAT_hvm_callback_vector))   \
        native_safe_halt();     \
    else                        \
        xen_safe_halt();        \
} while(0);

#define __save_and_cli(x)   \
do {  \
    if (xen_feature(XENFEAT_hvm_callback_vector)) { \
        (x) = native_save_fl();    \
        native_irq_disable();   \
    }       \
    else {  \
        xen_save_fl(x);         \
        xen_irq_disable();      \
    }   \
} while (0)

#define irqs_disabled()     \
    (xen_feature(XENFEAT_hvm_callback_vector) ?  \
        native_irqs_disabled() : xen_irqs_disabled())

#define read_cr2()     \
    (xen_feature(XENFEAT_auto_translated_physmap) ?   \
        native_read_cr2() : xen_read_cr2())

#define flush_tlb_global()                     \
do {            \
    if (xen_feature(XENFEAT_auto_translated_physmap))   \
        native_flush_tlb_global();     \
    else                                \
        xen_flush_tlb_global();        \
} while(0);

#define flush_tlb()                     \
do {            \
    if (xen_feature(XENFEAT_auto_translated_physmap))   \
        native_flush_tlb();     \
    else                                \
        xen_flush_tlb();        \
} while(0);

#define flush_tlb_single(addr)          \
do {									\
    if (xen_feature(XENFEAT_auto_translated_physmap))   \
        native_flush_tlb_single(addr);   \
    else                        \
        xen_flush_tlb_single(addr);      \
} while (0)

static inline void pvh_early_init(void)
{
	if (!xen_feature(XENFEAT_auto_translated_physmap) ||
	    !xen_feature(XENFEAT_hvm_callback_vector))
		return;

	native_write_cr0(native_read_cr0() | 
            (1UL << 1)  /* MP */ | 
            (1UL << 5)  /* NE */ |
            (1UL << 16) /* WP */ |
            (1UL << 18) /* AM */);
#ifdef __i386__
	BUG(); /* No support for 32bit */
#endif
}

static inline void enable_osfxsr(void)
{
    native_write_cr4(native_read_cr4() | (1UL << 9)  /* OSFXSR */);
}
#endif

#define local_irq_save(x)	__save_and_cli(x)
#define local_irq_restore(x)	__restore_flags(x)
#define local_save_flags(x)	__save_flags(x)
#define local_irq_disable()	__cli()
#define local_irq_enable()	__sti()

/* This is a barrier for the compiler only, NOT the processor! */
#define barrier() __asm__ __volatile__("": : :"memory")

#if defined(__i386__)
#define mb()    __asm__ __volatile__ ("lock; addl $0,0(%%esp)": : :"memory")
#define rmb()   __asm__ __volatile__ ("lock; addl $0,0(%%esp)": : :"memory")
#define wmb()	__asm__ __volatile__ ("": : :"memory")
#elif defined(__x86_64__)
#define mb()    __asm__ __volatile__ ("mfence":::"memory")
#define rmb()   __asm__ __volatile__ ("lfence":::"memory")
#define wmb()	__asm__ __volatile__ ("sfence" ::: "memory") /* From CONFIG_UNORDERED_IO (linux) */
#endif


#define LOCK_PREFIX ""
#define LOCK ""
#define ADDR (*(volatile long *) addr)
/*
 * Make sure gcc doesn't try to be clever and move things around
 * on us. We need to use _exactly_ the address the user gave us,
 * not some alias that contains the same information.
 */
typedef struct { volatile int counter; } atomic_t;


/************************** i386 *******************************/
#ifdef __INSIDE_MINIOS__
#if defined (__i386__)

#define xchg(ptr,v) ((__typeof__(*(ptr)))__xchg((unsigned long)(v),(ptr),sizeof(*(ptr))))
struct __xchg_dummy { unsigned long a[100]; };
#define __xg(x) ((struct __xchg_dummy *)(x))
static inline unsigned long __xchg(unsigned long x, volatile void * ptr, int size)
{
	switch (size) {
		case 1:
			__asm__ __volatile__("xchgb %b0,%1"
				:"=q" (x)
				:"m" (*__xg(ptr)), "0" (x)
				:"memory");
			break;
		case 2:
			__asm__ __volatile__("xchgw %w0,%1"
				:"=r" (x)
				:"m" (*__xg(ptr)), "0" (x)
				:"memory");
			break;
		case 4:
			__asm__ __volatile__("xchgl %0,%1"
				:"=r" (x)
				:"m" (*__xg(ptr)), "0" (x)
				:"memory");
			break;
	}
	return x;
}

/**
 * test_and_clear_bit - Clear a bit and return its old value
 * @nr: Bit to clear
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.
 * It can be reorderdered on other architectures other than x86.
 * It also implies a memory barrier.
 */
static inline int test_and_clear_bit(int nr, volatile unsigned long * addr)
{
	int oldbit;

	__asm__ __volatile__( LOCK
		"btrl %2,%1\n\tsbbl %0,%0"
		:"=r" (oldbit),"=m" (ADDR)
		:"Ir" (nr) : "memory");
	return oldbit;
}

static inline int constant_test_bit(int nr, const volatile unsigned long *addr)
{
	return ((1UL << (nr & 31)) & (addr[nr >> 5])) != 0;
}

static inline int variable_test_bit(int nr, const volatile unsigned long * addr)
{
	int oldbit;

	__asm__ __volatile__(
		"btl %2,%1\n\tsbbl %0,%0"
		:"=r" (oldbit)
		:"m" (ADDR),"Ir" (nr));
	return oldbit;
}

#define test_bit(nr,addr) \
(__builtin_constant_p(nr) ? \
 constant_test_bit((nr),(addr)) : \
 variable_test_bit((nr),(addr)))

/**
 * set_bit - Atomically set a bit in memory
 * @nr: the bit to set
 * @addr: the address to start counting from
 *
 * This function is atomic and may not be reordered.  See __set_bit()
 * if you do not require the atomic guarantees.
 *
 * Note: there are no guarantees that this function will not be reordered
 * on non x86 architectures, so if you are writting portable code,
 * make sure not to rely on its reordering guarantees.
 *
 * Note that @nr may be almost arbitrarily large; this function is not
 * restricted to acting on a single-word quantity.
 */
static inline void set_bit(int nr, volatile unsigned long * addr)
{
	__asm__ __volatile__( LOCK
		"btsl %1,%0"
		:"=m" (ADDR)
		:"Ir" (nr));
}

/**
 * clear_bit - Clears a bit in memory
 * @nr: Bit to clear
 * @addr: Address to start counting from
 *
 * clear_bit() is atomic and may not be reordered.  However, it does
 * not contain a memory barrier, so if it is used for locking purposes,
 * you should call smp_mb__before_clear_bit() and/or smp_mb__after_clear_bit()
 * in order to ensure changes are visible on other processors.
 */
static inline void clear_bit(int nr, volatile unsigned long * addr)
{
	__asm__ __volatile__( LOCK
		"btrl %1,%0"
		:"=m" (ADDR)
		:"Ir" (nr));
}

/**
 * __ffs - find first bit in word.
 * @word: The word to search
 *
 * Undefined if no bit exists, so code should check against 0 first.
 */
static inline unsigned long __ffs(unsigned long word)
{
	__asm__("bsfl %1,%0"
		:"=r" (word)
		:"rm" (word));
	return word;
}


/*
 * These have to be done with inline assembly: that way the bit-setting
 * is guaranteed to be atomic. All bit operations return 0 if the bit
 * was cleared before the operation and != 0 if it was not.
 *
 * bit 0 is the LSB of addr; bit 32 is the LSB of (addr+1).
 */
#define ADDR (*(volatile long *) addr)

#define rdtscll(val) \
     __asm__ __volatile__("rdtsc" : "=A" (val))



#elif defined(__x86_64__)/* ifdef __i386__ */
/************************** x86_84 *******************************/

#define xchg(ptr,v) ((__typeof__(*(ptr)))__xchg((unsigned long)(v),(ptr),sizeof(*(ptr))))
#define __xg(x) ((volatile long *)(x))
static inline unsigned long __xchg(unsigned long x, volatile void * ptr, int size)
{
	switch (size) {
		case 1:
			__asm__ __volatile__("xchgb %b0,%1"
				:"=q" (x)
				:"m" (*__xg(ptr)), "0" (x)
				:"memory");
			break;
		case 2:
			__asm__ __volatile__("xchgw %w0,%1"
				:"=r" (x)
				:"m" (*__xg(ptr)), "0" (x)
				:"memory");
			break;
		case 4:
			__asm__ __volatile__("xchgl %k0,%1"
				:"=r" (x)
				:"m" (*__xg(ptr)), "0" (x)
				:"memory");
			break;
		case 8:
			__asm__ __volatile__("xchgq %0,%1"
				:"=r" (x)
				:"m" (*__xg(ptr)), "0" (x)
				:"memory");
			break;
	}
	return x;
}

/**
 * test_and_clear_bit - Clear a bit and return its old value
 * @nr: Bit to clear
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.  
 * It also implies a memory barrier.
 */
static __inline__ int test_and_clear_bit(int nr, volatile void * addr)
{
	int oldbit;

	__asm__ __volatile__( LOCK_PREFIX
		"btrl %2,%1\n\tsbbl %0,%0"
		:"=r" (oldbit),"=m" (ADDR)
		:"dIr" (nr) : "memory");
	return oldbit;
}

static __inline__ int constant_test_bit(int nr, const volatile void * addr)
{
	return ((1UL << (nr & 31)) & (((const volatile unsigned int *) addr)[nr >> 5])) != 0;
}

static __inline__ int variable_test_bit(int nr, volatile const void * addr)
{
	int oldbit;

	__asm__ __volatile__(
		"btl %2,%1\n\tsbbl %0,%0"
		:"=r" (oldbit)
		:"m" (ADDR),"dIr" (nr));
	return oldbit;
}

#define test_bit(nr,addr) \
(__builtin_constant_p(nr) ? \
 constant_test_bit((nr),(addr)) : \
 variable_test_bit((nr),(addr)))


/**
 * set_bit - Atomically set a bit in memory
 * @nr: the bit to set
 * @addr: the address to start counting from
 *
 * This function is atomic and may not be reordered.  See __set_bit()
 * if you do not require the atomic guarantees.
 * Note that @nr may be almost arbitrarily large; this function is not
 * restricted to acting on a single-word quantity.
 */
static __inline__ void set_bit(int nr, volatile void * addr)
{
	__asm__ __volatile__( LOCK_PREFIX
		"btsl %1,%0"
		:"=m" (ADDR)
		:"dIr" (nr) : "memory");
}

/**
 * clear_bit - Clears a bit in memory
 * @nr: Bit to clear
 * @addr: Address to start counting from
 *
 * clear_bit() is atomic and may not be reordered.  However, it does
 * not contain a memory barrier, so if it is used for locking purposes,
 * you should call smp_mb__before_clear_bit() and/or smp_mb__after_clear_bit()
 * in order to ensure changes are visible on other processors.
 */
static __inline__ void clear_bit(int nr, volatile void * addr)
{
	__asm__ __volatile__( LOCK_PREFIX
		"btrl %1,%0"
		:"=m" (ADDR)
		:"dIr" (nr));
}

/**
 * __ffs - find first bit in word.
 * @word: The word to search
 *
 * Undefined if no bit exists, so code should check against 0 first.
 */
static __inline__ unsigned long __ffs(unsigned long word)
{
	__asm__("bsfq %1,%0"
		:"=r" (word)
		:"rm" (word));
	return word;
}

#define ADDR (*(volatile long *) addr)

#define rdtscll(val) do { \
     unsigned int __a,__d; \
     asm volatile("rdtsc" : "=a" (__a), "=d" (__d)); \
     (val) = ((unsigned long)__a) | (((unsigned long)__d)<<32); \
} while(0)

#define wrmsr(msr,val1,val2) \
      __asm__ __volatile__("wrmsr" \
                           : /* no outputs */ \
                           : "c" (msr), "a" (val1), "d" (val2))

#define wrmsrl(msr,val) wrmsr(msr,(uint32_t)((uint64_t)(val)),((uint64_t)(val))>>32)


#else /* ifdef __x86_64__ */
#error "Unsupported architecture"
#endif
#endif /* ifdef __INSIDE_MINIOS */

/********************* common i386 and x86_64  ****************************/
struct __synch_xchg_dummy { unsigned long a[100]; };
#define __synch_xg(x) ((struct __synch_xchg_dummy *)(x))

#define synch_cmpxchg(ptr, old_ptr, new) \
((__typeof__(*(ptr)))__synch_cmpxchg((ptr),\
                                     (unsigned long)(old_ptr), \
                                     (unsigned long)(new), \
                                     sizeof(*(ptr))))

static inline unsigned long __synch_cmpxchg(volatile void *ptr,
        unsigned long old_ptr,
        unsigned long new_ptr, int size)
{
    unsigned long prev;
    switch (size) {
        case 1:
            __asm__ __volatile__("lock; cmpxchgb %b1,%2"
                    : "=a"(prev)
                    : "q"(new_ptr), "m"(*__synch_xg(ptr)),
                    "0"(old_ptr)
                    : "memory");
            return prev;
        case 2:
            __asm__ __volatile__("lock; cmpxchgw %w1,%2"
                    : "=a"(prev)
                    : "r"(new_ptr), "m"(*__synch_xg(ptr)),
                    "0"(old_ptr)
                    : "memory");
            return prev;
#ifdef __x86_64__
        case 4:
            __asm__ __volatile__("lock; cmpxchgl %k1,%2"
                    : "=a"(prev)
                    : "r"(new_ptr), "m"(*__synch_xg(ptr)),
                    "0"(old_ptr)
                    : "memory");
            return prev;
        case 8:
            __asm__ __volatile__("lock; cmpxchgq %1,%2"
                    : "=a"(prev)
                    : "r"(new_ptr), "m"(*__synch_xg(ptr)),
                    "0"(old_ptr)
                    : "memory");
            return prev;
#else
        case 4:
            __asm__ __volatile__("lock; cmpxchgl %1,%2"
                    : "=a"(prev)
                    : "r"(new_ptr), "m"(*__synch_xg(ptr)),
                    "0"(old_ptr)
                    : "memory");
            return prev;
#endif
    }
    return old_ptr;
}


static __inline__ void synch_set_bit(int nr, volatile void * addr)
{
    __asm__ __volatile__ ( 
        "lock btsl %1,%0"
        : "=m" (ADDR) : "Ir" (nr) : "memory" );
}

static __inline__ void synch_clear_bit(int nr, volatile void * addr)
{
    __asm__ __volatile__ (
        "lock btrl %1,%0"
        : "=m" (ADDR) : "Ir" (nr) : "memory" );
}

static __inline__ int synch_test_and_set_bit(int nr, volatile void * addr)
{
    int oldbit;
    __asm__ __volatile__ (
        "lock btsl %2,%1\n\tsbbl %0,%0"
        : "=r" (oldbit), "=m" (ADDR) : "Ir" (nr) : "memory");
    return oldbit;
}

static __inline__ int synch_test_and_clear_bit(int nr, volatile void * addr)
{
    int oldbit;
    __asm__ __volatile__ (
        "lock btrl %2,%1\n\tsbbl %0,%0"
        : "=r" (oldbit), "=m" (ADDR) : "Ir" (nr) : "memory");
    return oldbit;
}

static __inline__ int synch_const_test_bit(int nr, const volatile void * addr)
{
    return ((1UL << (nr & 31)) & 
            (((const volatile unsigned int *) addr)[nr >> 5])) != 0;
}

static __inline__ int synch_var_test_bit(int nr, volatile void * addr)
{
    int oldbit;
    __asm__ __volatile__ (
        "btl %2,%1\n\tsbbl %0,%0"
        : "=r" (oldbit) : "m" (ADDR), "Ir" (nr) );
    return oldbit;
}

#define synch_test_bit(nr,addr) \
(__builtin_constant_p(nr) ? \
 synch_const_test_bit((nr),(addr)) : \
 synch_var_test_bit((nr),(addr)))


#undef ADDR

#endif /* not assembly */
#endif /* _OS_H_ */
