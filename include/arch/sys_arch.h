/*
 * lwip/arch/sys_arch.h
 *
 * Arch-specific semaphores and mailboxes for lwIP running on mini-os
 *
 * Tim Deegan <Tim.Deegan@eu.citrix.net>, July 2007
 * Simon Kuenzer <Simon.Kuenzer@neclab.eu>, October 2014
 */

#ifndef __LWIP_ARCH_SYS_ARCH_H__
#define __LWIP_ARCH_SYS_ARCH_H__

#include <mini-os/os.h>
#include <mini-os/xmalloc.h>
#include <mini-os/semaphore.h>

#define LWIP_COMPAT_MUTEX 1 /* enables emulation of mutex with
                             * binary semaphores */

#define SYS_SEM_NULL  NULL
#define SYS_MBOX_NULL NULL

struct lwip_sem {
    struct semaphore sem;
    int valid;
};

struct lwip_mbox {
    int count;
    void **messages;
    struct semaphore read_sem;
    struct semaphore write_sem;
    int writer;
    int reader;
    int valid;
};

typedef struct lwip_sem sys_sem_t;
typedef struct lwip_mbox sys_mbox_t;
typedef struct thread *sys_thread_t;
typedef unsigned long sys_prot_t;

#endif /*__LWIP_ARCH_SYS_ARCH_H__ */
