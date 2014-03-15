#ifndef _SHUTDOWN_H_
#define _SHUTDOWN_H_

#include <mini-os/hypervisor.h>

void init_shutdown(start_info_t *si);

void kernel_shutdown(int reason) __attribute__((noreturn));
void kernel_suspend(void);

#endif
