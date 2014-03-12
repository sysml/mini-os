#ifndef _SHUTDOWN_H_
#define _SHUTDOWN_H_

void init_shutdown(void);

void kernel_shutdown(int reason) __attribute__((noreturn));

#endif
