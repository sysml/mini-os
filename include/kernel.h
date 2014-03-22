#ifndef _KERNEL_H_
#define _KERNEL_H_

extern void do_exit(void) __attribute__((noreturn));
extern void stop_kernel(void);

void pre_suspend(void);
void post_suspend(int canceled);

#endif /* _KERNEL_H_ */
