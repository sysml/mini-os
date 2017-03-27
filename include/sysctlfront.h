#ifndef _SYSCTL_H_
#define _SYSCTL_H_

int  sysctlfront_store_init(void);
void sysctlfront_store_fini(void);
int  sysctlfront_store_wait(void);
void sysctlfront_store_stop_waiting(void);

#endif /* _SYSCTL_H_ */
