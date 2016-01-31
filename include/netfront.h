#include <mini-os/wait.h>
#ifdef HAVE_LWIP
#include <lwip/netif.h>
#include <lwip/netif/etharp.h>
#endif

#if defined CONFIG_NETFRONT_LWIP_ONLY && !defined HAVE_LWIP
#error "netfront: Cannot build netfront purely for lwIP without having lwIP"
#endif

struct netfront_dev;
void netfront_rx(struct netfront_dev *dev);
#define network_rx(dev) netfront_rx(dev);
#ifndef CONFIG_NETFRONT_LWIP_ONLY
void netfront_set_rx_handler(struct netfront_dev *dev, void (*thenetif_rx)(unsigned char* data, int len, void *arg), void *arg);
void netfront_xmit(struct netfront_dev *dev, unsigned char* data, int len);
#endif
struct netfront_dev *init_netfront(char *nodename, void (*netif_rx)(unsigned char *data, int len, void *arg), unsigned char rawmac[6], char **ip);
#ifdef HAVE_LWIP
void netfront_set_rx_pbuf_handler(struct netfront_dev *dev, void (*thenetif_rx)(struct pbuf *p, void *arg), void *arg);
err_t netfront_xmit_pbuf(struct netfront_dev *dev, struct pbuf *p, int co_type, int push);
void netfront_xmit_push(struct netfront_dev *dev);
#endif
void shutdown_netfront(struct netfront_dev *dev);
void suspend_netfront(void);
void resume_netfront(void);
#ifdef HAVE_LIBC
int netfront_tap_open(char *nodename);
ssize_t netfront_receive(struct netfront_dev *dev, unsigned char *data, size_t len);
#endif

extern struct wait_queue_head netfront_queue;

#ifdef HAVE_LWIP
struct eth_addr *netfront_get_hwaddr(struct netfront_dev *dev, struct eth_addr *out);

#if defined CONFIG_START_NETWORK || defined CONFIG_INCLUDE_START_NETWORK
/* Call this to bring up the netfront interface and the lwIP stack.
 * N.B. _must_ be called from a thread; it's not safe to call this from 
 * app_main(). */
void start_networking(void);
void stop_networking(void);
#ifdef CONFIG_LWIP_NOTHREADS
/* Note: DHCP is not yet supported when CONFIG_LWIP_NOTHREADS is set */
void poll_networking(void);
#endif

void networking_set_addr(struct ip_addr *ipaddr, struct ip_addr *netmask, struct ip_addr *gw);
#endif
#endif

#ifdef CONFIG_SELECT_POLL
int netfront_get_fd(struct netfront_dev *dev);
#endif
