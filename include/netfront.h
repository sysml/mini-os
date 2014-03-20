#include <mini-os/wait.h>
#ifdef HAVE_LWIP
#include <lwip/netif.h>
#include <lwip/netif/etharp.h>
#endif
struct netfront_dev;
void network_rx(struct netfront_dev *dev);
void netfront_set_rx_handler(struct netfront_dev *dev, void (*thenetif_rx)(unsigned char* data, int len, void *arg), void *arg);
struct netfront_dev *init_netfront(char *nodename, void (*netif_rx)(unsigned char *data, int len, void *arg), unsigned char rawmac[6], char **ip);
void netfront_xmit(struct netfront_dev *dev, unsigned char* data,int len);
void netfront_clean_tx_ring(struct netfront_dev *dev);
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
