#ifndef _POSIX_SYS_IN_H_
#define _POSIX_SYS_IN_H_

#include <fcntl.h>
#include <lwip/sockets.h>

#include <netinet/in6.h>

#ifndef CONFIG_LWIP
/**
 * Convert an u16_t from host- to network byte order.
 *
 * @param n u16_t in host byte order
 * @return n in network byte order
 */
inline u16_t
htons(u16_t n)
{
	return ((n & 0xff) << 8) | ((n & 0xff00) >> 8);
}

/**
 * Convert an u16_t from network- to host byte order.
 *
 * @param n u16_t in network byte order
 * @return n in host byte order
 */
inline u16_t
ntohs(u16_t n)
{
	return htons(n);
}

/**
 * Convert an u32_t from host- to network byte order.
 *
 * @param n u32_t in host byte order
 * @return n in network byte order
 */
inline u32_t
htonl(u32_t n)
{
	return ((n & 0xff) << 24) |
		((n & 0xff00) << 8) |
		((n & 0xff0000UL) >> 8) |
		((n & 0xff000000UL) >> 24);
}

/**
 * Convert an u32_t from network- to host byte order.
 *
 * @param n u32_t in network byte order
 * @return n in host byte order
 */
inline u32_t
ntohl(u32_t n)
{
	return htonl(n);
}
#endif

#endif /* _POSIX_SYS_IN_H_ */
