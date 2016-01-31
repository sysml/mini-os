/*
 * lwip/arch/cc.h
 *
 * Compiler-specific types and macros for lwIP running on mini-os
 *
 * Tim Deegan <Tim.Deegan@eu.citrix.net>, July 2007
 * Simon Kuenzer <Simon.Kuenzer@neclab.eu>, October 2014
 */

#ifndef __LWIP_ARCH_CC_H__
#define __LWIP_ARCH_CC_H__

#include <mini-os/os.h>
#include <mini-os/types.h>
#include <mini-os/lib.h>
#include <time.h>
#include <errno.h>

/* Typedefs for the types used by lwip */
typedef uint8_t  u8_t;
typedef int8_t   s8_t;
typedef uint16_t u16_t;
typedef int16_t  s16_t;
typedef uint32_t u32_t;
typedef int32_t  s32_t;
typedef uint64_t u64_t;
typedef int64_t  s64_t;
typedef uintptr_t mem_ptr_t;

#include <inttypes.h>
#define S16_F PRIi16
#define U16_F PRIu16
#define X16_F PRIx16
#define S32_F PRIi32
#define U32_F PRIu32
#define X32_F PRIx32
#define SZT_F "uz"

/* byte-swapping */
#ifdef HAVE_LIBC
#include <machine/endian.h>
#ifndef BIG_ENDIAN
#error endian.h does not define byte order
#endif
#else
#include <endian.h>
#endif

/* 32 bit checksum calculation */
#define LWIP_CHKSUM_ALGORITHM 3
#ifdef CONFIG_NETFRONT_PERSISTENT_GRANTS
#define ETH_PAD_SIZE 2
#else
#define ETH_PAD_SIZE 0
#endif

/* rand */
#define LWIP_RAND() ((u32_t)rand())

/* compiler hints for packing lwip's structures */
#define PACK_STRUCT_FIELD(_x)  _x
#define PACK_STRUCT_STRUCT     __attribute__ ((packed))
#define PACK_STRUCT_BEGIN
#define PACK_STRUCT_END

/* platform specific diagnostic output */
#define LWIP_PLATFORM_DIAG(_x) do { printf("lwip: "); printf _x; } while (0)
#define LWIP_PLATFORM_ASSERT(_x) do { printf("lwip: Assertion \"%s\" failed at line %d in %s\n", \
                                             _x, __LINE__, __FILE__); fflush(stdout); BUG(); } while(0)

/* lightweight synchronization mechanisms */
#define SYS_ARCH_DECL_PROTECT(_x)  int (_x)
#define SYS_ARCH_PROTECT(_x)       local_irq_save((_x))
#define SYS_ARCH_UNPROTECT(_x)     local_irq_restore((_x))

#endif /* __LWIP_ARCH_CC_H__ */
