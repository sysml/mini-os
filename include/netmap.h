/*
 *          MiniOS
 *
 *   file: netmap.h
 *
 *          NEC Europe Ltd. PROPRIETARY INFORMATION
 *
 * This software is supplied under the terms of a license agreement
 * or nondisclosure agreement with NEC Europe Ltd. and may not be
 * copied or disclosed except in accordance with the terms of that
 * agreement. The software and its source code contain valuable trade
 * secrets and confidential information which have to be maintained in
 * confidence.
 * Any unauthorized publication, transfer to third parties or duplication
 * of the object or source code - either totally or in part – is
 * prohibited.
 *
 *      Copyright (c) 2014 NEC Europe Ltd. All Rights Reserved.
 *
 * Authors: Joao Martins <joao.martins@neclab.eu>
 *
 * NEC Europe Ltd. DISCLAIMS ALL WARRANTIES, EITHER EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE AND THE WARRANTY AGAINST LATENT
 * DEFECTS, WITH RESPECT TO THE PROGRAM AND THE ACCOMPANYING
 * DOCUMENTATION.
 *
 * No Liability For Consequential Damages IN NO EVENT SHALL NEC Europe
 * Ltd., NEC Corporation OR ANY OF ITS SUBSIDIARIES BE LIABLE FOR ANY
 * DAMAGES WHATSOEVER (INCLUDING, WITHOUT LIMITATION, DAMAGES FOR LOSS
 * OF BUSINESS PROFITS, BUSINESS INTERRUPTION, LOSS OF INFORMATION, OR
 * OTHER PECUNIARY LOSS AND INDIRECT, CONSEQUENTIAL, INCIDENTAL,
 * ECONOMIC OR PUNITIVE DAMAGES) ARISING OUT OF THE USE OF OR INABILITY
 * TO USE THIS PROGRAM, EVEN IF NEC Europe Ltd. HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 *
 *     THIS HEADER MAY NOT BE EXTRACTED OR MODIFIED IN ANY WAY.
 */
#ifndef _NET_NETMAP_MINI_H_
#define _NET_NETMAP_MINI_H_

#define NM_CACHE_ALIGN	128
struct netmap_slot {
	uint32_t buf_idx; /* buffer index */
	uint16_t len;	/* packet length, to be copied to/from the hw ring */
	uint16_t flags;	/* buf changed, etc. */
    uint64_t ptr; /* grant reference or indirect buffer */
};

struct netmap_ring {
	/*
	 * buf_ofs is meant to be used through macros.
	 * It contains the offset of the buffer region from this
	 * descriptor.
	 */
	const int64_t	buf_ofs;
	const uint32_t	num_slots;	/* number of slots in the ring. */
	const uint32_t	nr_buf_size;
	const uint16_t	ringid;
	const uint16_t	dir;		/* 0: tx, 1: rx */

	uint32_t        head;		/* (u) first user slot */
	uint32_t        cur;		/* (u) wakeup point */
	uint32_t	tail;		/* (k) first kernel slot */

	uint32_t	flags;

	struct timeval	ts;		/* (k) time of last *sync() */

	/* opaque room for a mutex or similar object */
	uint8_t		sem[128] __attribute__((__aligned__(NM_CACHE_ALIGN)));

	/* the slots follow. This struct has variable size */
	struct netmap_slot slot[0];	/* array of slots. */
};

#define	NETMAP_RING_NEXT(r, i)				\
	((i)+1 == (r)->num_slots ? 0 : (i) + 1 )

/*
 * check if space is available in the ring.
 */
static inline int
nm_ring_empty(struct netmap_ring *ring)
{
	return (ring->cur == ring->tail);
}

static inline int
nm_ring_space(struct netmap_ring *ring)
{
        int ret = ring->tail - ring->cur;
        if (ret < 0)
                ret += ring->num_slots;
        return ret;
}

static inline 
void pkt_copy(const void *_src, void *_dst, int l)
{
	const uint64_t *src = _src;
	uint64_t *dst = _dst;
	for (; l > 0; l-=64) {
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
	}
}


#endif /* _NET_NETMAP_MINI_H_ */
