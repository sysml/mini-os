/*
 *          MiniOS
 *
 *   file: netmap.h
 *
 * Authors: Joao Martins <joao.martins@neclab.eu>
 *
 *
 * Copyright (c) 2014, NEC Europe Ltd., NEC Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * THIS HEADER MAY NOT BE EXTRACTED OR MODIFIED IN ANY WAY.
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
