/*
 * Copyright (c) 2006, 2007, 2009 QLogic Corporation. All rights reserved.
 * Copyright (c) 2005, 2006 PathScale, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "qib.h"

/**
 * qib_alloc_lkey - allocate an lkey
 * @mr: memory region that this lkey protects
 * @dma_region: 0->normal key, 1->restricted DMA key
 *
 * Returns 0 if successful, otherwise returns -errno.
 *
 * Increments mr reference count and sets published
 * as required.
 *
 * Sets the lkey field mr for non-dma regions.
 *
 */

int qib_alloc_lkey(struct qib_mregion *mr, int dma_region)
{
	unsigned long flags;
	u32 r;
	u32 n;
	int ret = 0;
	struct qib_ibdev *dev = to_idev(mr->pd->device);
	struct qib_lkey_table *rkt = &dev->lk_table;

	spin_lock_irqsave(&rkt->lock, flags);

	/* special case for dma_mr lkey == 0 */
	if (dma_region) {
		/* should the dma_mr be relative to the pd? */
		if (!dev->dma_mr) {
			qib_get_mr(mr);
			dev->dma_mr = mr;
			mr->lkey_published = 1;
		}
		goto success;
	}

	/* Find the next available LKEY */
	r = rkt->next;
	n = r;
	for (;;) {
		if (rkt->table[r] == NULL)
			break;
		r = (r + 1) & (rkt->max - 1);
		if (r == n) {
			qib_dbg("LKEY table full\n");
			goto bail;
		}
	}
	rkt->next = (r + 1) & (rkt->max - 1);
	/*
	 * Make sure lkey is never zero which is reserved to indicate an
	 * unrestricted LKEY.
	 */
	rkt->gen++;
	mr->lkey = (r << (32 - ib_qib_lkey_table_size)) |
		((((1 << (24 - ib_qib_lkey_table_size)) - 1) & rkt->gen)
		 << 8);
	if (mr->lkey == 0) {
		mr->lkey |= 1 << 8;
		rkt->gen++;
	}
	qib_get_mr(mr);
	rkt->table[r] = mr;
	mr->lkey_published = 1;
success:
	spin_unlock_irqrestore(&rkt->lock, flags);
out:
	return ret;
bail:
	spin_unlock_irqrestore(&rkt->lock, flags);
	ret = -ENOMEM;
	goto out;
}

/**
 * qib_free_lkey - free an lkey
 * @mr: mr to free from tables
 */
void qib_free_lkey(struct qib_mregion *mr)
{
	unsigned long flags;
	u32 lkey = mr->lkey;
	u32 r;
	struct qib_ibdev *dev = to_idev(mr->pd->device);
	struct qib_lkey_table *rkt = &dev->lk_table;

	spin_lock_irqsave(&rkt->lock, flags);
	if (!mr->lkey_published)
		goto out;
	mr->lkey_published = 0;
	if (lkey == 0) {
		if (dev->dma_mr && dev->dma_mr == mr) {
			qib_put_mr(dev->dma_mr);
			dev->dma_mr = NULL;
		}
	} else {
		r = lkey >> (32 - ib_qib_lkey_table_size);
		qib_put_mr(mr);
		rkt->table[r] = NULL;
	}
out:
	spin_unlock_irqrestore(&rkt->lock, flags);
}

/**
 * qib_lkey_ok - check IB SGE for validity and initialize
 * @rkt: table containing lkey to check SGE against
 * @isge: outgoing internal SGE
 * @sge: SGE to check
 * @acc: access flags
 *
 * Return 1 if valid and successful, otherwise returns 0.
 *
 * Check the IB SGE for validity and initialize our internal version
 * of it.
 */
int qib_lkey_ok(struct qib_lkey_table *rkt, struct qib_pd *pd,
		struct qib_sge *isge, struct ib_sge *sge, int acc)
{
	struct qib_mregion *mr;
	unsigned n, m;
	size_t off;
	unsigned long flags;

	/*
	 * We use LKEY == zero for kernel virtual addresses
	 * (see qib_get_dma_mr and qib_dma.c).
	 */
	spin_lock_irqsave(&rkt->lock, flags);
	if (sge->lkey == 0) {
		struct qib_ibdev *dev = to_idev(pd->ibpd.device);

		if (pd->user)
			goto bail;
		if (!dev->dma_mr)
			goto bail;
		qib_get_mr(dev->dma_mr);
		spin_unlock_irqrestore(&rkt->lock, flags);

		isge->mr = dev->dma_mr;
		isge->vaddr = (void *) sge->addr;
		isge->length = sge->length;
		isge->sge_length = sge->length;
		isge->m = 0;
		isge->n = 0;
		goto ok;
	}
	mr = rkt->table[(sge->lkey >> (32 - ib_qib_lkey_table_size))];
	if (unlikely(mr == NULL || mr->lkey != sge->lkey ||
		     mr->pd != &pd->ibpd))
		goto bail;

	off = sge->addr - mr->user_base;
	if (unlikely(sge->addr < mr->user_base ||
		     off + sge->length > mr->length ||
		     (mr->access_flags & acc) != acc))
		goto bail;
	qib_get_mr(mr);
	spin_unlock_irqrestore(&rkt->lock, flags);

	off += mr->offset;
	if (mr->page_shift) {
		/*
		page sizes are uniform power of 2 so no loop is necessary
		entries_spanned_by_off is the number of times the loop below
		would have executed.
		*/
		size_t entries_spanned_by_off;
		
		entries_spanned_by_off = off >> mr->page_shift;
		off -= (entries_spanned_by_off << mr->page_shift);
		m = entries_spanned_by_off/QIB_SEGSZ;
		n = entries_spanned_by_off%QIB_SEGSZ;
	} else {
		m = 0;
		n = 0;
		while (off >= mr->map[m]->segs[n].length) {
			off -= mr->map[m]->segs[n].length;
			n++;
			if (n >= QIB_SEGSZ) {
				m++;
				n = 0;
			}
		}
	}
	isge->mr = mr;
	isge->vaddr = mr->map[m]->segs[n].vaddr + off;
	isge->length = mr->map[m]->segs[n].length - off;
	isge->sge_length = sge->length;
	isge->m = m;
	isge->n = n;
ok:
	return 1;
bail:
	spin_unlock_irqrestore(&rkt->lock, flags);
	return 0;
}

/**
 * qib_rkey_ok - check the IB virtual address, length, and RKEY
 * @dev: infiniband device
 * @ss: SGE state
 * @len: length of data
 * @vaddr: virtual address to place data
 * @rkey: rkey to check
 * @acc: access flags
 *
 * Return 1 if successful, otherwise 0.
 */
int qib_rkey_ok(struct qib_qp *qp, struct qib_sge *sge,
		u32 len, u64 vaddr, u32 rkey, int acc)
{
	struct qib_lkey_table *rkt = &to_idev(qp->ibqp.device)->lk_table;
	struct qib_mregion *mr;
	unsigned n, m;
	size_t off;
	unsigned long flags;

	/*
	 * We use RKEY == zero for kernel virtual addresses
	 * (see qib_get_dma_mr and qib_dma.c).
	 */
	spin_lock_irqsave(&rkt->lock, flags);
	if (rkey == 0) {
		struct qib_pd *pd = to_ipd(qp->ibqp.pd);
		struct qib_ibdev *dev = to_idev(pd->ibpd.device);

		if (pd->user)
			goto bail;
		if (!dev->dma_mr)
			goto bail;
		qib_get_mr(dev->dma_mr);
		spin_unlock_irqrestore(&rkt->lock, flags);

		sge->mr = dev->dma_mr;
		sge->vaddr = (void *) vaddr;
		sge->length = len;
		sge->sge_length = len;
		sge->m = 0;
		sge->n = 0;
		goto ok;
	}

	mr = rkt->table[(rkey >> (32 - ib_qib_lkey_table_size))];
	if (unlikely(mr == NULL || mr->lkey != rkey || qp->ibqp.pd != mr->pd))
		goto bail;

	off = vaddr - mr->iova;
	if (unlikely(vaddr < mr->iova || off + len > mr->length ||
		     (mr->access_flags & acc) == 0))
		goto bail;
	qib_get_mr(mr);
	spin_unlock_irqrestore(&rkt->lock, flags);

	off += mr->offset;
	if (mr->page_shift) {
		/*
		page sizes are uniform power of 2 so no loop is necessary
		entries_spanned_by_off is the number of times the loop below
		would have executed.
		*/
		size_t entries_spanned_by_off;
		
		entries_spanned_by_off = off >> mr->page_shift;
		off -= (entries_spanned_by_off << mr->page_shift);
		m = entries_spanned_by_off/QIB_SEGSZ;
		n = entries_spanned_by_off%QIB_SEGSZ;
	} else {
		m = 0;
		n = 0;
		while (off >= mr->map[m]->segs[n].length) {
			off -= mr->map[m]->segs[n].length;
			n++;
			if (n >= QIB_SEGSZ) {
				m++;
				n = 0;
			}
		}
	}
	sge->mr = mr;
	sge->vaddr = mr->map[m]->segs[n].vaddr + off;
	sge->length = mr->map[m]->segs[n].length - off;
	sge->sge_length = len;
	sge->m = m;
	sge->n = n;
ok:
	return 1;
bail:
	spin_unlock_irqrestore(&rkt->lock, flags);
	return 0;
}
