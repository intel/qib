/**
 * Add this to support the backport to Chaos 4.3
 */

#define sg_page(a) (a)->page

static inline void sg_assign_page(struct scatterlist *sg, struct page *page)
{
	sg->page = page;
}

#define for_each_sg(sglist, sg, nr, __i)	\
	for (__i = 0, sg = (sglist); __i < (nr); __i++, sg++)

static inline struct scatterlist *sg_next(struct scatterlist *sg)
{
	if (!sg) {
		BUG();
		return NULL;
	}
	return sg + 1;
}


