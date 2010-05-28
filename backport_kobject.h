/**
 * More Chaos4.3 backport stuff.
 */

struct kobject *kobject_create_and_add(const char *name, struct kobject *parent);
int kobject_init_and_add(struct kobject *kobj, struct kobj_type *ktype,
                         struct kobject *parent, const char *fmt, ...);

int ib_sysfs_create_port_files(struct ib_device *device,
			       int (*create)(struct ib_device *dev, u8 port_num,
					     struct kobject *kobj));

static inline
struct kmem_cache *
kmem_cache_create_for_2_6_22 (const char *name, size_t size, size_t align,
			      unsigned long flags,
			      void (*ctor)(void*, struct kmem_cache *, unsigned long)
			      )
{
	return kmem_cache_create(name, size, align, flags, ctor, NULL);
}

#define kmem_cache_create kmem_cache_create_for_2_6_22

typedef irqreturn_t (*backport_irq_handler_t)(int, void *);

static inline int 
backport_request_irq(unsigned int irq,
                     irqreturn_t (*handler)(int, void *),
                     unsigned long flags, const char *dev_name, void *dev_id)
{
	return request_irq(irq, 
		           (irqreturn_t (*)(int, void *, struct pt_regs *))handler, 
			   flags, dev_name, dev_id);
}

#define request_irq backport_request_irq
#define irq_handler_t backport_irq_handler_t

