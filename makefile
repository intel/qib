VERSION=$(shell grep Version META | sed -e "s/Version:[ \t]*\(.*\)/\1/")
RELEASE=test
KERNVER=$(shell uname -r)
KERNDIR=/usr/src/kernels/$(KERNVER)

default:
	make RELEASE=$(VERSION)-$(RELEASE)$(KERNVER) -C $(KERNDIR) M=`pwd`

clean:
	make -C /usr/src/kernels/`uname -r` M=`pwd` clean
	rm -f *.tgz

dist: clean
	mkdir -p /tmp/qib-$(VERSION); \
	sed -e 's/#VERSION#/'$(VERSION)'/g' qib.spec.in > /tmp/qib-$(VERSION)/qib.spec ; \
	cp -a * /tmp/qib-$(VERSION); \
	pushd /tmp; \
	rm -f ./qib-$(VERSION)/qib.spec.in ./qib-$(VERSION)/cscope*; \
	tar czf qib-$(VERSION).tgz ./qib-$(VERSION); \
	popd; \
	mv /tmp/qib-$(VERSION).tgz .

install:
	mkdir -p $(RPM_BUILD_ROOT)/lib/modules/$(KERNVER)/updates
	install ib_qib.ko $(RPM_BUILD_ROOT)/lib/modules/$(KERNVER)/updates
