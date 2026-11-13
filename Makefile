# SPDX-License-Identifier: GPL-2.0-only

obj-m += ihook.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=arm64 modules

test:
	$(MAKE) -C $(KDIR) M=$(PWD)/tests ARCH=arm64 modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	$(MAKE) -C $(KDIR) M=$(PWD)/tests clean
