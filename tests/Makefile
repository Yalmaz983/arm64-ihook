# SPDX-License-Identifier: GPL-2.0-only

obj-m += ihook_test.o
ihook_test-y := ../ihook.o ihook_test.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=arm64 modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
