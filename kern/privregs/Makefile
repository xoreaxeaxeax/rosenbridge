ARCH := $(shell getconf LONG_BIT)
KERNEL_DIR := /lib/modules/$(shell uname -r)/build

obj-m:=privregs.o

default:
	$(MAKE) -C $(KERNEL_DIR) M=$(shell pwd) modules

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(shell pwd) modules clean
