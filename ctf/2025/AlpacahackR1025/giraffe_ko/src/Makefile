obj-m := driver.o
KBUILD_DIR := /path/to/linux-6.12.10

ccflags-remove-y := -fstack-protector-strong
ccflags-y += -fno-stack-protector -fno-stack-check -fno-stack-clash-protection \
             -fno-builtin -D__NO_FORTIFY_SOURCE

all:
	$(MAKE) -C $(KBUILD_DIR) M=$(shell pwd) modules

clean:
	$(MAKE) -C $(KBUILD_DIR) M=$(shell pwd) clean
