#
# Makefile for the linux duet framework
#
CONFIG_MODULE_SIG=n

KDIR ?= /lib/modules/`uname -r`/build

obj-m := duet.o
duet-y += init.o ioctl.o task.o bittree.o hash.o hook.o itree.o

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

debug:
	KCPPFLAGS="-DDUET_DEBUG" $(MAKE) -C $(KDIR) M=$(PWD) modules

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
