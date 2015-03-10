ccflags-y += -I$(PWD)/include $(EXTCFLAGS)

tracker-objs := latency_tracker.o rculfhash.o rculfhash-mm-chunk.o

ifneq ($(KERNELRELEASE),)
tracker-objs += $(shell \
	if [ $(VERSION) -eq 3 -a $(PATCHLEVEL) -ge 15 -a $(SUBLEVEL) -ge 0 ] ; then \
	echo "lttng-tracepoint.o" ; fi;)
endif

obj-m := tracker.o

wakeup_latency-objs := examples/wakeup_latency.o examples/wakeup_proc.o
obj-m += wakeup_latency.o

offcpu-objs := examples/offcpu.o examples/offcpu_proc.o
obj-m += offcpu.o

syscalls-objs := examples/syscalls.o examples/syscalls_proc.o
obj-m += syscalls.o

block_latency-objs := examples/block_latency_tp.o
obj-m += block_latency.o

network_stack_latency-objs := examples/network_stack_latency.o
obj-m += network_stack_latency.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
default:
	        $(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

modules_install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

clean:
	        $(MAKE) -C $(KDIR) M=$(PWD) clean
