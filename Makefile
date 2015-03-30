ccflags-y += -I$(PWD)/include $(EXTCFLAGS)

latency_tracker-objs := tracker.o rculfhash.o rculfhash-mm-chunk.o wfcqueue.o

ifneq ($(KERNELRELEASE),)
latency_tracker-objs += $(shell \
	if [ $(VERSION) -eq 3 -a $(PATCHLEVEL) -ge 15 -a $(SUBLEVEL) -ge 0 ] ; then \
	echo "lttng-tracepoint.o" ; fi;)
endif

obj-m := latency_tracker.o

latency_tracker_wakeup-objs := examples/wakeup_latency.o examples/wakeup_proc.o
obj-m += latency_tracker_wakeup.o

latency_tracker_offcpu-objs := examples/offcpu.o examples/offcpu_proc.o
obj-m += latency_tracker_offcpu.o

latency_tracker_syscalls-objs := examples/syscalls.o examples/syscalls_proc.o wrapper/trace-clock.o
obj-m += latency_tracker_syscalls.o

latency_tracker_block-objs := examples/block_latency_tp.o
obj-m += latency_tracker_block.o

latency_tracker_network_stack-objs := examples/network_stack_latency.o
obj-m += latency_tracker_network_stack.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
default:
	        $(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

modules_install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

clean:
	        $(MAKE) -C $(KDIR) M=$(PWD) clean
