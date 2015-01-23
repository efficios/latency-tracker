ccflags-y += -I$(PWD)/include

tracker-objs := latency_tracker.o
tracker-objs += $(shell \
	if [ $(VERSION) -eq 3 -a $(PATCHLEVEL) -ge 15 -a $(SUBLEVEL) -ge 0 ] ; then \
	echo "lttng-tracepoint.o" ; fi;)
obj-m := tracker.o

sched_latency-objs := examples/sched_latency_tp.o
obj-m += sched_latency.o

block_latency-objs := examples/block_latency_tp.o
obj-m += block_latency.o

network_stack_latency-objs := examples/network_stack_latency.o
obj-m += network_stack_latency.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
default:
	        $(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	        $(MAKE) -C $(KDIR) M=$(PWD) clean
