obj-m := latency_tracker.o examples/block_latency_tp.o examples/sched_latency_tp.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
default:
	        $(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
