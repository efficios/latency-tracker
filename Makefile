ifneq ($(KERNELRELEASE),)

TOP_LT_MODULES_DIR := $(shell dirname $(lastword $(MAKEFILE_LIST)))

include $(TOP_LT_MODULES_DIR)/Makefile.ABI.workarounds

ccflags-y += -I$(src)/include $(EXTCFLAGS) -g -Wall

latency_tracker-objs := tracker.o rculfhash.o rculfhash-mm-chunk.o wfcqueue.o \
	tracker_debugfs.o wrapper/trace-clock.o

latency_tracker-objs += $(shell \
	if [ $(VERSION) -ge 4 -o \
		\( $(VERSION) -eq 3 -a $(PATCHLEVEL) -ge 15 -a $(SUBLEVEL) -ge 0 \) ] ; then \
	echo "lttng-tracepoint.o" ; fi;)

obj-m := latency_tracker.o

latency_tracker_wakeup-objs := examples/wakeup_latency.o examples/wakeup_proc.o
obj-m += latency_tracker_wakeup.o

latency_tracker_offcpu-objs := examples/offcpu.o examples/offcpu_proc.o wrapper/trace-clock.o
obj-m += latency_tracker_offcpu.o

latency_tracker_syscalls-objs := examples/syscalls.o examples/syscalls_proc.o wrapper/trace-clock.o
obj-m += latency_tracker_syscalls.o

latency_tracker_block-objs := examples/block_latency_tp.o
obj-m += latency_tracker_block.o

latency_tracker_block_hist-objs := examples/block_hist.o examples/block_hist_kprobes.o \
	wrapper/trace-clock.o
obj-m += latency_tracker_block_hist.o

latency_tracker_network_stack-objs := examples/network_stack_latency.o
obj-m += latency_tracker_network_stack.o

latency_tracker_critical_timing-objs := examples/critical_timing.o wrapper/trace-clock.o tracker_debugfs.o
obj-m += latency_tracker_critical_timing.o

latency_tracker_rt-objs := examples/rt.o wrapper/trace-clock.o tracker_debugfs.o
obj-m += latency_tracker_rt.o

obj-m += latency_tracker_begin_end.o

latency_tracker_ttfb-objs := examples/ttfb.o wrapper/trace-clock.o
obj-m += latency_tracker_ttfb.o

else # KERNELRELEASE

# This part of the Makefile is used when the 'make' command is run in the
# base directory of the latency-tracker sources. It sets some environment and
# calls the kernel build system to build the actual modules.

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
CFLAGS = $(EXTCFLAGS)

default: modules

modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

modules_install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

endif # KERNELRELEASE
