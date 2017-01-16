latency-tracker
=============

_by [Julien Desfossez](mailto:jdesfossez@efficios.com), [Mathieu Desnoyers](mailto:mathieu.desnoyers@efficios.com)_

This kernel module is a simple latency tracker. It is designed to be called
from anywhere in the kernel (mostly used with tracepoints and kprobes) and is
designed to execute actions when an operation takes longer than a specified
threshold. It can also be configured to execute an action if an operation is
not completed before a timeout is reached.

The basic idea is to call the `latency_tracker_event_in($key)` at the beginning
and `latency_tracker_event_out($key)` at the end of an operation, no matter
where the operation begins and ends, only the `key` must match. A `threshold`
is configured by the user through a `debugfs` interface (using `cat` and
`echo`). If the delay between the entry and exit event is higher than the
`threshold`, a callback action is executed. By default, all trackers have a
`wakeup_pipe` file. This file blocks the `read` operation until a callback is
emitted. Most trackers also emit a tracepoint event when the callback is
executed. These events can be collected by the kernel tracers (`LTTng`,
`ftrace` and `perf`).

The latency-tracker takes care of the out-of-context memory allocation,
refcounting and synchronisation required to scale this kind of measurement and
reaction to highly concurrent environments. It is designed to be fast and to be
called from various execution contexts including IRQ and NMI handlers. The core
of the tracker relies on the [userspace-rcu](http://liburcu.org/) lock-less
hashtable ported to the kernel to match the entry and exit events, and the
kernel lock-less RCU linked-list to handle the memory. The latency-tracker has
its own NUMA-aware memory allocator to avoid doing allocation/freeing during
the measurements.

It is a work in progress and operates in very sensitive contexts, so make sure
to try it in a non-critical environment before deploying it in production.

The main intent is to use it to output alerts, latency metrics and run
diagnostic scripts on production servers or embedded platforms when debugging
hard to diagnose latency problems. Also, it should be fast enough to run as a
background monitoring tool without a significant impact on the production.

Coupled with a buffering kernel tracer (`LTTng` in snapshot mode or `ftrace`),
it can be used to stop the tracing and extract the trace from memory only when
an unusual latency is detected. This use-case is very powerful to collect
highly detailed information but still keep the trace short enough and focused
around the interesting event. The emitted tracepoint event also serves as an
entry point when analysing the trace either manually or with
[LTTng-analyses](https://github.com/lttng-analyses).

This project exposes the `latency-tracker` API to other kernel modules, but
also comes with a list of ready-to-use trackers (source code in
[`trackers`](trackers/)).

Installation requirements
-------------------------
  - Linux kernel starting at 3.12 (or 3.10 in RHEL7)
  - Linux kernel headers (`linux-headers-generic` on ubuntu)
  - gcc and make

On Ubuntu:

```
apt-get update
apt-get install git gcc make linux-headers-generic
git clone https://github.com/efficios/latency-tracker.git
cd latency_tracker
make
```

Usage
-----

The `latency_tracker.ko` is required for all trackers it is the base
architecture. Each tracker is compiled as its own module:
`latency_tracker_$TRACKER.ko`. When a tracker is loaded in memory, it can be
configured through `debugfs`. For now, only instance of each tracker is created
when loading a tracker module. In the future, it will be possible to create
multiple instances with different parameters. The default tracker instance is
always called "default".

```
insmod latency_tracker.ko
insmod latency_tracker_$TRACKER.ko
ls /sys/kernel/debug/latency/$TRACKER/default
```

Implemented modules
-------------------

Here is a list and the description of the trackers ready to run (in the
[`trackers/`](trackers/) directory).


### Wakeup latency

Measure the delay between the time a task has been woken up and the time it
actually runs. When the delay is higher than the specified threshold (5 usec by
default), a tracepoint is emitted (`latency_tracker_wakeup`).
Example with ftrace (works also with LTTng, see below for the configuration):

```
# insmod latency_tracker.ko
# insmod latency_tracker_wakeup.ko
# echo 1 > /sys/kernel/debug/tracing/tracing_on
# echo 1 > /sys/kernel/debug/tracing/events/latency_tracker/latency_tracker_wakeup/enable 
# cat /sys/kernel/debug/tracing/trace_pipe
rsyslogd   [001] d...   171.919230: latency_tracker_wakeup: comm=in:imklog, pid=412, delay=1496644, flag=0
```

###  Offcpu latency

Measure how long a task has been scheduled out and why it was woken up. If a
task has been scheduled out for more than the threshold, take the stack of its
waker when it is woken up.
Example with ftrace (works also with LTTng, see below for the configuration):

```
# insmod latency_tracker.ko
# insmod latency_tracker_offcpu.ko
# echo 1 > /sys/kernel/debug/tracing/tracing_on
# echo 1 > /sys/kernel/debug/tracing/events/latency_tracker/latency_tracker_offcpu_sched_switch/enable
# echo 1 > /sys/kernel/debug/tracing/events/latency_tracker/latency_tracker_offcpu_sched_wakeup/enable
# cat /sys/kernel/debug/tracing/trace_pipe
          <idle>-0     [002] dNh.   446.936781: latency_tracker_offcpu_sched_wakeup: waker_comm=swapper/2 (0), wakee_comm=rcuos/1 (18), wakee_offcpu_delay=9999903039, flag=0, waker_stack=ttwu_do_wakeup+0xe2/0x100
ttwu_do_activate.constprop.112+0x66/0x70
sched_ttwu_pending+0x4f/0x70
scheduler_ipi+0x5b/0x170
smp_reschedule_interrupt+0x2a/0x30
reschedule_interrupt+0x6d/0x80
default_idle+0x23/0xe0
arch_cpu_idle+0xf/0x20
cpuidle_idle_call+0xce
          <idle>-0     [002] d...   446.936841: latency_tracker_offcpu_sched_switch: comm=rcuos/1, pid=18, delay=9999959521, flag=0, stack=schedule+0x29/0x70
nocb_follower_wait+0xa2/0xf0
rcu_nocb_kthread+0x3d/0x190
kthread+0xc9/0xe0
ret_from_fork+0x7c/0xb0
```

### System calls latency

Measure how long a system call is running, if it is running for more than the
threshold, record its stack every time it has some CPU time. That way, we can
follow where it is blocked in the kernel.

Example with ftrace (works also with LTTng, see below for the configuration):

```
# insmod latency_tracker.ko
# insmod latency_tracker_syscalls.ko
# echo 1 > /sys/module/latency_tracker_syscalls/parameters/watch_all
# echo 1 > /sys/kernel/debug/tracing/tracing_on
# echo 1 > /sys/kernel/debug/tracing/events/latency_tracker/latency_tracker_syscall/enable
# echo 1 > /sys/kernel/debug/tracing/events/latency_tracker/latency_tracker_syscall_stack/enable
# cat /sys/kernel/debug/tracing/trace_pipe # example with a "sync" process that is blocked in the kernel
     kworker/3:2-28326 [003] d... 81136.470321: latency_tracker_syscall_stack: comm=sync, pid=32224, start_ts=81106437283881, delay=8559610219 flag=0, stack=_cond_resched+0x29/0x40
write_cache_pages+0x283/0x480
generic_writepages+0x40/0x60
do_writepages+0x1e/0x40
__filemap_fdatawrite_range+0x59/0x60
filemap_fdatawrite+0x1f/0x30
fdatawrite_one_bdev+0x16/0x20
iterate_bdevs+0xd9/0x120
sys_sync+0x63/0x90
tracesys

     ksoftirqd/0-3     [000] d... 81136.471039: latency_tracker_syscall_stack: comm=sync, pid=32224, start_ts=81106437283881, delay=8560313476 flag=0, stack=io_schedule+0x9d/0x140
sleep_on_page+0xe/0x20
__wait_on_bit+0x62/0x90
wait_on_page_bit+0x7f/0x90
filemap_fdatawait_range+0xf9/0x190
filemap_fdatawait+0x27/0x30
fdatawait_one_bdev+0x16/0x20
iterate_bdevs+0xd9/0x120
sys_sync+0x71/0x90
tracesys+0xe1/0xe6

          <idle>-0     [001] d... 81136.471234: latency_tracker_syscall_stack: comm=rngd, pid=1937, start_ts=81113031566114, delay=1966228144 flag=0, stack=schedule+0x29/0x70
schedule_hrtimeout_range_clock+0x14d/0x170
schedule_hrtimeout_range+0x13/0x20
poll_schedule_timeout+0x49/0x70
do_sys_poll+0x428/0x540
SyS_poll+0x65/0x100
tracesys+0xe1/0xe6

[...]
            sync-32224 [000] d... 81136.471297: latency_tracker_syscall: comm=sync, pid=32224, start_ts=81106437283881, delay=8560621068
```


### I/O request latency histogram

Classify the I/O requests at various level (syscall, FS, I/O scheduler and
block device) into buckets of latency to give a quick overview of the current
I/O activity and latency. Every time the data is output, the counters are
reset, so it is possible to accurately measure what happened between 2 commands
in terms of I/O, or just let it run and output periodically to get a profile of
the activity of a machine.

[Video demo](http://ju.klipix.org/demo-latency_tracker.ogv)

```
# insmod latency_tracker.ko
# insmod latency_tracker_block_hist.ko
# watch -n 1 cat /proc/block_hist_tracker
# cat /proc/block_hist_tracker
Latency range   |                    syscall        |      fs   |   iosched |    block
                |read  write r+w   sync  open  close|read  write|read  write|read  write
#########################################################################################
[1ns, 2ns[      |0     0     0     0     0     0    |0     0    |0     0    |0     0
[2ns, 4ns[      |0     0     0     0     0     0    |0     0    |0     0    |0     0
[4ns, 8ns[      |0     0     0     0     0     0    |0     0    |0     0    |0     0
[8ns, 16ns[     |0     0     0     0     0     0    |0     0    |0     0    |0     0
[16ns, 32ns[    |0     0     0     0     0     0    |0     0    |0     0    |0     0
[32ns, 64ns[    |0     0     0     0     0     0    |0     0    |0     0    |0     0
[64ns, 128ns[   |0     0     0     0     0     0    |0     0    |0     0    |0     0
[128ns, 256ns[  |0     0     0     0     0     0    |0     0    |0     0    |0     0
[256ns, 512ns[  |0     0     0     0     0     8    |0     0    |0     0    |0     0
[512ns, 1us[    |9     0     0     0     2     162  |45    0    |0     0    |0     0
[1us, 2us[      |21    0     0     0     22    36   |59    0    |0     1    |0     0
[2us, 4us[      |78    1     0     0     75    11   |26    0    |0     0    |0     0
[4us, 8us[      |76    0     0     0     78    0    |37    0    |0     2    |0     0
[8us, 16us[     |22    11    0     0     18    0    |4     2    |0     0    |0     0
[16us, 32us[    |3     4     0     0     3     0    |1     1    |0     0    |0     0
[32us, 64us[    |1     14    0     0     0     0    |1     0    |0     0    |0     0
[64us, 128us[   |5     10    0     0     0     0    |2     0    |0     0    |0     0
[128us, 256us[  |0     1     0     0     0     0    |0     0    |0     0    |0     0
[256us, 512us[  |1     0     0     0     3     0    |1     0    |0     0    |0     1
[512us, 1ms[    |1     0     0     0     4     0    |1     0    |0     0    |0     2
[1ms, 2ms[      |0     0     0     0     0     0    |0     0    |0     0    |0     0
[2ms, 4ms[      |1     0     0     0     0     0    |1     0    |0     0    |0     0
[4ms, 8ms[      |3     0     0     0     0     0    |3     0    |0     0    |0     0
[8ms, 16ms[     |0     0     0     0     0     0    |0     0    |0     0    |0     0
[16ms, 32ms[    |1     0     0     0     0     0    |1     0    |0     0    |0     0
[32ms, 64ms[    |0     0     0     0     0     0    |0     0    |0     0    |0     0
[64ms, 128ms[   |1     0     0     0     0     0    |0     0    |0     0    |0     0
[128ms, 256ms[  |4     0     0     0     0     0    |0     0    |0     0    |0     0
[256ms, 512ms[  |4     0     0     0     0     0    |0     0    |0     0    |0     0
[512ms, 1s[     |1     0     0     0     0     0    |0     0    |0     0    |0     0
[1s, 2s[        |0     0     0     0     0     0    |0     0    |0     0    |0     0
[2s, 4s[        |0     0     0     0     0     0    |0     0    |0     0    |0     0
[4s, 8s[        |0     0     0     0     0     0    |0     0    |0     0    |0     0
[8s, 16s[       |0     0     0     0     0     0    |0     0    |0     0    |0     0
[16s, 32s[      |0     0     0     0     0     0    |0     0    |0     0    |0     0
[32s, 64s[      |0     0     0     0     0     0    |0     0    |0     0    |0     0
[64s, 128s[     |0     0     0     0     0     0    |0     0    |0     0    |0     0
[128s, 256s[    |0     0     0     0     0     0    |0     0    |0     0    |0     0
[256s, 512s[    |0     0     0     0     0     0    |0     0    |0     0    |0     0
[512s, 1024s[   |0     0     0     0     0     0    |0     0    |0     0    |0     0
[1024s, 2048s[  |0     0     0     0     0     0    |0     0    |0     0    |0     0

```

Coding trackers
---------------

### Block I/O requests

To get a callback for all I/O requests that take more than 5 usec to complete:
  - Create a latency_tracker
  - in `block_rq_issue`, call `latency_tracker_event_in()` with the device and the sector as the key, and `thresh = 5000000`
  - in `block_rq_complete`, call `latency_tracker_event_out` with the same key
  - if the delay between the event_in and out for the same device + sector is longer than 2 usec, your callback is called.

This example is implemented in [`trackers/block_latency_tp.c`](trackers/block_latency_tp.c).
You can also change dynamically the threshold and timeout parameters by writing the
value in `/sys/module/latency_tracker_block/parameters/usec_treshold` and `/sys/module/latency_tracker_block/parameters/usec_timeout`

### Scheduler latency
To get a callback if a task takes more than 5 usec to be scheduled in after a wakeup and get a notification if after 6 usec
it is still not scheduled in:
  - Create a latency_tracker
  - in `sched_wakeup`, call `latency_tracker_event_in()` with the pid as key, `thresh = 5000000` and `timeout = 6000000`
  - in `sched_switch`, call `latency_tracker_event_out` with the same key
  - if the delay between the event_in and out for the same pid is longer than 5 usec, your callback is called, if after 6 usec the process is still not scheduled in, the callback is called with `timeout = 1`.

You can also change dynamically the threshold and timeout parameters by writing the
value in `/sys/module/latency_tracker_wakeup/parameters/usec_treshold` and `/sys/module/latency_tracker_wakeup/parameters/usec_timeout`

This example is implemented in [`trackers/wakeup_latency.c`](trackers/wakeup_latency.c).

Loading the modules
-------------------
For example to load two trackers provided:

```
insmod latency_tracker.ko
insmod latency_tracker_wakeup.ko
insmod latency_tracker_block.ko
```

Reading the output with Ftrace
------------------------------

```
cd /sys/kernel/debug/tracing/
echo 1 > events/latency_tracker/wakeup_latency/enable
echo 1 > events/latency_tracker/block_latency/enable
echo 1 > tracing_on
cat trace_pipe
```

Example output:

```
<idle>-0  [001] d.h. 16147.403374: block_latency: dev=(253,16), sector=8165312, delay=8601382
<idle>-0  [001] d.h. 16147.403396: block_latency: dev=(253,16), sector=8166320, delay=8621856
cc1-16824 [001] d... 16024.831282: sched_latency: pid=16823, delay=7540760, timeout=0
vim-16382 [000] d... 16031.684266: sched_latency: pid=32, delay=6230259, timeout=0

```

Reading the output with LTTng
-----------------------------

To use the tracepoints provided by this module with LTTng, you first have to
connect LTTng probes to them. A patch ready to be applied to the last
lttng-modules is provided in [`extras/`](extras/). When installed, compiled, load the
new probe module with `modprobe lttng-probe-latency_tracker`. Then you can configure
your LTTng session as you would usually do:

```
lttng create
lttng enable-event -k wakeup_latency,block_latency
lttng enable-event -k ..... # connect the other tracepoints you want
lttng start
# do stuff
lttng stop
lttng view
lttng destroy
```

Example output:

``` [16:04:02.378122496] (+0.000030737) trusty wakeup_latency: { cpu_id = 1 },
{ pid = 7, delay = 21239915, timeout = 0 } [16:04:13.029794374] (+10.651671878)
trusty block_latency: { cpu_id = 1 }, { major = 253, minor = 16, sector =
7668496, delay = 6486352 } [16:04:13.029836068] (+0.000041694) trusty
block_latency: { cpu_id = 1 }, { major = 253, minor = 16, sector = 7669504,
delay = 6531005 } ```

Integration with LTTng snapshots
--------------------------------

One of the main reason to be for this system if the integration with LTTng
snapshots. The flight-recorder mode of LTTng allows to write a trace in memory
in a ring-buffer and only extract it when necessary (lttng snapshot record).
The main difficulty is to trigger the collection of snapshots at the right
time. Integrating the latency tracker with this features allows to extract the
history before the latency was detected and might help understand why it
happened. The size of the history depends on the LTTng sesssion configuration
(subbuff size, number and enabled events) and the rate of events generated.  It
can range from a few milliseconds to minutes.

To try it, the script [`trackers/watch-block-event.sh`](trackers/watch-block-event.sh)
give a good starting point.

Using it in the kernel
----------------------

Create a latency tracker with:

    struct latency_tracker *latency_tracker_create(
        int (*match_fct) (const void *key1, const void *key2, size_t length),
        u32 (*hash_fct) (const void *key, u32 length, u32 initval),
	int max_events, uint64_t gc_period, uint64_t gc_thresh);

You can pass NULL, to use default hash (`jhash`) and match (`memcmp`)
functions.

The parameter `max_events` is the maximum number events that can be present at
any time (event_in without event_out).
Since no memory allocation is done during the event_in, if the number of
pre-allocated events is >= to max_events, the new event creations are dropped
and a message is logged in dmesg until some events are cleared (by event_out).

On the enter callsite, call:

    latency_tracker_event_in(struct latency_tracker *tracker,
        void *key, size_t key_len, uint64_t thresh,
        void (*cb)(unsigned long ptr),
        uint64_t timeout, unsigned int unique, void *priv);

On the exit callsite, call:

    latency_tracker_event_out(struct latency_tracker *tracker,
        void *key, unsigned int key_len, unsigned int id);

If the delay (ns) between the event_in and event_out is higher than
thresh, execute cb with a pointer to the struct latency_tracker_event
of this event. The pointer priv of this structure is initialized from
priv passed here.

If timeout (nsec) is > 0, start a timer to fire at now + timeout. If the
timeout fires before the event_out, the cb_flag argument of the struct passed
to the callback is set to LATENCY_TRACKER_CB_TIMEOUT and the timer is stopped.
The event is not removed from the HT, so if the event_out arrives eventually,
the callback is executed again but with cb_flag set to
LATENCY_TRACKER_CB_NORMAL.

The id is passed to the callback as the cb_out_id member of the struct. It
can be used to track the event_out origin if multiple possible.

The memory management of priv is left entirely to the caller.

When done, destroy the tracker with:

    latency_tracker_destroy(struct latency_tracker *tracker);


Acknowledgment
--------------

Most of the code for handling the tracepoints, the allocation of memory, the
usage of kallsyms, the locking is largely inspired by LTTng and the work of
Mathieu Desnoyers.


Final words
-----------

We hope you enjoy this module, please remember it is a work in progress so all
the feedback is really appreciated and try not to break your system !
