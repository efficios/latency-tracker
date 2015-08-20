latency_tracker
=============

_by [Julien Desfossez](mailto:jdesfossez@efficios.com)_

This kernel module is a simple latency tracker. It is designed to be called
from anywhere in the kernel (including tracepoints and kprobes) and is designed
to execute lightweight actions when an operation takes longer than a specified
threshold (and/or timeout).

The main intent is to use it to output alerts and latency metrics on production
servers (not just in debugging situations).

It is designed to be fast and can be called in various situations including IRQ
handlers (no memory allocation and irq-safe spin-locks). It is still a work in
progress, so any suggestions to improve the above statement will be taken into
account.

The user is responsible to create callback functions that won't crash their
kernel, so you have to be careful to use it. Some ready to use examples are
provided in [`examples/`](examples/). Calling tracepoints, registering stack
traces and doing all kinds of basic aggregations from the callbacks (with
output when you unload the module or in a deferred timer handler) seems to be
the most interesting usage for this module for now. Everything that does I/O
operations during a callback (even printk) can create feedback loops depending
on the context and eventually hang the kernel).

For more secure and user-friendly use cases, please consider using SystemTap
instead.

Installation
------------
  - Linux kernel headers (`linux-headers-generic` on ubuntu)
  - gcc and make

On Ubuntu:

```
apt-get update
apt-get install git gcc make linux-headers-generic
git clone https://github.com/jdesfossez/latency_tracker.git
cd latency_tracker
make
```

Implemented modules
-------------------

Here is a list and the description of the examples ready to run (in the
[`examples/`] directory.  For all these examples, the threshold and timeout
parameters can be controlled at run-time in
/sys/module/<module_name>/parameters/usec_{treshold|timeout}`.

All of these examples require first that the `latency_tracker.ko` module is loaded
(`insmod latency_tracker.ko`).

### Wakeup latency

Measure the delay between the time a task has been woken up and the time it
actually runs. When the delay is higher than the specified threshold (5 usec by
default), a tracepoint is emitted (`wakeup_latency`).
Example with ftrace (works also with LTTng, see below for the configuration):

```
# insmod latency_tracker.ko
# insmod latency_tracker_wakeup.ko
# echo 1 > /sys/kernel/debug/tracing/tracing_on
# echo 1 > /sys/kernel/debug/tracing/events/latency_tracker/wakeup_latency/enable 
# cat /sys/kernel/debug/tracing/trace_pipe
rsyslogd   [001] d...   171.919230: wakeup_latency: comm=in:imklog, pid=412, delay=1496644, flag=0
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
# echo 1 > /sys/kernel/debug/tracing/events/latency_tracker/offcpu_sched_switch/enable
# echo 1 > /sys/kernel/debug/tracing/events/latency_tracker/offcpu_sched_wakeup/enable
# cat /sys/kernel/debug/tracing/trace_pipe
          <idle>-0     [002] dNh.   446.936781: offcpu_sched_wakeup: waker_comm=swapper/2 (0), wakee_comm=rcuos/1 (18), wakee_offcpu_delay=9999903039, flag=0, waker_stack=ttwu_do_wakeup+0xe2/0x100
ttwu_do_activate.constprop.112+0x66/0x70
sched_ttwu_pending+0x4f/0x70
scheduler_ipi+0x5b/0x170
smp_reschedule_interrupt+0x2a/0x30
reschedule_interrupt+0x6d/0x80
default_idle+0x23/0xe0
arch_cpu_idle+0xf/0x20
cpuidle_idle_call+0xce
          <idle>-0     [002] d...   446.936841: offcpu_sched_switch: comm=rcuos/1, pid=18, delay=9999959521, flag=0, stack=schedule+0x29/0x70
nocb_follower_wait+0xa2/0xf0
rcu_nocb_kthread+0x3d/0x190
kthread+0xc9/0xe0
ret_from_fork+0x7c/0xb0
```



Coding examples
---------------

### Block I/O requests

To get a callback for all I/O requests that take more than 5 usec to complete:
  - Create a latency_tracker
  - in `block_rq_issue`, call `latency_tracker_event_in()` with the device and the sector as the key, and `thresh = 5000000`
  - in `block_rq_complete`, call `latency_tracker_event_out` with the same key
  - if the delay between the event_in and out for the same device + sector is longer than 2 usec, your callback is called.

This example is implemented in [`examples/block_latency_tp.c`](examples/block_latency_tp.c).
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

This example is implemented in [`examples/wakeup_latency.c`](examples/wakeup_latency.c).

Loading the modules
-------------------
For example to load two examples provided:

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

```
[16:04:02.378122496] (+0.000030737) trusty wakeup_latency: { cpu_id = 1 }, { pid = 7, delay = 21239915, timeout = 0 }
[16:04:13.029794374] (+10.651671878) trusty block_latency: { cpu_id = 1 }, { major = 253, minor = 16, sector = 7668496, delay = 6486352 }
[16:04:13.029836068] (+0.000041694) trusty block_latency: { cpu_id = 1 }, { major = 253, minor = 16, sector = 7669504, delay = 6531005 }
```

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

To try it, the script [`examples/watch-block-event.sh`](examples/watch-block-event.sh)
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

I hope you enjoy this module, please remember it is a work in progress so all
the feedback is really appreciated and try not to break your system !
