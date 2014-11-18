latency_tracker
=============

_by [Julien Desfossez](mailto:jdesfossez@efficios.com)_

This kernel module is a simple latency tracker. It is designed to be called
from anywhere in the kernel (including tracepoints and kprobes).

Using
-----

Create a latency tracker with:

    struct latency_tracker *latency_tracker_create(
        int (*match_fct) (const void *key1, const void *key2, size_t length),
        u32 (*hash_fct) (const void *key, u32 length, u32 initval));
You can pass NULL, to use default hash (`jhash`) and match (`memcmp`) functions.

On the enter callsite, call:

    latency_tracker_event_in(struct latency_tracker *tracker,
        void *key, size_t key_len, uint64_t thresh,
        void (*cb)(unsigned long ptr, unsigned int timeout),
        uint64_t timeout, void *priv);

On the exit callsite, call:

    latency_tracker_event_out(struct latency_tracker *tracker,
        void *key, unsigned int key_len);

If the delay (ns) between the event_in and event_out is higher than
thresh, execute cb with a pointer to the struct latency_tracker_event
of this event. The pointer priv of this structure is initialized from
priv passed here.
If timeout (nsec) is > 0, start a timer to fire at now + timeout.
If the timeout fires before the event_out, the timeout argument of the
callback is set to 1 and the timer is stopped. The event is not removed
from the HT, so if the event_out arrives eventually, the callback is
executed again but with timeout set to 0.
The memory management of priv is left entirely to the caller.

When done, destroy the tracker with:

    latency_tracker_destroy(struct latency_tracker *tracker);


Example usage
-------------

### Block I/O requests

To get a callback for all I/O requests that take more than 5 usec to complete:
  - Create a latency_tracker
  - in `block_rq_issue`, call `latency_tracker_event_in()` with the device and the sector as the key, and `thresh = 5000000`
  - in `block_rq_complete`, call `latency_tracker_event_out` with the same key
  - if the delay between the event_in and out for the same device + sector is longer than 2 usec, your callback is called.

This example is implemented in [`examples/block_latency_tp.c`](examples/block_latency_tp.c).

### Scheduler latency
To get a callback if a task takes more than 5 usec to be scheduled in after a wakeup and get a notification if after 6 usec
it is still not scheduled in:
  - Create a latency_tracker
  - in `sched_wakeup`, call `latency_tracker_event_in()` with the pid as key, `thresh = 5000000` and `timeout = 6000000`
  - in `sched_switch`, call `latency_tracker_event_out` with the same key
  - if the delay between the event_in and out for the same pid is longer than 5 usec, your callback is called, if after 6 usec the process is still not scheduled in, the callback is called with `timeout = 1`.

From the callback, you can call functions like printk, tracepoint, take callstacks, gather statistics for later print out, etc.

This example is implemented in [`examples/sched_latency_tp.c`](examples/sched_latency_tp.c).
