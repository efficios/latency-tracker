latency_tracker
=============

_by [Julien Desfossez](mailto:jdesfossez@efficios.com)_

This kernel module is a simple latency tracker.

Using
-----

Create a latency tracker with:

    struct latency_tracker *latency_tracker_create(
        int (*match_fct) (const void *key1, const void *key2, size_t length),
        u32 (*hash_fct) (const void *key, u32 length, u32 initval));
You can pass NULL, to use default hash and match functions.

On the enter callsite, call:

    latency_tracker_event_in(struct latency_tracker *tracker,
        void *key, size_t key_len, unsigned int thresh,
        void (*cb)(unsigned long ptr, unsigned int timeout),
        unsigned int timeout, void *priv);

On the exit callsite, call:

    latency_tracker_event_out(struct latency_tracker *tracker,
        void *key, unsigned int key_len);

If the delay (ns) between the event_in and event_out is higher than
thresh, execute cb with a pointer to the struct latency_tracker_event
of this event. The pointer priv of this structure is initialized from
priv passed here.
If timeout (usec) is > 0, start a timer to fire at now + timeout.
If the timeout fires before the event_out, the timeout argument of the
callback is set to 1 and the timer is stopped. The event is not removed
from the HT, so if the event_out arrives eventually, the callback is
executed again but with timeout set to 0.
The memory management of priv is left entirely to the caller.

When done, destroy the tracker with:

    latency_tracker_destroy(struct latency_tracker *tracker);
