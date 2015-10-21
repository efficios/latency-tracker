#ifndef _TRACKER_PRIVATE_H
#define _TRACKER_PRIVATE_H

//#define DEFAULT_LATENCY_HASH_BITS 3
//#define DEFAULT_LATENCY_TABLE_SIZE (1 << DEFAULT_LATENCY_HASH_BITS)
#define DEFAULT_LATENCY_TABLE_SIZE 2048

#include <linux/workqueue.h>

#include "wrapper/ht.h"
#include "rculfhash-internal.h"
#include "urcu/wfcqueue.h"

struct latency_tracker {
	/*  basic kernel HT */
        struct hlist_head ht[DEFAULT_LATENCY_TABLE_SIZE];
	/* urcu ht */
	struct cds_lfht *urcu_ht;
	/*
	 * Match function for the hash table, use jhash if NULL.
	 * Returns 0 on match.
	 */
        int (*match_fct) (const void *key1, const void *key2, size_t length);
	/*
	 * Hash function for the hash table, use memcmp if NULL.
	 */
        u32 (*hash_fct) (const void *key, u32 length, u32 initval);
	/*
	 * Number of events currently allocated in the tracker (or to be
	 * allocated after the latency_tracker_enable).
	 */
	int free_list_nelems;
	/*
	 * Allow the maximum number of concurrent events to grow up
	 * to this value (resized in a workqueue, by doubling the size
	 * of the total list up-to max_resize). 0 to disable resizing.
	 */
	int max_resize;
	/* Flag to trigger the freelist resize work. */
	int need_to_resize;
	/*
	 * Max size of the keys we can expect.
	 */
	int key_size;
	/* How much event could not be tracked due to an empty free list. */
	uint64_t skipped_count;
#ifdef OLDFREELIST
	struct list_head events_free_list;
#else
	struct llist_head ll_events_free_list;
#endif
	/*
	 * Period of the timer (nsec) that performs various housekeeping tasks:
	 * - garbage collection checks (if enabled)
	 * - check if the freelist needs to be resized
	 * Set it to 0 to disable it.
	 * 100ms (100*1000*1000) is a good arbitrary value.
	 */
        uint64_t timer_period;
	/*
	 * Delay (nsec) after which an event is considered too old (so we
	 * stop waiting for the event_out and remove it from the HT.
	 * This performs an iteration on the HT of in use events, the overhead
	 * of this action depends on the timer_period and number of events
	 * simultaneously active.
	 */
        uint64_t gc_thresh;

	/*
	 * If an event_out happens after "threshold" ns after the event_in,
	 * the callback associated with the event is called with cb_flag set
	 * to LATENCY_TRACKER_CB_NORMAL.
	 */
	uint64_t threshold;
	/*
	 * After "timeout" ns, if the event_out has still not happened, call
	 * the callback with cb_flag set to LATENCY_TRACKER_CB_TIMEOUT. The
	 * event is not removed from the HT, so the callback will be called
	 * again if the event_out arrives. This feature is different from the
	 * garbage collector.
	 *
	 * Set to 0 to disable it.
	 */
	uint64_t timeout;
	/*
	 * Function pointer to the callback
	 */
	void (*cb)(struct latency_tracker_event_ctx *ctx);

	/* GC and resize work */
        struct timer_list timer;
	struct workqueue_struct *resize_q;
	struct work_struct resize_w;

	struct llist_head to_release;
	struct workqueue_struct *tracker_call_rcu_q;
	struct delayed_work tracker_call_rcu_w;

	/* For timeout on events (on timer_period) */
	struct cds_wfcq_head timeout_head;
	struct cds_wfcq_tail timeout_tail;

	/*
	 * When we start using the event at this address, start
	 * the resize mechanism (pointer comparison).
	 */
	struct latency_tracker_event *resize_event;
        /*
         * Protects the access to the HT, the free_list and the timer.
         */
        spinlock_t lock;
	/*
	 * When enabled, the tracking actually starts and some parameters
	 * cannot be changed anymore.
	 *
	 * FIXME: list them here.
	 */
	int enabled;
	/*
	 * A private pointer that is accessible everywhere the tracker object
	 * is accessible, the caller is responsible of the memory allocation of
	 * this pointer.
	 */
        void *priv;
};

/*
 * Structure representing an event, it is preallocated during the
 * latency_tracker_enable (or resize), initialized during the
 * latency_tracker_event_in and released after the latency_tracker_event_out.
 * We try to keep this struct as small as possible because there might be a
 * lot of these in circulation.
 */
struct latency_tracker_event {
#ifdef BASEHT
	/* basic kernel HT */
	struct hlist_node hlist;
#endif
#if defined(OLDFREELIST)
	/* Node in the spin_locked freelist. */
	struct list_head list;
#endif
	/* Node in the LL freelist. */
	struct llist_node llist;
	/* Node in the URCU HT */
	struct cds_lfht_node urcunode;
	/* back pointer to the tracker. */
	struct latency_tracker *tracker;
	union {
		/*
		 * wfcqueue node if using the timeout.
		 */
		struct cds_wfcq_node timeout_node;
		/* call_rcu */
		struct rcu_head urcuhead;
	} u;
	/*
	 * Reclaim the event when the refcount == 0.
	 * If we use the timeout, the refcount is set to 2 (one for the
	 * timeout list and the other for the normal exit (or GC)).
	 */
	struct kref refcount;
	/* Timestamp of event creation. */
	u64 start_ts;
	/*
	 * Private pointer set by the caller, passed when the callback is
	 * called. Memory management left entirely to the user.
	 */
	void *priv;
	/*
	 * Copy of the key.
	 * MUST BE THE LAST FIELD.
	 */
	struct latency_tracker_key tkey;
};

#if defined(OLDFREELIST)
static
void latency_tracker_event_destroy(struct kref *kref);
#endif
static
void __latency_tracker_event_destroy(struct kref *kref);

#endif /* _TRACKER_PRIVATE_H */
