/*
 * tracker_private.h
 *
 * Latency tracker private header
 *
 * Copyright (C) 2016 Julien Desfossez <jdesfossez@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _TRACKER_PRIVATE_H
#define _TRACKER_PRIVATE_H

//#define DEFAULT_LATENCY_HASH_BITS 3
//#define DEFAULT_LATENCY_TABLE_SIZE (1 << DEFAULT_LATENCY_HASH_BITS)
#define DEFAULT_LATENCY_TABLE_SIZE 2048

#include <linux/workqueue.h>
#include <linux/irq_work.h>
#include <asm/local.h>

//#include "wrapper/ht.h"
//#include "rculfhash-internal.h"
//#include "urcu/wfcqueue.h"

#define TRACKER_NAME_SIZE 32

struct numa_pool {
	struct llist_head llist;
};

struct per_cpu_ll {
	local_t current_count;
	struct numa_pool *pool;
	struct llist_head llist;
};

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
	/*
	 * Size allocated for event->priv_data.
	 */
	int priv_data_size;
	/* How many events were inserted in the HT. */
	uint64_t tracked_count;
	/* How many event could not be tracked due to an empty free list. */
	uint64_t skipped_count;
	int per_cpu_alloc;
	int nr_cpus;
	int numa_node_max;
	struct per_cpu_ll __percpu *per_cpu_ll;
	struct numa_pool *per_node_pool;
	/*
	 * Is the tracker active ?
	 * When creating a tracker, this is set to 0 and needs to be set to 1
	 * by the user (from the API or debugfs) to start the tracking. The
	 * trackers are responsible to check the state when processing events.
	 * When switching to a different value, the change_tracking_on_cb is
	 * called if it is set.
	 */
	int tracking_on;
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
	/*
	 * name of the tracker (for debugfs)
	 */
	char tracker_name[TRACKER_NAME_SIZE + 1];
	/*
	 * Name of this instance of the tracker (to allow multiple trackers
	 * to run simulataneously.
	 */
	char instance_name[TRACKER_NAME_SIZE + 1];
	/*
	 * debugfs control dir
	 */
	struct dentry *debugfs_instance_dir;
	struct dentry *debugfs_tracker_dir;
	/*
	 * debugfs wakeup_pipe stuff
	 */
	struct dentry *wakeup_pipe;
	struct irq_work wake_irq;
	bool got_alert;
	wait_queue_head_t read_wait;
	unsigned int wakeup_rate_limit_ns;
	u64 last_wakeup_ts;
	atomic_t wakeup_readers;

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
	 * If not NULL, called on event_out and for each event still in
	 * the HT on latency_tracker_destroy.
	 */
	void (*destroy_event_cb) (struct latency_tracker_event *event);
	/*
	 * Clear all the internal state of the tracker.
	 */
	int (*change_tracking_on_cb) (struct latency_tracker *tracker,
			int old_value, int new_value);
        /*
         * Protects the access to the HT, the free_list and the timer.
         */
        spinlock_t lock;
	/*
	 * When allocated, the tracking can start and some parameters cannot
	 * be changed anymore.
	 * FIXME: list them here.
	 */
	int allocated;
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
	 * Private pointer set by the caller, available in the callback.
	 * Memory management left entirely to the user.
	 */
	void *priv;
	/*
	 * Below are allocated pointers, the memset performed when we
	 * put back an event must stop here.
	 */
	/*
	 * Allocated data for the user, the size is determined when creating
	 * the tracker, the memory is freed when the tracker is destroyed.
	 * The data is memset to 0 when putting back the event.
	 */
	void *priv_data;

	/* memset(0) stops here where resetting the event*/

	/* Pool owning this event */
	struct numa_pool *pool;
	/*
	 * Copy of the key, memset to 0 independantly of the event.
	 */
	struct latency_tracker_key tkey;
};

void __latency_tracker_event_destroy(struct kref *kref);

#endif /* _TRACKER_PRIVATE_H */
