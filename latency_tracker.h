#if !defined(LATENCY_TRACKER_H)
#define LATENCY_TRACKER_H

/*
 * latency_tracker.h
 *
 * Latency tracker
 *
 * Copyright (C) 2014 Julien Desfossez <jdesfossez@efficios.com>
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

#include <linux/version.h>
#define LATENCY_TRACKER_MAX_KEY_SIZE 128

struct latency_tracker;

enum latency_tracker_cb_flag {
	LATENCY_TRACKER_CB_NORMAL	= 0,
	LATENCY_TRACKER_CB_TIMEOUT	= 1,
	LATENCY_TRACKER_CB_UNIQUE	= 2,
	LATENCY_TRACKER_CB_GC		= 3,
};

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0))
#include <linux/rhashtable.h>
#else
struct rhash_head {};
struct rhashtable {};
#endif
#include "rculfhash-internal.h"

struct latency_tracker_key {
	size_t key_len;
	char key[LATENCY_TRACKER_MAX_KEY_SIZE];
};

struct latency_tracker_event {
	struct timer_list timer;
	/* basic kernel HT */
	struct hlist_node hlist;
	/* rhashtable */
	struct rhash_head node;
	/* URCU HT */
	struct cds_lfht_node urcunode;
	struct rcu_head urcuhead;
	/* Timestamp of event creation. */
	u64 start_ts;
	/* Timestamp of event completion. */
	u64 end_ts;
	/* Timeout timestamp. */
	uint64_t timeout;
	/* Time threshold value to call the callback. */
	uint64_t thresh;
	/* Hash of the key. */
	u32 hkey;
	/* Copy of the key. */
	struct latency_tracker_key tkey;
	struct list_head list;
	/* back pointer to the tracker. */
	struct latency_tracker *tracker;
	/*
	 * Flag set before calling the callback to identify various
	 * the condition of call (normal, timeout, garbage collect, etc).
	 */
	enum latency_tracker_cb_flag cb_flag;
	/*
	 * Optional event_out ID, useful if multiple exit paths are
	 * possible (error, normal, etc).
	 */
	unsigned int cb_out_id;
	/*
	 * Function pointer to the callback, the pointer passed is this
	 * struct latency_tracker_event.
	 */
	void (*cb)(unsigned long ptr);
	/*
	 * Pointer set a event creation by the caller and kept as is up
	 * to the event destruction. The memory management is left entirely
	 * to the caller.
	 */
	void *priv;
};

/*
 * Return code when adding an event to a tracker.
 */
enum latency_tracker_event_in_ret {
	LATENCY_TRACKER_OK	= 0,
	LATENCY_TRACKER_FULL	= 1,
	LATENCY_TRACKER_ERR	= 2,
};

/*
 * Create a latency tracker.
 * match_fct: function to compare 2 keys, returns 0 if equal
 *            if NULL: use memcmp
 * hash_fct: function to hash a key, if NULL: use jhash
 * max_events: expected number of concurrent live events (default: 100)
 * gc: every gc_period ns, check if there are events older than gc_thresh ns,
 *     close them and pass LATENCY_TRACKER_CB_GC as cb_flag (disabled by
 *     default with 0 and 0).
 */
struct latency_tracker *latency_tracker_create(
		int (*match_fct) (const void *key1, const void *key2,
			size_t length),
		u32 (*hash_fct) (const void *key, u32 length, u32 initval),
		int max_events, uint64_t gc_period, uint64_t gc_thresh,
		void *priv);

/*
 * Destroy and free a tracker and all the current events in the HT.
 *
 * All events causing a call to event_in and event_out MUST be disabled before
 * calling this function.
 */
void latency_tracker_destroy(struct latency_tracker *tracker);

/*
 * Update the tracker garbage collector parameters (ns).
 * If any of the 2 values equals 0, the GC is stopped.
 */
void latency_tracker_set_gc_thresh(struct latency_tracker *tracker,
		uint64_t gc_thres);
void latency_tracker_set_gc_period(struct latency_tracker *tracker,
		uint64_t gc_thres);

/*
 * Start the tracking of an event.
 * If the delay (ns) between the event_in and event_out is higher than
 * thresh, execute cb with a pointer to the struct latency_tracker_event
 * of this event. The pointer priv of this structure is initialized from
 * priv passed here.
 * If timeout (usec) is > 0, start a timer to fire at now + timeout.
 * The cb_flag of the structure passed to the callback informs the callback
 * if it got called because of the timeout or other condition.
 * If the timeout occurs before the event_out, the event is not removed
 * from the HT, so if the event_out arrives eventually, the callback is
 * executed again but with the normal cb_flag.
 * The memory management of priv is left entirely to the caller.
 *
 * If this function is called from a tracepoint or a kprobe, you should call
 * _latency_tracker_event_in instead to avoid nesting two
 * rcu_read_lock_sched_notrace.
 */
enum latency_tracker_event_in_ret latency_tracker_event_in(
		struct latency_tracker *tracker,
		void *key, size_t key_len, uint64_t thresh,
		void (*cb)(unsigned long ptr),
		uint64_t timeout, unsigned int unique, void *priv);

enum latency_tracker_event_in_ret _latency_tracker_event_in(
		struct latency_tracker *tracker,
		void *key, size_t key_len, uint64_t thresh,
		void (*cb)(unsigned long ptr),
		uint64_t timeout, unsigned int unique, void *priv);

/*
 * Stop the tracking of an event.
 * Cancels the timer if it was set.
 * The optional id is passed to the callback in cb_out_id, it can be used
 * to identify the origin of the event_out (eg: error or normal).
 *
 * If this function is called from a tracepoint or a kprobe, you should call
 * _latency_tracker_event_out instead to avoid nesting two
 * rcu_read_lock_sched_notrace.
 */
int latency_tracker_event_out(struct latency_tracker *tracker,
		void *key, unsigned int key_len, unsigned int id);
int _latency_tracker_event_out(struct latency_tracker *tracker,
		void *key, unsigned int key_len, unsigned int id);


void *latency_tracker_get_priv(struct latency_tracker *tracker);

#endif /*  LATENCY_TRACKER_H */
