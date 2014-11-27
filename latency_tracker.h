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

#define LATENCY_TRACKER_MAX_KEY_SIZE 128

enum latency_tracker_cb_flag {
	LATENCY_TRACKER_CB_NORMAL	= 0,
	LATENCY_TRACKER_CB_TIMEOUT	= 1,
	LATENCY_TRACKER_CB_UNIQUE	= 2,
	LATENCY_TRACKER_CB_GC		= 3,
};

struct latency_tracker_event {
	struct timer_list timer;
	struct hlist_node hlist;
	u64 start_ts;
	u64 end_ts;
	uint64_t timeout;
	uint64_t thresh;
	u32 hkey;
	char key[LATENCY_TRACKER_MAX_KEY_SIZE];
	size_t key_len;
	struct list_head list;
	enum latency_tracker_cb_flag cb_flag;
	void (*cb)(unsigned long ptr);
	void *priv;
};

struct latency_tracker;

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
 */
struct latency_tracker *latency_tracker_create(
		int (*match_fct) (const void *key1, const void *key2,
			size_t length),
		u32 (*hash_fct) (const void *key, u32 length, u32 initval),
		int max_events);

/*
 * Destroy and free a tracker and all the current events in the HT.
 */
void latency_tracker_destroy(struct latency_tracker *tracker);

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
 */
enum latency_tracker_event_in_ret latency_tracker_event_in(
		struct latency_tracker *tracker,
		void *key, size_t key_len, uint64_t thresh,
		void (*cb)(unsigned long ptr),
		uint64_t timeout, unsigned int unique, void *priv);

/*
 * Stop the tracking of an event.
 * Cancels the timer if it was set.
 */
int latency_tracker_event_out(struct latency_tracker *tracker,
		void *key, unsigned int key_len);

#endif /*  LATENCY_TRACKER_H */
