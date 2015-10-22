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
#include <linux/kref.h>
#include "rculfhash-internal.h"
#include "urcu/wfcqueue.h"

#define DEFAULT_STARTUP_ALLOC_EVENTS 100
#define DEFAULT_THRESHOLD 1000000000

struct latency_tracker_event_ctx;

struct latency_tracker_key {
	size_t key_len;
	char *key;
};

/*
 * Return code when adding an event to a tracker.
 */
enum latency_tracker_event_in_ret {
	LATENCY_TRACKER_OK		= 0,
	LATENCY_TRACKER_FULL		= 1,
	LATENCY_TRACKER_ERR		= 2,
	LATENCY_TRACKER_ERR_TIMEOUT	= 3,
	LATENCY_TRACKER_DISABLED	= 4,
};

enum latency_tracker_cb_flag {
	LATENCY_TRACKER_CB_NORMAL	= 0,
	LATENCY_TRACKER_CB_TIMEOUT	= 1,
	LATENCY_TRACKER_CB_UNIQUE	= 2,
	LATENCY_TRACKER_CB_GC		= 3,
};

/*
 * Create a latency tracker.
 *
 * The default parameters are enough to start (FIXME: document the
 * defaultshere), but we can override with the latency_tracker_set_* functions.
 * When all the settings are done, call latency_tracker_enable to start the
 * tracking.
 */
struct latency_tracker *latency_tracker_create(void);

/*
 * Destroy and free a tracker and all the current events in the HT.
 *
 * All events causing a call to event_in and event_out MUST be disabled before
 * calling this function.
 */
void latency_tracker_destroy(struct latency_tracker *tracker);

/*
 * Start the tracker.
 * Returns 0 on success, a negative value and a printk on error.
 */
int latency_tracker_enable(struct latency_tracker *tracker);

/*
 * Setters to various tracker parameters.
 * Most of these should be performed before the call to latency_tracker_enable.
 * FIXME: document which parameters can be changed at runtime.
 */
/* default: memcmp */
int latency_tracker_set_match_fct(struct latency_tracker *tracker,
		int (*match_fct) (const void *key1, const void *key2,
			size_t length));
/* default: jhash */
int latency_tracker_set_hash_fct(struct latency_tracker *tracker,
		u32 (*hash_fct) (const void *key, u32 length, u32 initval));

int latency_tracker_set_startup_events(struct latency_tracker *tracker, int
		startup_events);
/* default: 0 */
int latency_tracker_set_max_resize(struct latency_tracker *tracker, int
		max_resize);
/* default: NULL */
int latency_tracker_set_priv(struct latency_tracker *tracker, void *priv);
/* default: 0 */
int latency_tracker_set_timer_period(struct latency_tracker *tracker, uint64_t
		timer_period);
/*
 * nanoseconds default: 0 */
int latency_tracker_set_timeout(struct latency_tracker *tracker, uint64_t
		timeout);
/*
 * nanoseconds default: DEFAULT_THRESHOLD */
int latency_tracker_set_threshold(struct latency_tracker *tracker, uint64_t
		threshold);
/* default: NULL */
int latency_tracker_set_callback(struct latency_tracker *tracker, void
		(*cb)(struct latency_tracker_event_ctx *ctx));
/* default: sizeof(long) */
int latency_tracker_set_key_size(struct latency_tracker *tracker, int size);
/* default: 0 */
int latency_tracker_set_priv_data_size(struct latency_tracker *tracker,
		int size);

/*
 * Update the tracker garbage collector parameters (ns).
 * If 0, the GC is stopped.
 */
int latency_tracker_set_gc_thresh(struct latency_tracker *tracker,
		uint64_t gc_thres);

void *latency_tracker_get_priv(struct latency_tracker *tracker);

/*
 * Structure passed as argument to the callback.
 * Exposed publicly, but should be accessed with the getters to make the
 * code eventually portable to user-space.
 */
struct latency_tracker_event_ctx {
	uint64_t start_ts;
	uint64_t end_ts;
	enum latency_tracker_cb_flag cb_flag;
	unsigned int cb_out_id;
	struct latency_tracker_key *tkey;
	void *priv_data;
	void *priv;
};

static inline
uint64_t latency_tracker_event_ctx_get_start_ts(
		struct latency_tracker_event_ctx *ctx)
{
	return ctx->start_ts;
}

static inline
uint64_t latency_tracker_event_ctx_get_end_ts(
		struct latency_tracker_event_ctx *ctx)
{
	return ctx->end_ts;
}
static inline
enum latency_tracker_cb_flag latency_tracker_event_ctx_get_cb_flag(
		struct latency_tracker_event_ctx *ctx)
{
	return ctx->cb_flag;
}
static inline
unsigned int latency_tracker_event_ctx_get_cb_out_id(
		struct latency_tracker_event_ctx *ctx)
{
	return ctx->cb_out_id;
}
static inline
struct latency_tracker_key *latency_tracker_event_ctx_get_key(
		struct latency_tracker_event_ctx *ctx)
{
	return ctx->tkey;
}

static inline
void *latency_tracker_event_ctx_get_priv(
		struct latency_tracker_event_ctx *ctx)
{
	return ctx->priv;
}

static inline
void *latency_tracker_event_ctx_get_priv_data(
		struct latency_tracker_event_ctx *ctx)
{
	return ctx->priv_data;
}

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
		void *key, size_t key_len,
		unsigned int unique, void *priv);

enum latency_tracker_event_in_ret _latency_tracker_event_in(
		struct latency_tracker *tracker,
		void *key, size_t key_len, unsigned int unique,
		u64 ts_override, void *priv);

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

/*
 * Lookup if the key is in the tracker HT and return the associated event if
 * available, returns NULL if not found. An event is "findable" as long as the
 * event_out on the key has not been performed. The structure returned is
 * guaranteed to be valid even after the event_out and until the put_event is
 * not done.
 */
struct latency_tracker_event *latency_tracker_get_event(
		struct latency_tracker *tracker, void *key,
		unsigned int key_len);

/*
 * Release the reference on an event (to allow freeing the memory associated
 * with it).
 */
void latency_tracker_put_event(struct latency_tracker_event *event);

uint64_t latency_tracker_event_get_start_ts(struct latency_tracker_event *event);
/*
 * Memory is guaranteed to be allocated even after the event_out if we hold the
 * refcount on the event (get_event), but there is no exclusive access to these
 * pointers, so use with caution if multiple callsites can access the same data
 * at the same time.
 */
void *latency_tracker_event_get_priv(struct latency_tracker_event *event);
void *latency_tracker_event_get_priv_data(struct latency_tracker_event *event);

/*
 * Returns the number of skipped events due to an empty free list.
 */
uint64_t latency_tracker_skipped_count(struct latency_tracker *tracker);

#endif /*  LATENCY_TRACKER_H */
