/*
 * latency_tracker.c
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

#include <linux/module.h>
#include <linux/ktime.h>
#include <linux/hrtimer.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/jhash.h>
#include <linux/module.h>
#include <linux/workqueue.h>
#include "latency_tracker.h"
#include "wrapper/jiffies.h"
#include "wrapper/tracepoint.h"
#include "wrapper/ht.h"
#include "wrapper/freelist.h"
#include "tracker_private.h"
#include "tracker_debugfs.h"

#ifdef BENCH
#include "measure.h"
#endif

#define CREATE_TRACE_POINTS
#include <trace/events/latency_tracker.h>

EXPORT_TRACEPOINT_SYMBOL_GPL(latency_tracker_wakeup);
EXPORT_TRACEPOINT_SYMBOL_GPL(latency_tracker_offcpu_sched_switch);
EXPORT_TRACEPOINT_SYMBOL_GPL(latency_tracker_offcpu_sched_wakeup);
EXPORT_TRACEPOINT_SYMBOL_GPL(latency_tracker_syscall);
EXPORT_TRACEPOINT_SYMBOL_GPL(latency_tracker_syscall_stack);
EXPORT_TRACEPOINT_SYMBOL_GPL(latency_tracker_net);
EXPORT_TRACEPOINT_SYMBOL_GPL(latency_tracker_block);
EXPORT_TRACEPOINT_SYMBOL_GPL(latency_tracker_critical_timing_stack);
EXPORT_TRACEPOINT_SYMBOL_GPL(latency_tracker_rt);
EXPORT_TRACEPOINT_SYMBOL_GPL(latency_tracker_begin);
EXPORT_TRACEPOINT_SYMBOL_GPL(latency_tracker_end);
EXPORT_TRACEPOINT_SYMBOL_GPL(latency_tracker_ttfb);

static void latency_tracker_enable_timer(struct latency_tracker *tracker);
static void latency_tracker_timer_cb(unsigned long ptr);
static void latency_tracker_timeout_cb(struct latency_tracker *tracker,
		struct latency_tracker_event *data, int flush);

/*
 * Function to get the timestamp.
 * FIXME: import the goodness from the LTTng trace clock
 */
static inline u64 trace_clock_monotonic_wrapper(void)
{
	ktime_t ktime;

	/*
	 * Refuse to trace from NMIs with this wrapper, because an NMI could
	 * nest over the xtime write seqlock and deadlock.
	 */
	if (in_nmi())
		return (u64) -EIO;

	ktime = ktime_get();
	return ktime_to_ns(ktime);
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0))
static
void deferred_latency_tracker_put_event(struct rcu_head *head)
{
	struct latency_tracker *tracker;
	struct latency_tracker_event *s =
		container_of(head, struct latency_tracker_event, u.urcuhead);
	tracker = s->tracker;
	wrapper_freelist_put_event(tracker, s);
}
#endif

static
void discard_event(struct latency_tracker *tracker,
		struct latency_tracker_event *s)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0))
	/*
	 * Our own call_rcu because the mainline one causes sched_wakeups
	 * that we might want to instrument causing deadlocks.
	 */
	int was_empty;

	/*
	 * We can reuse llist node because it is not used anymore
	 * by the parent list.
	 */
	was_empty = llist_add(&s->llist, &tracker->to_release);
	if (was_empty)
		queue_delayed_work(tracker->tracker_call_rcu_q,
				&tracker->tracker_call_rcu_w, 100);
#else
	call_rcu_sched(&s->u.urcuhead,
			deferred_latency_tracker_put_event);
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0) */
}

static
void tracker_call_rcu_workqueue(struct work_struct *work)
{
       struct latency_tracker *tracker;
       struct llist_node *list;
       struct latency_tracker_event *e, *n;

       tracker = container_of(work, struct latency_tracker,
		       tracker_call_rcu_w.work);
       list = llist_del_all(&tracker->to_release);
       synchronize_sched();
       llist_for_each_entry_safe(e, n, list, llist)
	       wrapper_freelist_put_event(tracker, e);
}


/*
 * Must be called with proper locking.
 */
void __latency_tracker_event_destroy(struct kref *kref)
{
	struct latency_tracker *tracker;
	struct latency_tracker_event *s;

	s = container_of(kref, struct latency_tracker_event, refcount);
	tracker = s->tracker;
	if (tracker->destroy_event_cb)
		tracker->destroy_event_cb(s);
	discard_event(tracker, s);
}

static
void latency_tracker_handle_timeouts(struct latency_tracker *tracker, int flush)
{
	struct cds_wfcq_node *qnode;
	struct latency_tracker_event *s;
	u64 now;

	if (unlikely(flush))
		now = -1ULL;
	else
		now = trace_clock_monotonic_wrapper();

	for (;;) {
		if (cds_wfcq_empty(&tracker->timeout_head, &tracker->timeout_tail))
			break;
		if (likely(!flush)) {
			/* Check before dequeue. */
			qnode = &tracker->timeout_head.node;
			if (!qnode->next)
				break;
			s = caa_container_of(qnode->next,
					struct latency_tracker_event, u.timeout_node);
			if (atomic_read(&s->refcount.refcount) > 1 &&
					(s->start_ts + tracker->timeout) > now)
				break;
		}

		qnode = __cds_wfcq_dequeue_nonblocking(&tracker->timeout_head,
				&tracker->timeout_tail);
		if (!qnode)
			break;
		s = caa_container_of(qnode, struct latency_tracker_event,
				u.timeout_node);
		latency_tracker_timeout_cb(tracker, s, flush);
	}
}

/*
 * The timer handles the garbage collection of the HT and starts
 * the resize work if needed.
 */
static
void latency_tracker_timer_cb(unsigned long ptr)
{
	struct latency_tracker *tracker = (struct latency_tracker *) ptr;
	unsigned long flags;
	u64 now;

	if (tracker->gc_thresh) {
		now = trace_clock_monotonic_wrapper();
		wrapper_ht_gc(tracker, now);
	}

	queue_work(tracker->resize_q, &tracker->resize_w);

	spin_lock_irqsave(&tracker->lock, flags);
	latency_tracker_enable_timer(tracker);
	spin_unlock_irqrestore(&tracker->lock, flags);
}

/* Must be called with the lock held. */
static
void latency_tracker_enable_timer(struct latency_tracker *tracker)
{
	del_timer(&tracker->timer);
	if (tracker->timer_period == 0)
		return;

	tracker->timer.function = latency_tracker_timer_cb;
	tracker->timer.expires = jiffies +
		wrapper_nsecs_to_jiffies(tracker->timer_period);
	tracker->timer.data = (unsigned long) tracker;
	add_timer(&tracker->timer);
}

static
void latency_tracker_workqueue(struct work_struct *work)
{
	struct latency_tracker *tracker;

	tracker = container_of(work, struct latency_tracker, resize_w);
	latency_tracker_handle_timeouts(tracker, 0);
	if (tracker->need_to_resize) {
		tracker->need_to_resize = 0;
		printk("latency_tracker: starting the resize\n");
		wrapper_resize_work(tracker);
	}
}

int latency_tracker_set_gc_thresh(struct latency_tracker *tracker,
		uint64_t gc_thresh)
{
	unsigned long flags;

	spin_lock_irqsave(&tracker->lock, flags);
	tracker->gc_thresh = gc_thresh;
	//latency_tracker_enable_timer(tracker);
	spin_unlock_irqrestore(&tracker->lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(latency_tracker_set_gc_thresh);

int latency_tracker_set_timer_period(struct latency_tracker *tracker,
		uint64_t timer_period)
{
	/* FIXME: locking, cancel existing, etc */
	if (!tracker->timer_period) {
		tracker->resize_q = create_singlethread_workqueue("latency_tracker");
		INIT_WORK(&tracker->resize_w, latency_tracker_workqueue);
	}
	tracker->timer_period = timer_period;
	cds_wfcq_init(&tracker->timeout_head, &tracker->timeout_tail);
	latency_tracker_enable_timer(tracker);

	return 0;
}
EXPORT_SYMBOL_GPL(latency_tracker_set_timer_period);

int latency_tracker_set_match_fct(struct latency_tracker *tracker,
		int (*match_fct) (const void *key1, const void *key2,
			size_t length))
{
	if (tracker->enabled)
		return -1;

	tracker->match_fct = match_fct;
	return 0;
}
EXPORT_SYMBOL_GPL(latency_tracker_set_match_fct);

int latency_tracker_set_hash_fct(struct latency_tracker *tracker,
		u32 (*hash_fct) (const void *key, u32 length, u32 initval))
{
	if (tracker->enabled)
		return -1;

	tracker->hash_fct = hash_fct;
	return 0;
}
EXPORT_SYMBOL_GPL(latency_tracker_set_hash_fct);

int latency_tracker_set_startup_events(struct latency_tracker *tracker,
		int startup_events)
{
	if (tracker->enabled)
		return -1;

	tracker->free_list_nelems = startup_events;
	return 0;
}
EXPORT_SYMBOL_GPL(latency_tracker_set_startup_events);

int latency_tracker_set_max_resize(struct latency_tracker *tracker,
		int max_resize)
{
	if (tracker->enabled)
		return -1;

	tracker->max_resize = max_resize;
	return 0;
}
EXPORT_SYMBOL_GPL(latency_tracker_set_max_resize);

int latency_tracker_set_priv(struct latency_tracker *tracker,
		void *priv)
{
	tracker->priv = priv;

	return 0;
}
EXPORT_SYMBOL_GPL(latency_tracker_set_priv);

int latency_tracker_set_timeout(struct latency_tracker *tracker,
		uint64_t timeout)
{
	tracker->timeout = timeout;

	return 0;
}
EXPORT_SYMBOL_GPL(latency_tracker_set_timeout);

int latency_tracker_set_threshold(struct latency_tracker *tracker,
		uint64_t threshold)
{
	tracker->threshold = threshold;
	return 0;
}
EXPORT_SYMBOL_GPL(latency_tracker_set_threshold);

uint64_t latency_tracker_get_timeout(struct latency_tracker *tracker)
{
	return tracker->timeout;
}
EXPORT_SYMBOL_GPL(latency_tracker_get_timeout);


uint64_t latency_tracker_get_threshold(struct latency_tracker *tracker)
{
	return tracker->threshold;
}
EXPORT_SYMBOL_GPL(latency_tracker_get_threshold);

int latency_tracker_get_tracking_on(struct latency_tracker *tracker)
{
	return tracker->tracking_on;
}
EXPORT_SYMBOL_GPL(latency_tracker_get_tracking_on);

int latency_tracker_set_tracking_on(struct latency_tracker *tracker,
		int val, int cleanup)
{
	int old;

	old = tracker->tracking_on;
	tracker->tracking_on = val;
	/* This cannot be done from within a tracepoint probe (deadlock) */
	if (cleanup) {
		synchronize_sched();
		if (old > 0 && val == 0)
			latency_tracker_clear_ht(tracker);
	}
	if (tracker->change_tracking_on_cb)
		tracker->change_tracking_on_cb(tracker, old, val);

	return 0;
}
EXPORT_SYMBOL_GPL(latency_tracker_set_tracking_on);

int latency_tracker_set_callback(struct latency_tracker *tracker,
		void (*cb)(struct latency_tracker_event_ctx *ctx))
{
	tracker->cb = cb;
	return 0;
}
EXPORT_SYMBOL_GPL(latency_tracker_set_callback);

int latency_tracker_set_key_size(struct latency_tracker *tracker,
		int size)
{
	if (tracker->enabled)
		return -1;

	tracker->key_size = size;
	return 0;
}
EXPORT_SYMBOL_GPL(latency_tracker_set_key_size);

int latency_tracker_set_priv_data_size(struct latency_tracker *tracker,
		int size)
{
	if (tracker->enabled)
		return -1;

	tracker->priv_data_size = size;
	return 0;
}
EXPORT_SYMBOL_GPL(latency_tracker_set_priv_data_size);

int latency_tracker_set_destroy_event_cb(struct latency_tracker *tracker,
		void (*destroy_event_cb) (struct latency_tracker_event *event))
{
	if (tracker->enabled)
		return -1;

	tracker->destroy_event_cb = destroy_event_cb;
	return 0;
}
EXPORT_SYMBOL_GPL(latency_tracker_set_destroy_event_cb);

int latency_tracker_set_change_tracking_on_cb(struct latency_tracker *tracker,
		void (*change_tracking_on_cb) (struct latency_tracker *tracker,
			int prev_value, int new_value))
{
	if (tracker->enabled)
		return -1;

	tracker->change_tracking_on_cb = change_tracking_on_cb;
	return 0;
}
EXPORT_SYMBOL_GPL(latency_tracker_set_change_tracking_on_cb);

struct latency_tracker *latency_tracker_create(const char *name)
{
	struct latency_tracker *tracker;
	int ret;

	tracker = kzalloc(sizeof(struct latency_tracker), GFP_KERNEL);
	if (!tracker) {
		printk("latency_tracker: Alloc tracker failed\n");
		goto error;
	}
	tracker->hash_fct = jhash;
	tracker->match_fct = memcmp;
	tracker->key_size = sizeof(long);
	tracker->free_list_nelems = DEFAULT_STARTUP_ALLOC_EVENTS;
	tracker->threshold = DEFAULT_THRESHOLD;
	tracker->tracking_on = 0;
	if (!name)
		goto error_free;
	strncpy(tracker->tracker_name, name, 32);
	ret = latency_tracker_debugfs_add_tracker(tracker);
	if (ret != 0) {
		printk("latency_tracker: debugfs creation error\n");
		goto error_free;
	}
	init_timer(&tracker->timer);
	spin_lock_init(&tracker->lock);
	wrapper_ht_init(tracker);
	tracker->tracker_call_rcu_q = create_workqueue("tracker_rcu");
	INIT_DELAYED_WORK(&tracker->tracker_call_rcu_w, tracker_call_rcu_workqueue);

	ret = try_module_get(THIS_MODULE);
	if (!ret)
		goto error_debugfs;
#ifdef BENCH
	alloc_measurements();
#endif
	goto end;

error_debugfs:
	latency_tracker_debugfs_remove_tracker(tracker);
error_free:
	kfree(tracker);
error:
	tracker = NULL;
end:
	return tracker;
}
EXPORT_SYMBOL_GPL(latency_tracker_create);

int latency_tracker_enable(struct latency_tracker *tracker)
{
	tracker->enabled = 1;
	return wrapper_freelist_init(tracker, tracker->free_list_nelems);
}
EXPORT_SYMBOL_GPL(latency_tracker_enable);

int latency_tracker_clear_ht(struct latency_tracker *tracker)
{
	return wrapper_ht_clear(tracker);
}
EXPORT_SYMBOL_GPL(latency_tracker_clear_ht);

void latency_tracker_destroy(struct latency_tracker *tracker)
{
	int nb = 0;

	/*
	 * All callers of in/out are required to have preemption disable. We
	 * issue a synchronize_sched to ensure no more in/out are running.
	 */
	synchronize_sched();

	/*
	 * Remove timer, and make sure currently running timers have completed.
	 */
	del_timer_sync(&tracker->timer);

	/*
	 * Stop and destroy the freelist resize work queue.
	 */
	if (tracker->timer_period) {
		flush_workqueue(tracker->resize_q);
		destroy_workqueue(tracker->resize_q);
	}
	del_timer_sync(&tracker->timer);

	cancel_delayed_work(&tracker->tracker_call_rcu_w);
	flush_workqueue(tracker->tracker_call_rcu_q);
	destroy_workqueue(tracker->tracker_call_rcu_q);

	nb = latency_tracker_clear_ht(tracker);
	printk("latency_tracker: %d events were still pending at destruction\n", nb);

	if (tracker->timer_period)
		latency_tracker_handle_timeouts(tracker, 1);

	latency_tracker_debugfs_remove_tracker(tracker);
	/*
	 * Wait for all call_rcu_sched issued within wrapper_ht_clear to have
	 * completed.
	 */
	rcu_barrier_sched();

	wrapper_freelist_destroy(tracker);

#ifdef BENCH
	output_measurements();
	free_measurements();
#endif
	kfree(tracker);
	module_put(THIS_MODULE);
}
EXPORT_SYMBOL_GPL(latency_tracker_destroy);

static
void latency_tracker_timeout_cb(struct latency_tracker *tracker,
		struct latency_tracker_event *data, int flush)
{
	int ret;
	struct latency_tracker_event_ctx ctx = {
		.start_ts = data->start_ts,
		.end_ts = trace_clock_monotonic_wrapper(),
		.cb_flag = LATENCY_TRACKER_CB_TIMEOUT,
		.cb_out_id = 0,
		.tkey = &data->tkey,
		.priv = data->priv,
		.priv_data = data->priv_data,
	};

	if (unlikely(flush)) {
		__latency_tracker_event_destroy(&data->refcount);
		return;
	}

	ret = kref_put(&data->refcount, __latency_tracker_event_destroy);
	/* Run the user-provided callback if it has never been run. */
	if (!ret)
		tracker->cb(&ctx);
}

enum latency_tracker_event_in_ret _latency_tracker_event_in_get(
		struct latency_tracker *tracker,
		void *key, size_t key_len,
		unsigned int unique, u64 ts_override,
		void *priv, struct latency_tracker_event **new_event)
{
	struct latency_tracker_event *s, *old_s;
	int ret;
	u32 hkey;
#ifdef BENCH
	BENCH_PREAMBULE;

	BENCH_GET_TS1;
#endif
	if (!tracker) {
		ret = LATENCY_TRACKER_ERR;
		goto end;
	}
	if (!tracker->enabled) {
		ret = LATENCY_TRACKER_DISABLED;
		goto end;
	}
	if (key_len > tracker->key_size) {
		ret = LATENCY_TRACKER_ERR;
		goto end;
	}

	s = wrapper_freelist_get_event(tracker);

	if (!s) {
		ret = LATENCY_TRACKER_FULL;
		tracker->skipped_count++;
		goto end_unlock;
	}
	tracker->tracked_count++;
	hkey = tracker->hash_fct(key, key_len, 0);

	memcpy(s->tkey.key, key, key_len);
	s->tkey.key_len = key_len;
	s->tracker = tracker;
	if (ts_override)
		s->start_ts = ts_override;
	else
		s->start_ts = trace_clock_monotonic_wrapper();
	s->priv = priv;
	kref_init(&s->refcount);

	if (tracker->timeout > 0) {
		if (!tracker->timer_period) {
			/* Need the tracker timer to handle the timeout. */
			ret = LATENCY_TRACKER_ERR_TIMEOUT;
			goto end_unlock;
		}
		kref_get(&s->refcount);
		cds_wfcq_enqueue(&tracker->timeout_head,
				&tracker->timeout_tail, &s->u.timeout_node);
	}

	if (new_event) {
		kref_get(&s->refcount);
		*new_event = s;
	}
	/*
	 * If we specify the unique property, get rid of other duplicate keys
	 * without calling the callback.
	 */
	if (unique)
		wrapper_ht_unique_check(tracker, &s->tkey);
	old_s = wrapper_ht_add(tracker, s, hkey, unique);
	if (old_s) {
		kref_put(&old_s->refcount, __latency_tracker_event_destroy);
	}

	if ((s == tracker->resize_event) &&
			(tracker->free_list_nelems < tracker->max_resize)) {
		tracker->need_to_resize = 1;
		tracker->resize_event = NULL;
	}

	ret = LATENCY_TRACKER_OK;

	goto end;

end_unlock:

end:
#ifdef BENCH
	BENCH_GET_TS2;
	BENCH_APPEND;
#endif
	return ret;
}
EXPORT_SYMBOL_GPL(_latency_tracker_event_in_get);

enum latency_tracker_event_in_ret _latency_tracker_event_in(
		struct latency_tracker *tracker,
		void *key, size_t key_len,
		unsigned int unique, u64 ts_override,
		void *priv)
{
		return _latency_tracker_event_in_get(tracker,
				key, key_len, unique, ts_override,
				priv, NULL);
}
EXPORT_SYMBOL_GPL(_latency_tracker_event_in);

enum latency_tracker_event_in_ret latency_tracker_event_in(
		struct latency_tracker *tracker,
		void *key, size_t key_len,
		unsigned int unique, void *priv)
{
	enum latency_tracker_event_in_ret ret;

	rcu_read_lock_sched_notrace();
	ret = _latency_tracker_event_in(tracker, key, key_len, unique, 0, priv);
	rcu_read_unlock_sched_notrace();

	return ret;
}
EXPORT_SYMBOL_GPL(latency_tracker_event_in);

int _latency_tracker_event_out(struct latency_tracker *tracker,
		struct latency_tracker_event *event, void *key,
		unsigned int key_len, unsigned int id,
		u64 ts_override)
{
	int ret;
	int found = 0;
	u64 now;
	struct latency_tracker_key tkey;

	if (!tracker) {
		goto error;
	}
	if (!tracker->enabled) {
		ret = LATENCY_TRACKER_DISABLED;
		goto end;
	}

	if (ts_override)
		now = ts_override;
	else
		now = trace_clock_monotonic_wrapper();

	if (event) {
		wrapper_check_cb(tracker, now, id, event);
		ret = wrapper_ht_del(tracker, event);
		if (!ret)
			kref_put(&event->refcount, __latency_tracker_event_destroy);
		found = 1;
	} else {
		tkey.key_len = key_len;
		tkey.key = key;
		found = wrapper_ht_check_event(tracker, &tkey, id, now);
	}

	if (!found)
		goto error;

	ret = 0;
	goto end;

error:
	ret = -1;
end:
	return ret;
}
EXPORT_SYMBOL_GPL(_latency_tracker_event_out);

int latency_tracker_event_out(struct latency_tracker *tracker,
		struct latency_tracker_event *event, void *key,
		unsigned int key_len, unsigned int id, u64 ts_override)
{
	int ret;

	rcu_read_lock_sched_notrace();
	ret = _latency_tracker_event_out(tracker, event, key, key_len, id,
			ts_override);
	rcu_read_unlock_sched_notrace();
	return ret;
}
EXPORT_SYMBOL_GPL(latency_tracker_event_out);

struct latency_tracker_event *latency_tracker_get_event_by_key(
		struct latency_tracker *tracker, void *key,
		unsigned int key_len, struct latency_tracker_event_iter *iter)
{
	struct latency_tracker_event *s;
	struct latency_tracker_key tkey;
	int ret;

	tkey.key_len = key_len;
	tkey.key = key;

	rcu_read_lock_sched_notrace();
	s = wrapper_ht_find_event(tracker, &tkey, iter);
	if (!s)
		goto end;

	ret = kref_get_unless_zero(&s->refcount);
	if (!ret)
		s = NULL;

end:
	rcu_read_unlock_sched_notrace();
	return s;
}
EXPORT_SYMBOL_GPL(latency_tracker_get_event_by_key);

struct latency_tracker_event *latency_tracker_get_next_duplicate(
		struct latency_tracker *tracker, void *key,
		unsigned int key_len, struct latency_tracker_event_iter *iter)
{
	struct latency_tracker_event *s;
	struct latency_tracker_key tkey;
	int ret;

	tkey.key_len = key_len;
	tkey.key = key;

	WARN_ON_ONCE(!rcu_read_lock_sched_held());
	s = wrapper_ht_next_duplicate(tracker, &tkey, iter);
	if (!s)
		goto end;

	ret = kref_get_unless_zero(&s->refcount);
	if (!ret)
		s = NULL;

end:
	return s;
}
EXPORT_SYMBOL_GPL(latency_tracker_get_next_duplicate);

int latency_tracker_ref_event(struct latency_tracker_event *event)
{
	/*
	 * 0: failed
	 * 1: success
	 */
	return kref_get_unless_zero(&event->refcount);
}
EXPORT_SYMBOL_GPL(latency_tracker_ref_event);

void latency_tracker_unref_event(struct latency_tracker_event *event)
{
	if (!event)
		return;
	rcu_read_lock_sched_notrace();
	kref_put(&event->refcount, __latency_tracker_event_destroy);
	rcu_read_unlock_sched_notrace();
}
EXPORT_SYMBOL_GPL(latency_tracker_unref_event);

void *latency_tracker_event_get_priv(
		struct latency_tracker_event *event)
{
	return event->priv;
}
EXPORT_SYMBOL_GPL(latency_tracker_event_get_priv);

void *latency_tracker_event_get_priv_data(
		struct latency_tracker_event *event)
{
	return event->priv_data;
}
EXPORT_SYMBOL_GPL(latency_tracker_event_get_priv_data);

uint64_t latency_tracker_event_get_start_ts(
		struct latency_tracker_event *event)
{
	return event->start_ts;
}
EXPORT_SYMBOL_GPL(latency_tracker_event_get_start_ts);

void *latency_tracker_get_priv(struct latency_tracker *tracker)
{
	return tracker->priv;
}
EXPORT_SYMBOL_GPL(latency_tracker_get_priv);

uint64_t latency_tracker_skipped_count(struct latency_tracker *tracker)
{
	return tracker->skipped_count;
}
EXPORT_SYMBOL_GPL(latency_tracker_skipped_count);

uint64_t latency_tracker_tracked_count(struct latency_tracker *tracker)
{
	return tracker->tracked_count;
}
EXPORT_SYMBOL_GPL(latency_tracker_tracked_count);

void example_cb(struct latency_tracker_event_ctx *ctx)
{
	printk("cb called for key %s with %p, cb_flag = %d\n",
			latency_tracker_event_ctx_get_key(ctx)->key,
			latency_tracker_event_ctx_get_priv(ctx),
			latency_tracker_event_ctx_get_cb_flag(ctx));
}

static
int test_tracker(void)
{
	char *k1 = "blablabla1";
	char *k2 = "bliblibli1";
	int ret, i;
	struct latency_tracker *tracker;

	tracker = latency_tracker_create("test");
	if (!tracker)
		goto error;
	ret = latency_tracker_set_startup_events(tracker, 300);
	if (ret)
		goto error;
	ret = latency_tracker_set_timer_period(tracker, 100*1000*1000);
	if (ret)
		goto error;
	ret = latency_tracker_set_key_size(tracker, strlen(k1) + 1);
	if (ret)
		goto error;
	ret = latency_tracker_enable(tracker);
	if (ret)
		goto error;

	for (i = 0; i < 10; i++) {
	printk("insert k1\n");
	ret = latency_tracker_event_in(tracker, k1, strlen(k1) + 1, 0, NULL);
	if (ret)
		printk("failed\n");
	udelay(10000);
	}

	printk("insert k2\n");
	rcu_read_lock_sched_notrace();
	ret = _latency_tracker_event_in(tracker, k2, strlen(k2) + 1, 0, 0, NULL);
	rcu_read_unlock_sched_notrace();
	if (ret)
		printk("failed\n");

	printk("lookup k1\n");
	latency_tracker_event_out(tracker, NULL, k1, strlen(k1) + 1, 0, 0);
	printk("lookup k2\n");
	latency_tracker_event_out(tracker, NULL, k2, strlen(k2) + 1, 0, 0);
	printk("lookup k1\n");
	rcu_read_lock_sched_notrace();
	_latency_tracker_event_out(tracker, NULL, k1, strlen(k1) + 1, 0, 0);
	rcu_read_unlock_sched_notrace();

	printk("done\n");
	latency_tracker_destroy(tracker);

	ret = 0;
	goto end;

error:
	ret = -1;
end:
	return ret;
}

static
int __init latency_tracker_init(void)
{
	int ret;

	ret = latency_tracker_debugfs_setup();
	if (ret < 0)
		goto end;
	ret = test_tracker();

	ret = lttng_tracepoint_init();
	if (ret)
		return ret;

end:
	return ret;
}

static
void __exit latency_tracker_exit(void)
{
	latency_tracker_debugfs_cleanup();
	lttng_tracepoint_exit();
}

module_init(latency_tracker_init);
module_exit(latency_tracker_exit);
MODULE_AUTHOR("Julien Desfossez <jdesfossez@efficios.com>");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL");
