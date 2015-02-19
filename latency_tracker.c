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
#include <linux/preempt_mask.h>
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
#define CREATE_TRACE_POINTS
#include <trace/events/latency_tracker.h>

#define DEFAULT_MAX_ALLOC_EVENTS 100

EXPORT_TRACEPOINT_SYMBOL_GPL(sched_latency);
EXPORT_TRACEPOINT_SYMBOL_GPL(net_latency);
EXPORT_TRACEPOINT_SYMBOL_GPL(block_latency);

static void latency_tracker_enable_gc(struct latency_tracker *tracker);
static void latency_tracker_gc_cb(unsigned long ptr);

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

static
void deferred_latency_tracker_put_event(struct rcu_head *head)
{
	struct latency_tracker *tracker;
	struct latency_tracker_event *s =
		container_of(head, struct latency_tracker_event, urcuhead);
	tracker = s->tracker;
	wrapper_freelist_put_event(tracker, s);
}

static
void discard_event(struct latency_tracker *tracker,
		struct latency_tracker_event *s)
{
#if defined(BASEHT) && !defined(LLFREELIST)
	__wrapper_freelist_put_event(tracker, s);
#else
	call_rcu_sched(&s->urcuhead,
			deferred_latency_tracker_put_event);
#endif
}

/*
 * Must be called with proper locking.
 */
static
void __latency_tracker_event_destroy(struct latency_tracker *tracker,
		struct latency_tracker_event *s)
{
	int ret;

	ret = wrapper_ht_del(tracker, s);
	if (ret) {
		/* Has already been removed concurrently, we do not own it. */
		return;
	}
	if (s->timeout > 0)
		del_timer_sync(&s->timer);

	discard_event(tracker, s);
}

static
void latency_tracker_event_destroy(struct latency_tracker *tracker,
		struct latency_tracker_event *s)
{
	unsigned long flags;

	spin_lock_irqsave(&tracker->lock, flags);
	__latency_tracker_event_destroy(tracker, s);
	spin_unlock_irqrestore(&tracker->lock, flags);
}

static
void latency_tracker_gc_cb(unsigned long ptr)
{
	struct latency_tracker *tracker = (struct latency_tracker *) ptr;
	unsigned long flags;
	u64 now;

	now = trace_clock_monotonic_wrapper();
	wrapper_ht_gc(tracker, now);
	spin_lock_irqsave(&tracker->lock, flags);
	latency_tracker_enable_gc(tracker);
	spin_unlock_irqrestore(&tracker->lock, flags);
}

/* Must be called with the lock held. */
static
void latency_tracker_enable_gc(struct latency_tracker *tracker)
{
	del_timer(&tracker->timer);
	if (tracker->gc_period == 0 || tracker->gc_thresh == 0) {
		return;
	}

	tracker->timer.function = latency_tracker_gc_cb;
	tracker->timer.expires = jiffies +
		wrapper_nsecs_to_jiffies(tracker->gc_period);
	tracker->timer.data = (unsigned long) tracker;
	add_timer(&tracker->timer);
}

void latency_tracker_set_gc_thresh(struct latency_tracker *tracker,
		uint64_t gc_thresh)
{
	unsigned long flags;

	spin_lock_irqsave(&tracker->lock, flags);
	tracker->gc_thresh = gc_thresh;
	latency_tracker_enable_gc(tracker);
	spin_unlock_irqrestore(&tracker->lock, flags);
}

void latency_tracker_set_gc_period(struct latency_tracker *tracker,
		uint64_t gc_period)
{
	unsigned long flags;

	spin_lock_irqsave(&tracker->lock, flags);
	tracker->gc_period = gc_period;
	latency_tracker_enable_gc(tracker);
	spin_unlock_irqrestore(&tracker->lock, flags);
}

struct latency_tracker *latency_tracker_create(
		int (*match_fct) (const void *key1, const void *key2,
			size_t length),
		u32 (*hash_fct) (const void *key, u32 length, u32 initval),
		int max_events, int max_resize, uint64_t gc_period,
		uint64_t gc_thresh, void *priv)

{
	struct latency_tracker *tracker;
	int ret;

	tracker = kzalloc(sizeof(struct latency_tracker), GFP_KERNEL);
	if (!tracker) {
		printk("latency_tracker: Alloc tracker failed\n");
		goto error;
	}
	if (!hash_fct) {
		tracker->hash_fct = jhash;
	}
	if (!match_fct) {
		tracker->match_fct = memcmp;
	}
	if (!max_events)
		max_events = DEFAULT_MAX_ALLOC_EVENTS;
	tracker->gc_period = gc_period;
	tracker->gc_thresh = gc_thresh;
	tracker->priv = priv;

	init_timer(&tracker->timer);
	latency_tracker_enable_gc(tracker);

	spin_lock_init(&tracker->lock);

	wrapper_ht_init(tracker);

	tracker->max_resize = max_resize;
	if (max_resize) {
		tracker->resize_q = create_singlethread_workqueue("resize");
		INIT_DELAYED_WORK(&tracker->resize_w, wrapper_resize_work);
	}

	ret = wrapper_freelist_init(tracker, max_events);
	if (ret < 0)
		goto error_free_events;

	ret = try_module_get(THIS_MODULE);
	if (!ret)
		goto error_free_events;

	goto end;

error_free_events:
	wrapper_freelist_destroy(tracker);
	kfree(tracker);
error:
	tracker = NULL;
end:
	return tracker;
}
EXPORT_SYMBOL_GPL(latency_tracker_create);

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
	if (tracker->max_resize) {
		flush_workqueue(tracker->resize_q);
		destroy_workqueue(tracker->resize_q);
	}

	nb = wrapper_ht_clear(tracker);
	printk("latency_tracker: %d events were still pending at destruction\n", nb);

	/*
	 * Wait for all call_rcu_sched issued within wrapper_ht_clear to have
	 * completed.
	 */
	rcu_barrier_sched();

	wrapper_freelist_destroy(tracker);

	kfree(tracker);
	module_put(THIS_MODULE);
}
EXPORT_SYMBOL_GPL(latency_tracker_destroy);

static
void latency_tracker_timeout_cb(unsigned long ptr)
{
	struct latency_tracker_event *data = (struct latency_tracker_event *) ptr;

	del_timer(&data->timer);
	data->cb_flag = LATENCY_TRACKER_CB_TIMEOUT;
	data->timeout = 0;

	/* Run the user-provided callback. */
	data->cb(ptr);
}

enum latency_tracker_event_in_ret _latency_tracker_event_in(
		struct latency_tracker *tracker,
		void *key, size_t key_len, uint64_t thresh,
		void (*cb)(unsigned long ptr),
		uint64_t timeout, unsigned int unique, void *priv)
{
	struct latency_tracker_event *s, *old_s;
	int ret;
	unsigned long flags;

	if (!tracker) {
		ret = LATENCY_TRACKER_ERR;
		goto end;
	}
	if (key_len > LATENCY_TRACKER_MAX_KEY_SIZE) {
		ret = LATENCY_TRACKER_ERR;
		goto end;
	}

#if !defined(LLFREELIST)
	spin_lock_irqsave(&tracker->lock, flags);
#endif

	s = wrapper_freelist_get_event(tracker);

#if !defined(LLFREELIST) && defined URCUHT
	spin_unlock_irqrestore(&tracker->lock, flags);
#endif
	if (!s) {
		ret = LATENCY_TRACKER_FULL;
		goto end;
	}
	s->hkey = tracker->hash_fct(key, key_len, 0);

	memcpy(s->tkey.key, key, key_len);
	s->tkey.key_len = key_len;
	s->tracker = tracker;
	s->start_ts = trace_clock_monotonic_wrapper();
	s->thresh = thresh;
	s->timeout = timeout;
	s->cb = cb;
	s->priv = priv;

	if (timeout > 0) {
		init_timer(&s->timer);
		s->timer.function = latency_tracker_timeout_cb;
		s->timer.expires = jiffies +
			wrapper_nsecs_to_jiffies(timeout);
		s->timer.data = (unsigned long) s;
		add_timer(&s->timer);
	}

	/*
	 * If we specify the unique property, get rid of other duplicate keys
	 * without calling the callback.
	 */
	if (unique)
		wrapper_ht_unique_check(tracker, &s->tkey);
	old_s = wrapper_ht_add(tracker, s);
	if (old_s) {
		discard_event(tracker, old_s);
	}
#if !defined(LLFREELIST) && !defined(URCUHT)
	spin_unlock_irqrestore(&tracker->lock, flags);
#endif
	if (s->resize_flag &&
			(tracker->free_list_nelems < tracker->max_resize)) {
		printk("latency_tracker: starting the resize\n");
		queue_delayed_work(tracker->resize_q, &tracker->resize_w, 100);
//		queue_work(tracker->resize_q, &tracker->resize_w);
	}

	ret = LATENCY_TRACKER_OK;

end:
	return ret;
}
EXPORT_SYMBOL_GPL(_latency_tracker_event_in);

enum latency_tracker_event_in_ret latency_tracker_event_in(
		struct latency_tracker *tracker,
		void *key, size_t key_len, uint64_t thresh,
		void (*cb)(unsigned long ptr),
		uint64_t timeout, unsigned int unique, void *priv)
{
	enum latency_tracker_event_in_ret ret;

	rcu_read_lock_sched_notrace();
	ret = _latency_tracker_event_in(tracker, key, key_len, thresh, cb,
			timeout, unique, priv);
	rcu_read_unlock_sched_notrace();

	return ret;
}
EXPORT_SYMBOL_GPL(latency_tracker_event_in);

int _latency_tracker_event_out(struct latency_tracker *tracker,
		void *key, unsigned int key_len, unsigned int id)
{
	int ret;
	int found = 0;
	u64 now;
	struct latency_tracker_key tkey;

	if (!tracker) {
		goto error;
	}

	now = trace_clock_monotonic_wrapper();
	tkey.key_len = key_len;
	memcpy(tkey.key, key, key_len);
	found = wrapper_ht_check_event(tracker, &tkey, id, now);

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
		void *key, unsigned int key_len, unsigned int id)
{
	int ret;

	rcu_read_lock_sched_notrace();
	ret = _latency_tracker_event_out(tracker, key, key_len, id);
	rcu_read_unlock_sched_notrace();
	return ret;
}
EXPORT_SYMBOL_GPL(latency_tracker_event_out);

void *latency_tracker_get_priv(struct latency_tracker *tracker)
{
	return tracker->priv;
}
EXPORT_SYMBOL_GPL(latency_tracker_get_priv);

void example_cb(unsigned long ptr)
{
	struct latency_tracker_event *data = (struct latency_tracker_event *) ptr;

	printk("cb called for key %s with %p, cb_flag = %d\n", (char *) data->tkey.key,
			data->priv, data->cb_flag);
}

static
int test_tracker(void)
{
	char *k1 = "blablabla1";
	char *k2 = "bliblibli1";
	int ret, i;
	struct latency_tracker *tracker;

	tracker = latency_tracker_create(NULL, NULL, 3, 0, 0, 0, NULL);
	if (!tracker)
		goto error;

	for (i = 0; i < 30; i++) {
		printk("insert k1\n");
		ret = latency_tracker_event_in(tracker, k1, strlen(k1) + 1, 6,
				example_cb, 0, 0, NULL);
		if (ret)
			printk("failed\n");

		printk("insert k2\n");
		rcu_read_lock_sched_notrace();
		ret = _latency_tracker_event_in(tracker, k2, strlen(k2) + 1, 400,
				example_cb, 0, 0, NULL);
		rcu_read_unlock_sched_notrace();
		if (ret)
			printk("failed\n");
		yield();
	}

	printk("lookup k1\n");
	latency_tracker_event_out(tracker, k1, strlen(k1) + 1, 0);
	printk("lookup k2\n");
	latency_tracker_event_out(tracker, k2, strlen(k2) + 1, 0);
	printk("lookup k1\n");
	rcu_read_lock_sched_notrace();
	_latency_tracker_event_out(tracker, k1, strlen(k1) + 1, 0);
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

	ret = test_tracker();

	ret = lttng_tracepoint_init();
	if (ret)
		return ret;

	return ret;
}

static
void __exit latency_tracker_exit(void)
{
	lttng_tracepoint_exit();
}

module_init(latency_tracker_init);
module_exit(latency_tracker_exit);
MODULE_AUTHOR("Julien Desfossez <jdesfossez@efficios.com>");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL");
