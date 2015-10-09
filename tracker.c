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
#define CREATE_TRACE_POINTS
#include <trace/events/latency_tracker.h>

#define DEFAULT_MAX_ALLOC_EVENTS 100

EXPORT_TRACEPOINT_SYMBOL_GPL(latency_tracker_wakeup);
EXPORT_TRACEPOINT_SYMBOL_GPL(latency_tracker_offcpu_sched_switch);
EXPORT_TRACEPOINT_SYMBOL_GPL(latency_tracker_offcpu_sched_wakeup);
EXPORT_TRACEPOINT_SYMBOL_GPL(latency_tracker_syscall);
EXPORT_TRACEPOINT_SYMBOL_GPL(latency_tracker_syscall_stack);
EXPORT_TRACEPOINT_SYMBOL_GPL(latency_tracker_net);
EXPORT_TRACEPOINT_SYMBOL_GPL(latency_tracker_block);

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
		container_of(head, struct latency_tracker_event, urcuhead);
	tracker = s->tracker;
	wrapper_freelist_put_event(tracker, s);
}
#endif

static
void discard_event(struct latency_tracker *tracker,
		struct latency_tracker_event *s)
{
#if defined(BASEHT) && !defined(LLFREELIST)
	__wrapper_freelist_put_event(tracker, s);
#else
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0))
	/*
	 * Our own call_rcu because the mainline one causes sched_wakeups
	 * that we might want to instrument causing deadlocks.
	 */
	int was_empty;

	was_empty = llist_add(&s->release_llist, &tracker->to_release);
	if (was_empty)
		queue_delayed_work(tracker->tracker_call_rcu_q,
				&tracker->tracker_call_rcu_w, 100);
#else
	call_rcu_sched(&s->urcuhead,
			deferred_latency_tracker_put_event);
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0) */
#endif
}

#if defined(URCUHT) || defined(LLFREELIST)
static
void tracker_call_rcu_workqueue(struct work_struct *work)
{
       struct latency_tracker *tracker;
       struct llist_node *list;
       struct latency_tracker_event *e, *n;

       tracker = container_of(work, struct latency_tracker,
		       tracker_call_rcu_w.work);

       if (!tracker)
	       return;

       list = llist_del_all(&tracker->to_release);
       synchronize_sched();
       llist_for_each_entry_safe(e, n, list, release_llist)
	       wrapper_freelist_put_event(tracker, e);
}
#endif


/*
 * Must be called with proper locking.
 */
static
void __latency_tracker_event_destroy(struct kref *kref)
{
	struct latency_tracker *tracker;
	struct latency_tracker_event *s;

	s = container_of(kref, struct latency_tracker_event, refcount);
	tracker = s->tracker;
	discard_event(tracker, s);
}

#if defined(OLDFREELIST)
static
void latency_tracker_event_destroy(struct kref *kref)
{
	unsigned long flags;
	struct latency_tracker *tracker;
	struct latency_tracker_event *s;

	s = container_of(kref, struct latency_tracker_event, refcount);
	tracker = s->tracker;

	spin_lock_irqsave(&tracker->lock, flags);
	__latency_tracker_event_destroy(kref);
	spin_unlock_irqrestore(&tracker->lock, flags);
}
#endif

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
					struct latency_tracker_event, timeout_node);
			if (atomic_read(&s->refcount.refcount) > 1 &&
					(s->start_ts + tracker->timeout) > now)
				break;
		}

		qnode = __cds_wfcq_dequeue_nonblocking(&tracker->timeout_head,
				&tracker->timeout_tail);
		if (!qnode)
			break;
		s = caa_container_of(qnode, struct latency_tracker_event,
				timeout_node);
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
	if (!tracker)
		return;
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
	if (tracker->started)
		return -1;

	tracker->match_fct = match_fct;
	return 0;
}
EXPORT_SYMBOL_GPL(latency_tracker_set_match_fct);

int latency_tracker_set_hash_fct(struct latency_tracker *tracker,
		u32 (*hash_fct) (const void *key, u32 length, u32 initval))
{
	if (tracker->started)
		return -1;

	tracker->hash_fct = hash_fct;
	return 0;
}
EXPORT_SYMBOL_GPL(latency_tracker_set_hash_fct);

int latency_tracker_set_max_events(struct latency_tracker *tracker,
		int max_events)
{
	if (tracker->started)
		return -1;

	tracker->max_events = max_events;
	return wrapper_freelist_init(tracker, tracker->max_events);
}
EXPORT_SYMBOL_GPL(latency_tracker_set_max_events);

int latency_tracker_set_max_resize(struct latency_tracker *tracker,
		int max_resize)
{
	if (tracker->started)
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

int latency_tracker_set_callback(struct latency_tracker *tracker,
		void (*cb)(struct latency_tracker_event_ctx *ctx))
{
	tracker->cb = cb;
	return 0;
}
EXPORT_SYMBOL_GPL(latency_tracker_set_callback);

struct latency_tracker *latency_tracker_create(void)
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
	tracker->max_events = DEFAULT_MAX_ALLOC_EVENTS;
	init_timer(&tracker->timer);
	spin_lock_init(&tracker->lock);
	wrapper_ht_init(tracker);
#if defined(URCUHT) || defined(LLFREELIST)
	tracker->tracker_call_rcu_q = create_workqueue("tracker_rcu");
	INIT_DELAYED_WORK(&tracker->tracker_call_rcu_w, tracker_call_rcu_workqueue);
#endif

	ret = try_module_get(THIS_MODULE);
	if (!ret)
		goto error_free;
	goto end;

error_free:
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
	if (tracker->timer_period) {
		flush_workqueue(tracker->resize_q);
		destroy_workqueue(tracker->resize_q);
	}
	del_timer_sync(&tracker->timer);

#if defined(URCUHT) || defined(LLFREELIST)
	cancel_delayed_work(&tracker->tracker_call_rcu_w);
	flush_workqueue(tracker->tracker_call_rcu_q);
	destroy_workqueue(tracker->tracker_call_rcu_q);
#endif

	nb = wrapper_ht_clear(tracker);
	printk("latency_tracker: %d events were still pending at destruction\n", nb);

	if (tracker->timer_period)
		latency_tracker_handle_timeouts(tracker, 1);
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
	};

	if (unlikely(flush)) {
#if !defined(LLFREELIST)
		latency_tracker_event_destroy(&data->refcount);
#else
		__latency_tracker_event_destroy(&data->refcount);
#endif
		return;
	}

#if !defined(LLFREELIST)
	ret = kref_put(&data->refcount, latency_tracker_event_destroy);
#else
	ret = kref_put(&data->refcount, __latency_tracker_event_destroy);
#endif
	/* Run the user-provided callback if it has never been run. */
	if (!ret)
		tracker->cb(&ctx);
}

enum latency_tracker_event_in_ret _latency_tracker_event_in(
		struct latency_tracker *tracker,
		void *key, size_t key_len,
		unsigned int unique, void *priv)
{
	struct latency_tracker_event *s, *old_s;
	int ret;
#if !defined(LLFREELIST)
	unsigned long flags;
#endif

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
		tracker->skipped_count++;
		goto end_unlock;
	}
	s->hkey = tracker->hash_fct(key, key_len, 0);

	memcpy(s->tkey.key, key, key_len);
	s->tkey.key_len = key_len;
	s->tracker = tracker;
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
				&tracker->timeout_tail, &s->timeout_node);
	}

	/*
	 * If we specify the unique property, get rid of other duplicate keys
	 * without calling the callback.
	 */
	if (unique)
		wrapper_ht_unique_check(tracker, &s->tkey);
	old_s = wrapper_ht_add(tracker, s);
	if (old_s) {
		kref_put(&old_s->refcount, __latency_tracker_event_destroy);
	}
#if !defined(LLFREELIST) && !defined(URCUHT)
	spin_unlock_irqrestore(&tracker->lock, flags);
#endif
	if (s->resize_flag &&
			(tracker->free_list_nelems < tracker->max_resize))
		tracker->need_to_resize = 1;

	ret = LATENCY_TRACKER_OK;

	goto end;

end_unlock:
#if !defined(LLFREELIST) && !defined(URCUHT)
	spin_unlock_irqrestore(&tracker->lock, flags);
#endif

end:
	return ret;
}
EXPORT_SYMBOL_GPL(_latency_tracker_event_in);

enum latency_tracker_event_in_ret latency_tracker_event_in(
		struct latency_tracker *tracker,
		void *key, size_t key_len,
		unsigned int unique, void *priv)
{
	enum latency_tracker_event_in_ret ret;

	rcu_read_lock_sched_notrace();
	ret = _latency_tracker_event_in(tracker, key, key_len, unique, priv);
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

struct latency_tracker_event *latency_tracker_get_event(
		struct latency_tracker *tracker, void *key,
		unsigned int key_len)
{
	struct latency_tracker_event *s;
	struct latency_tracker_key tkey;

	tkey.key_len = key_len;
	memcpy(tkey.key, key, key_len);

	s = wrapper_ht_get_event(tracker, &tkey);

	return s;
}
EXPORT_SYMBOL_GPL(latency_tracker_get_event);

void latency_tracker_put_event(struct latency_tracker_event *event)
{
	if (!event)
		return;
	rcu_read_lock_sched_notrace();
#if !defined(LLFREELIST)
	kref_put(&event->refcount, latency_tracker_event_destroy);
#else
	kref_put(&event->refcount, __latency_tracker_event_destroy);
#endif
	rcu_read_unlock_sched_notrace();
}
EXPORT_SYMBOL_GPL(latency_tracker_put_event);

void *latency_tracker_event_get_priv(
		struct latency_tracker_event *event)
{
	return event->priv;
}
EXPORT_SYMBOL_GPL(latency_tracker_event_get_priv);

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

	tracker = latency_tracker_create();
	if (!tracker)
		goto error;
	latency_tracker_set_max_events(tracker, 300);
	latency_tracker_set_timer_period(tracker, 100*1000*1000);

	for (i = 0; i < 10; i++) {
	printk("insert k1\n");
	ret = latency_tracker_event_in(tracker, k1, strlen(k1) + 1, 0, NULL);
	if (ret)
		printk("failed\n");
	udelay(10000);
	}

	printk("insert k2\n");
	rcu_read_lock_sched_notrace();
	ret = _latency_tracker_event_in(tracker, k2, strlen(k2) + 1, 0, NULL);
	rcu_read_unlock_sched_notrace();
	if (ret)
		printk("failed\n");

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
