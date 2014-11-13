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
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/module.h>
#include "latency_tracker.h"

#define DEFAULT_LATENCY_HASH_BITS 3
#define DEFAULT_LATENCY_TABLE_SIZE (1 << DEFAULT_LATENCY_HASH_BITS)

struct latency_tracker {
	struct hlist_head ht[DEFAULT_LATENCY_TABLE_SIZE];
	int (*match_fct) (const void *key1, const void *key2, size_t length);
	u32 (*hash_fct) (const void *key, u32 length, u32 initval);
};

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
void latency_tracker_event_destroy(struct latency_tracker_event *s)
{
	hash_del(&s->hlist);
	kfree(s->key);
	if (s->timeout > 0)
		del_timer_sync(&s->timer);
	kfree(s);
}

struct latency_tracker *latency_tracker_create(
		int (*match_fct) (const void *key1, const void *key2,
			size_t length),
		u32 (*hash_fct) (const void *key, u32 length, u32 initval))

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
	hash_init(tracker->ht);
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
	int bkt;
	struct latency_tracker_event *s;

	hash_for_each(tracker->ht, bkt, s, hlist)
		latency_tracker_event_destroy(s);
	kfree(tracker);
	module_put(THIS_MODULE);
}
EXPORT_SYMBOL_GPL(latency_tracker_destroy);

static
void latency_tracker_timeout_cb(unsigned long ptr)
{
	struct latency_tracker_event *data = (struct latency_tracker_event *) ptr;

	del_timer(&data->timer);
	data->timeout = 0;

	/* Run the user-provided callback. */
	data->cb(ptr, 1);
}

int latency_tracker_event_in(struct latency_tracker *tracker,
		void *key, size_t key_len, uint64_t thresh,
		void (*cb)(unsigned long ptr, unsigned int timeout),
		uint64_t timeout, void *priv)
{
	struct latency_tracker_event *s;
	int ret;

	if (!tracker) {
		goto error;
	}

	s = kzalloc(sizeof(struct latency_tracker_event), GFP_KERNEL);
	if (!s) {
		printk("latency_tracker: Failed to alloc latency_tracker_event_in\n");
		goto error;
	}

	s->hkey = tracker->hash_fct(key, key_len, 0);
	s->key = kmalloc(key_len, GFP_KERNEL);
	if (!s->key) {
		printk("latency_tracker: Key alloc failed\n");
		goto error;
	}
	memcpy(s->key, key, key_len);

	s->start_ts = trace_clock_monotonic_wrapper();
	s->thresh = thresh;
	s->timeout = timeout;
	s->cb = cb;
	s->priv = priv;

	if (timeout > 0) {
		init_timer(&s->timer);
		s->timer.function = latency_tracker_timeout_cb;
		s->timer.expires = jiffies +
			nsecs_to_jiffies(timeout);
		s->timer.data = (unsigned long) s;
		add_timer(&s->timer);
	}

	hash_add(tracker->ht, &s->hlist, s->hkey);

	ret = 0;
	goto end;

error:
	ret = -1;
end:
	return ret;
}
EXPORT_SYMBOL_GPL(latency_tracker_event_in);

int latency_tracker_event_out(struct latency_tracker *tracker,
		void *key, unsigned int key_len)
{
	struct latency_tracker_event *s;
	int ret;
	int found = 0;
	u32 k;
	u64 now;

	if (!tracker) {
		goto error;
	}

	k = tracker->hash_fct(key, key_len, 0);

	hash_for_each_possible(tracker->ht, s, hlist, k){
		if (tracker->match_fct(key, s->key, key_len))
			continue;
		now = trace_clock_monotonic_wrapper();
		if ((now - s->start_ts) > s->thresh) {
			s->end_ts = now;
			if (s->cb)
				s->cb((unsigned long) s, 0);
		}
		latency_tracker_event_destroy(s);
		found = 1;
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
EXPORT_SYMBOL_GPL(latency_tracker_event_out);

void example_cb(unsigned long ptr, unsigned int timeout)
{
	struct latency_tracker_event *data = (struct latency_tracker_event *) ptr;
	printk("cb called for key %s with %p, timeout = %d\n", (char *) data->key,
			data->priv, timeout);
}

static
int test_tracker(void)
{
	char *k1 = "blablabla1";
	char *k2 = "bliblibli1";
	int ret;
	struct latency_tracker *tracker;

	tracker = latency_tracker_create(NULL, NULL);
	if (!tracker)
		goto error;

	printk("insert k1\n");
	latency_tracker_event_in(tracker, k1, strlen(k1) + 1, 600, example_cb, 0, NULL);
	printk("insert k2\n");
	latency_tracker_event_in(tracker, k2, strlen(k2) + 1, 400, example_cb, 2000000, NULL);

	printk("lookup k1\n");
	latency_tracker_event_out(tracker, k1, strlen(k1) + 1);
	printk("lookup k2\n");
	latency_tracker_event_out(tracker, k2, strlen(k2) + 1);
	printk("lookup k1\n");
	latency_tracker_event_out(tracker, k1, strlen(k1) + 1);

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

	return ret;
}

static
void __exit latency_tracker_exit(void)
{
}

module_init(latency_tracker_init);
module_exit(latency_tracker_exit);
MODULE_AUTHOR("Julien Desfossez <jdesfossez@efficios.com>");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL");
