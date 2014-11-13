#include <linux/module.h>
#include <linux/preempt_mask.h>
#include <linux/ktime.h>
#include <linux/hrtimer.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/module.h>
#include "latency.h"

struct latency_state {
	struct timer_list timer;
	struct hlist_node hlist;
	u64 start_ts;
	u64 end_ts;
	unsigned int timeout;
	unsigned int thresh;
	u32 hkey;
	void *key;
	size_t key_len;
	void (*cb)(unsigned long ptr, unsigned int timeout);
	void *priv;
};

#define DEFAULT_LATENCY_HASH_BITS 3
#define DEFAULT_LATENCY_TABLE_SIZE (1 << DEFAULT_LATENCY_HASH_BITS)

struct latency_tracker {
	struct hlist_head ht[DEFAULT_LATENCY_TABLE_SIZE];
	int (*match_fct) (const void *key1, const void *key2, size_t length);
	u32 (*hash_fct) (const void *key, u32 length, u32 initval);
};

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
void latency_tracker_event_destroy(struct latency_state *s)
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
		printk("alloc tracker failed\n");
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

void latency_tracker_destroy(struct latency_tracker *tracker)
{
	int bkt;
	struct latency_state *s;

	hash_for_each(tracker->ht, bkt, s, hlist)
		latency_tracker_event_destroy(s);
	kfree(tracker);
	module_put(THIS_MODULE);
}

static
void latency_tracker_timeout_cb(unsigned long ptr)
{
	struct latency_state *data = (struct latency_state *) ptr;

	printk("timeout handler\n");
	del_timer(&data->timer);
	data->cb(ptr, 1);
}

int latency_tracker_event_in(struct latency_tracker *tracker,
		void *key, size_t key_len, unsigned int thresh,
		void (*cb)(unsigned long ptr, unsigned int timeout),
		unsigned int timeout, void *priv)
{
	struct latency_state *s;
	int ret;

	if (!tracker) {
		goto error;
	}

	s = kzalloc(sizeof(struct latency_state), GFP_KERNEL);
	if (!s) {
		printk("Failed to alloc latency_tracker_event_in\n");
		goto error;
	}

	s->hkey = tracker->hash_fct(key, key_len, 0);
	s->key = kmalloc(key_len, GFP_KERNEL);
	if (!s->key) {
		printk("alloc failed\n");
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
			usecs_to_jiffies(timeout);
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
	struct latency_state *s;
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
		/*
		printk("now : %lu, start : %lu, diff : %lu\n",
				now, s->start_ts, now - s->start_ts);
				*/
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

void test_cb(unsigned long ptr, unsigned int timeout)
{
	struct latency_state *data = (struct latency_state *) ptr;
	printk("cb called for key %s with %p, timeout = %d\n", (char *) data->key,
			data->priv, timeout);
}

static
int __init latency_tracker_init(void)
{
	char *k1 = "blablabla1";
	char *k2 = "bliblibli1";
	int ret;
	struct latency_tracker *tracker;

	tracker = latency_tracker_create(NULL, NULL);
	if (!tracker)
		goto error;

	printk("insert k1\n");
	latency_tracker_event_in(tracker, k1, strlen(k1) + 1, 600, test_cb, 0, NULL);
	printk("insert k2\n");
	latency_tracker_event_in(tracker, k2, strlen(k2) + 1, 400, test_cb, 2000000, NULL);

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
void __exit latency_tracker_exit(void)
{
	printk("exit\n");
}

module_init(latency_tracker_init);
module_exit(latency_tracker_exit);
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL");
