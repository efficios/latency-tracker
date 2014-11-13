#include <linux/module.h>
#include <linux/preempt_mask.h>
#include <linux/ktime.h>
#include <linux/hrtimer.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
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
	int (*cb)(struct latency_state *data);
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
	kfree(s);
}

struct latency_tracker *latency_tracker_create(
		int (*match_fct) (const void *key1, const void *key2,
			size_t length),
		u32 (*hash_fct) (const void *key, u32 length, u32 initval))

{
	struct latency_tracker *tracker;

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

	goto end;

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
}

int latency_tracker_event_in(struct latency_tracker *tracker,
		void *key, size_t key_len, unsigned int thresh,
		int (*cb)(struct latency_state *data),
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
	if (!s->key) {
		printk("failed memcpy\n");
		goto error;
	}
	s->start_ts = trace_clock_monotonic_wrapper();
	s->thresh = thresh;
	s->timeout = timeout;
	s->cb = cb;
	s->priv = priv;

	/*
	if (timeout > 0) {
		init_timer(&s->timer);
		s->timer.function = cb;
		s->timer.expires = jiffies +
			usecs_to_jiffies(timeout);
		s->timer.data = s;
		add_timer(&s->timer);

		del_timer_sync(&s->timer);
	}
	*/

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
				s->cb(s);
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

int test_cb(struct latency_state *data)
{
	printk("cb called for key %s with %p\n", (char *) data->key, data->priv);
	return 0;
}

static
int __init latency_tracker_init(void)
{
	char *k1 = "blablabla1";
	char *k2 = "bliblibli1";
	struct latency_tracker *tracker;

	tracker = latency_tracker_create(NULL, NULL);

	printk("insert k1\n");
	latency_tracker_event_in(tracker, k1, strlen(k1) + 1, 6000, test_cb, 0, NULL);
	printk("insert k2\n");
	latency_tracker_event_in(tracker, k2, strlen(k2) + 1, 4000, test_cb, 0, NULL);

	printk("lookup k1\n");
	latency_tracker_event_out(tracker, k1, strlen(k1) + 1);
	printk("lookup k2\n");
	latency_tracker_event_out(tracker, k2, strlen(k2) + 1);
	printk("lookup k1\n");
	latency_tracker_event_out(tracker, k1, strlen(k1) + 1);


	latency_tracker_destroy(tracker);
	printk("done\n");

	return 0;
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
