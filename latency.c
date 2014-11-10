#include <linux/module.h>
#include <linux/preempt_mask.h>
#include <linux/ktime.h>
#include <linux/hrtimer.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include "include/trace/events/latency.h"
#include "latency.h"

#define CREATE_TRACE_POINTS

struct latency_state {
	pid_t pid;
	u64 start_ts;
	unsigned int timeout;
	unsigned int thresh;
	int (*cb)(char *key, void *priv);
	void *priv;
	u32 key;
	struct hlist_node hlist;
};

DEFINE_HASHTABLE(latency_ht, 3);

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

int latency_event_in(char *key, unsigned int thresh,
		int (*cb)(char *key, void *priv),
		unsigned int timeout, void *priv)
{
	struct latency_state *s;
	int ret;

	s = kmalloc(sizeof(struct latency_state), GFP_KERNEL);
	if (!s) {
		printk("Failed to alloc latency_event_in\n");
		goto error;
	}
	memset(s, 0, sizeof(struct latency_state));

	s->key = jhash(key, strlen(key), 0);
	s->pid = current->pid;
	s->start_ts = trace_clock_monotonic_wrapper();
	s->thresh = thresh;
	s->timeout = timeout;
	s->cb = cb;
	s->priv = priv;

	hash_add(latency_ht, &s->hlist, s->key);

	ret = 0;
	goto end;

error:
	ret = -1;
end:
	return ret;
}
EXPORT_SYMBOL_GPL(latency_event_in);

int latency_event_out(char *key)
{
	struct latency_state *s;
	int ret;
	int found = 0;
	u32 k;
	u64 now;

	k = jhash(key, strlen(key), 0);

	hash_for_each_possible(latency_ht, s, hlist, k){
		now = trace_clock_monotonic_wrapper();
		/*
		printk("now : %lu, start : %lu, diff : %lu\n",
				now, s->start_ts, now - s->start_ts);
				*/
		if ((now - s->start_ts) > s->thresh) {
			if (s->cb)
				s->cb(key, s->priv);
		}
		hash_del(&s->hlist);
		kfree(s);
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
EXPORT_SYMBOL_GPL(latency_event_out);

int test_cb(char *key, void *priv)
{
	printk("cb called for key %s with %p\n", key, priv);
	return 0;
}

static int __init trace_init(void)
{
	char *k1 = "blablabla1";
	char *k2 = "bliblibli1";

	printk("insert k1\n");
	latency_event_in(k1, 6000, test_cb, 0, NULL);
	printk("insert k2\n");
	latency_event_in(k2, 4000, test_cb, 0, NULL);


	printk("lookup k1\n");
	latency_event_out(k1);
	printk("lookup k2\n");
	latency_event_out(k2);
	printk("lookup k1\n");
	latency_event_out(k1);


	printk("done\n");
//	state.entry_ts = kmalloc(65535 * sizeof(unsigned long), GFP_KERNEL);
//	memset(state.entry_ts, 0, 65535);

//	trace_subsys_eventname(0, current);
	return 0;
}

static void __exit trace_exit(void)
{
	printk("exit\n");
}

module_init(trace_init);
module_exit(trace_exit);
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL");
