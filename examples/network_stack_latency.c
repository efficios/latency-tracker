/*
 * net_latency_tp.c
 *
 * Example of usage of latency_tracker with kernel tracepoints.
 *
 * In this example, we call the callback function net_cb when the delay
 * between a net wakeup and its completion (net_switch) takes more than
 * DEFAULT_USEC_NET_LATENCY_THRESH microseconds. Moreover, if the task is
 * still not netuled after DEFAULT_USEC_NET_LATENCY_TIMEOUT microseconds,
 * the callback is called with timeout = 1.
 *
 * The 2 parameters can be controlled at run-time by writing the value in
 * micro-seconds in:
 * /sys/module/net_latency_tp/parameters/usec_threshold and
 * /sys/module/net_latency_tp/parameters/usec_timeout
 *
 * The garbage collector is enabled by default (every 1s, cleanup events older
 * than 5ms), the values can be controlled when inserting the module.
 *
 * It is possible to use nanoseconds, but you have to write manually the value
 * in this source code.
 *
 * Copyright (C) 2014 Julien Desfossez <jdesfossez@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; only version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>

#include "network_stack_latency.h"
#include "../latency_tracker.h"
#include "../wrapper/kallsyms.h"
#include "../wrapper/tracepoint.h"

#include <trace/events/latency_tracker.h>

/*
 * Threshold to execute the callback (microseconds).
 */
#define DEFAULT_USEC_NET_LATENCY_THRESH 5 * 1000
/*
 * Timeout to execute the callback (microseconds).
 */
#define DEFAULT_USEC_NET_LATENCY_TIMEOUT 100 * 1000

/* By default, every 1s, garbage collect every event older than 5ms */
#define DEFAULT_USEC_NET_LATENCY_GC_PERIOD 1000000
#define DEFAULT_USEC_NET_LATENCY_GC_THRESH 5000

static unsigned long usec_gc_period = DEFAULT_USEC_NET_LATENCY_GC_PERIOD;
module_param(usec_gc_period, ulong, 0444);
MODULE_PARM_DESC(usec_gc_period, "Garbage collector period in microseconds");

static unsigned long usec_gc_threshold = DEFAULT_USEC_NET_LATENCY_GC_THRESH;
module_param(usec_gc_threshold, ulong, 0444);
MODULE_PARM_DESC(usec_gc_threshold, "Garbage collector threshold in microseconds");

enum net_exit_reason {
	NET_EXIT_COPY_IOVEC = 0,
	NET_EXIT_CONSUME = 1,
	NET_EXIT_FREE = 2,
	NET_EXIT_KPROBE_FREE = 3,
};

/*
 * microseconds because we can't guarantee the passing of 64-bit
 * arguments to insmod on all architectures.
 */
static unsigned long usec_threshold = DEFAULT_USEC_NET_LATENCY_THRESH;
module_param(usec_threshold, ulong, 0644);
MODULE_PARM_DESC(usec_threshold, "Threshold in microseconds");

static unsigned long usec_timeout = DEFAULT_USEC_NET_LATENCY_TIMEOUT;
module_param(usec_timeout, ulong, 0644);
MODULE_PARM_DESC(usec_timeout, "Timeout in microseconds");

struct netkey {
	struct sk_buff *skb;
} __attribute__((__packed__));
#undef MAX_KEY_SIZE
#define MAX_KEY_SIZE sizeof(struct netkey)

static struct latency_tracker *tracker;

static int cnt = 0;

static
void net_cb(struct latency_tracker_event_ctx *ctx)
{
	uint64_t end_ts = latency_tracker_event_ctx_get_end_ts(ctx);
	uint64_t start_ts = latency_tracker_event_ctx_get_start_ts(ctx);
	enum latency_tracker_cb_flag cb_flag = latency_tracker_event_ctx_get_cb_flag(ctx);
	unsigned int cb_out_id = latency_tracker_event_ctx_get_cb_out_id(ctx);
	struct net_device *dev = latency_tracker_event_ctx_get_priv(ctx);

	/*
	 * Don't log garbage collector and unique cleanups.
	 */
	if (cb_flag == LATENCY_TRACKER_CB_GC ||
			cb_flag == LATENCY_TRACKER_CB_UNIQUE)
		return;

	cnt++;

	if (dev)
		trace_latency_tracker_net(dev, end_ts - start_ts,
			cb_flag, cb_out_id);
}

static
void probe_netif_receive_skb(void *ignore, struct sk_buff *skb)
{
	struct netkey key;
	enum latency_tracker_event_in_ret ret;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	if (!skb)
		return;

	key.skb = skb;


	ret = latency_tracker_event_in(tracker, &key, sizeof(key),
		1, skb->dev);
	if (ret == LATENCY_TRACKER_FULL) {
		printk("latency_tracker net: no more free events, consider "
				"increasing the max_events parameter\n");
	} else if (ret) {
		printk("latency_tracker net: error adding event\n");
	}
}

static
void probe_skb_copy_datagram_iovec(void *ignore, struct sk_buff *skb, int len)
{
	struct netkey key;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	if (!skb)
		return;

	key.skb = skb;

	latency_tracker_event_out(tracker, NULL, &key, sizeof(key),
			NET_EXIT_COPY_IOVEC, 0);
}

static
void probe_consume_skb(void *ignore, struct sk_buff *skb)
{
	struct netkey key;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	if (!skb)
		return;

	key.skb = skb;

	latency_tracker_event_out(tracker, NULL, &key, sizeof(key),
			NET_EXIT_CONSUME, 0);
}

static
void probe_kfree_skb(void *ignore, struct sk_buff *skb, void *location)
{
	struct netkey key;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	if (!skb)
		return;

	key.skb = skb;

	latency_tracker_event_out(tracker, NULL, &key, sizeof(key), NET_EXIT_FREE,
			0);
}

static
int handle_kfree_skbmem(struct kprobe *p, struct pt_regs *regs)
{
#ifdef CONFIG_X86
	void *skb;
	struct netkey key;

#ifdef __i386__
	skb = (void *) regs->ax;
#else /* __i386__ */
	skb = (void *) regs->di;
#endif /* __i386__ */

	key.skb = skb;
	latency_tracker_event_out(tracker, NULL, &key, sizeof(key),
			NET_EXIT_KPROBE_FREE, 0);

#endif /* CONFIG_X86 */
	return 0;
}

static struct kprobe kp = {
	.pre_handler = handle_kfree_skbmem,
	.post_handler = NULL,
	.fault_handler = NULL,
	.addr = NULL,
};

static
int __init net_latency_tp_init(void)
{
	int ret;
	void (*kfree_skbmem_sym)(struct sk_buff *skb);

	tracker = latency_tracker_create("net");
	if (!tracker)
		goto error;
	latency_tracker_set_startup_events(tracker, 100);
	latency_tracker_set_timer_period(tracker, usec_gc_period * 1000);
	latency_tracker_set_threshold(tracker, usec_threshold * 1000);
	latency_tracker_set_timeout(tracker, usec_timeout * 1000);
	latency_tracker_set_callback(tracker, net_cb);
	latency_tracker_set_key_size(tracker, MAX_KEY_SIZE);
	ret = latency_tracker_enable(tracker);
	if (ret)
		goto error;

	ret = lttng_wrapper_tracepoint_probe_register("netif_receive_skb",
			probe_netif_receive_skb, NULL);
	WARN_ON(ret);

	ret = lttng_wrapper_tracepoint_probe_register("skb_copy_datagram_iovec",
			probe_skb_copy_datagram_iovec, NULL);
	WARN_ON(ret);

	ret = lttng_wrapper_tracepoint_probe_register("consume_skb",
			probe_consume_skb, NULL);
	WARN_ON(ret);

	ret = lttng_wrapper_tracepoint_probe_register("kfree_skb",
			probe_kfree_skb, NULL);
	WARN_ON(ret);

	kfree_skbmem_sym =
		(void *) kallsyms_lookup_funcptr("kfree_skbmem");
	if (!kfree_skbmem_sym) {
		printk("Failed to hook a kprobe on kfree_skbmem");
		ret = 0;
		goto end;
	}
	kp.addr = (kprobe_opcode_t *) kfree_skbmem_sym;
	register_kprobe(&kp);

	ret = 0;
	goto end;

error:
	ret = -1;
end:
	return ret;
}
module_init(net_latency_tp_init);

static
void __exit net_latency_tp_exit(void)
{
	lttng_wrapper_tracepoint_probe_unregister("netif_receive_skb",
			probe_netif_receive_skb, NULL);
	lttng_wrapper_tracepoint_probe_unregister("skb_copy_datagram_iovec",
			probe_skb_copy_datagram_iovec, NULL);
	lttng_wrapper_tracepoint_probe_unregister("consume_skb",
			probe_consume_skb, NULL);
	lttng_wrapper_tracepoint_probe_unregister("kfree_skb",
			probe_kfree_skb, NULL);
	tracepoint_synchronize_unregister();
	unregister_kprobe(&kp);
	latency_tracker_destroy(tracker);
	printk("Total net alerts : %d\n", cnt);
}
module_exit(net_latency_tp_exit);

MODULE_AUTHOR("Julien Desfossez <jdesfossez@efficios.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
