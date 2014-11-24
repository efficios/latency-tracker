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
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include "network_stack_latency.h"
#include "../latency_tracker.h"

#define CREATE_TRACE_POINTS
#include <trace/events/latency_tracker.h>

/*
 * Threshold to execute the callback (microseconds).
 */
#define DEFAULT_USEC_NET_LATENCY_THRESH 5 * 1000
/*
 * Timeout to execute the callback (microseconds).
 */
#define DEFAULT_USEC_NET_LATENCY_TIMEOUT 100 * 1000

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

static struct latency_tracker *tracker;

static int cnt = 0;

static
void net_cb(unsigned long ptr, unsigned int timeout)
{
	struct latency_tracker_event *data =
		(struct latency_tracker_event *) ptr;
	struct net_device *dev = data->priv;

	cnt++;

	if (dev)
		trace_net_latency(dev, data->end_ts - data->start_ts,
			0, timeout);
}

static
void probe_netif_receive_skb(void *ignore, struct sk_buff *skb)
{
	struct netkey key;
	u64 thresh, timeout;

	if (!skb)
		return;

	key.skb = skb;

	thresh = usec_threshold * 1000;
	timeout = usec_timeout * 1000;

	latency_tracker_event_in(tracker, &key, sizeof(key),
		thresh, net_cb, timeout,
		skb->dev);
}

static
void probe_skb_copy_datagram_iovec(void *ignore, struct sk_buff *skb, int len)
{
	struct netkey key;

	if (!skb)
		return;

	key.skb = skb;

	latency_tracker_event_out(tracker, &key, sizeof(key));
}

static
int __init net_latency_tp_init(void)
{
	int ret;

	tracker = latency_tracker_create(NULL, NULL, 100);
	if (!tracker)
		goto error;

	ret = tracepoint_probe_register("netif_receive_skb",
			probe_netif_receive_skb, NULL);
	WARN_ON(ret);

	ret = tracepoint_probe_register("skb_copy_datagram_iovec",
			probe_skb_copy_datagram_iovec, NULL);
	WARN_ON(ret);

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
	tracepoint_probe_unregister("netif_receive_skb",
			probe_netif_receive_skb, NULL);
	tracepoint_probe_unregister("skb_copy_datagram_iovec",
			probe_skb_copy_datagram_iovec, NULL);
	tracepoint_synchronize_unregister();
	latency_tracker_destroy(tracker);
	printk("Total net alerts : %d\n", cnt);
}
module_exit(net_latency_tp_exit);

MODULE_AUTHOR("Julien Desfossez <jdesfossez@efficios.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
