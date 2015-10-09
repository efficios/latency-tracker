/*
 * block_latency_tp.c
 *
 * Example of usage of latency_tracker with kernel tracepoints.
 * In this example, we call the callback function blk_cb when the delay
 * between a block request (block_rq_issue) and its completion
 * (block_rq_complete) takes more than BLK_LATENCY_THRESH nanoseconds.
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
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/poll.h>
#include "block_latency_tp.h"
#include "../latency_tracker.h"
#include "../wrapper/tracepoint.h"

#include <trace/events/latency_tracker.h>

/*
 * Threshold to execute the callback (microseconds).
 */
#define DEFAULT_USEC_BLK_LATENCY_THRESHOLD 5 * 1000
#define DEFAULT_USEC_BLK_LATENCY_TIMEOUT 0
/*
 * Garbage collector parameters (microseconds).
 */
#define DEFAULT_USEC_BLK_LATENCY_GC_THRESHOLD 0
#define DEFAULT_USEC_BLK_LATENCY_GC_PERIOD 0

/*
 * microseconds because we can't guarantee the passing of 64-bit
 * arguments to insmod on all architectures.
 */
static unsigned long usec_threshold = DEFAULT_USEC_BLK_LATENCY_THRESHOLD;
module_param(usec_threshold, ulong, 0644);
MODULE_PARM_DESC(usec_threshold, "Threshold in microseconds");

static unsigned long usec_timeout = DEFAULT_USEC_BLK_LATENCY_TIMEOUT;
module_param(usec_timeout, ulong, 0644);
MODULE_PARM_DESC(usec_timeout, "Timeout in microseconds");

static unsigned long usec_gc_threshold = DEFAULT_USEC_BLK_LATENCY_GC_THRESHOLD;
module_param(usec_gc_threshold, ulong, 0644);
MODULE_PARM_DESC(usec_gc_threshold, "Garbage collector threshold in microseconds");

static unsigned long usec_gc_period = DEFAULT_USEC_BLK_LATENCY_GC_PERIOD;
module_param(usec_gc_period, ulong, 0644);
MODULE_PARM_DESC(usec_gc_period, "Garbage collector period in microseconds");

struct blkkey {
	dev_t dev;
	sector_t sector;
} __attribute__((__packed__));

enum wake_reason {
	BLOCK_TRACKER_WAKE_DATA = 0,
	BLOCK_TRACKER_WAIT = 1,
	BLOCK_TRACKER_HUP = 2,
};

struct block_tracker {
	u64 last_alert_ts;
	u64 ns_rate_limit;
	wait_queue_head_t read_wait;
	enum wake_reason reason;
	bool got_alert;
	int readers;
};

static struct latency_tracker *tracker;
static int cnt = 0;
static int rq_cnt = 0;

static struct proc_dir_entry *block_tracker_proc_dentry;
static const struct file_operations block_tracker_fops;

static
void blk_cb(struct latency_tracker_event_ctx *ctx)
{
	struct blkkey *key = (struct blkkey *) latency_tracker_event_ctx_get_key(ctx)->key;
	struct block_tracker *block_priv =
		(struct block_tracker *) latency_tracker_event_ctx_get_priv(ctx);
	uint64_t end_ts = latency_tracker_event_ctx_get_end_ts(ctx);
	uint64_t start_ts = latency_tracker_event_ctx_get_start_ts(ctx);
	enum latency_tracker_cb_flag cb_flag = latency_tracker_event_ctx_get_cb_flag(ctx);

	/*
	 * Don't log garbage collector and unique cleanups.
	 */
	if (cb_flag == LATENCY_TRACKER_CB_GC ||
			cb_flag == LATENCY_TRACKER_CB_UNIQUE)
		goto end;

	/*
	 * Rate limiter.
	 */
	if ((end_ts - block_priv->last_alert_ts) <
			block_priv->ns_rate_limit)
		goto rate_limit;

	printk("BLOCK\n");
	trace_latency_tracker_block(key->dev, key->sector,
			end_ts - start_ts);
	cnt++;

	if (block_priv->readers > 0) {
		block_priv->reason = BLOCK_TRACKER_WAKE_DATA;
		wake_up_interruptible(&block_priv->read_wait);
		block_priv->got_alert = true;
	}

rate_limit:
	block_priv->last_alert_ts = end_ts;
end:
	return;
}

static
void rq_to_key(struct blkkey *key, struct request *rq)
{
	if (!key || !rq)
		return;

	key->sector = blk_rq_pos(rq);
	key->dev = rq->rq_disk ? disk_devt(rq->rq_disk) : 0;
}

static
void probe_block_rq_issue(void *ignore, struct request_queue *q,
		struct request *rq)
{
	struct blkkey key;
	enum latency_tracker_event_in_ret ret;

	rq_cnt++;
	if (rq->cmd_type == REQ_TYPE_BLOCK_PC)
		return;

	if (blk_rq_sectors(rq) == 0)
		return;

	rq_to_key(&key, rq);

	ret = latency_tracker_event_in(tracker, &key, sizeof(key),
		0, latency_tracker_get_priv(tracker));
	if (ret == LATENCY_TRACKER_FULL) {
		printk("latency_tracker block: no more free events, consider "
				"increasing the max_events parameter\n");
	} else if (ret) {
		printk("latency_tracker block: error adding event\n");
	}
}

static
void probe_block_rq_complete(void *ignore, struct request_queue *q,
		struct request *rq, unsigned int nr_bytes)
{
	struct blkkey key;

	if (rq->cmd_type == REQ_TYPE_BLOCK_PC)
		return;

	rq_to_key(&key, rq);
	latency_tracker_event_out(tracker, &key, sizeof(key), 0);
}

static
unsigned int tracker_proc_poll(struct file *filp,
		poll_table *wait)
{
	struct block_tracker *block_priv = filp->private_data;
	unsigned int mask = 0;

	if (filp->f_mode & FMODE_READ) {
		poll_wait(filp, &block_priv->read_wait, wait);
		if (block_priv->reason == BLOCK_TRACKER_WAKE_DATA)
			mask |= POLLIN;
		else
			mask |= POLLHUP;
	}

	return mask;
}

static
ssize_t tracker_proc_read(struct file *filp, char __user *buf, size_t n,
		loff_t *offset)
{
	struct block_tracker *block_priv = filp->private_data;

	wait_event_interruptible(block_priv->read_wait,
			block_priv->got_alert);
	block_priv->reason = BLOCK_TRACKER_WAIT;
	block_priv->got_alert = false;

	return 0;
}

static
int tracker_proc_open(struct inode *inode, struct file *filp)
{
	struct block_tracker *block_priv = PDE_DATA(inode);
	int ret;

	init_waitqueue_head(&block_priv->read_wait);
	block_priv->got_alert = false;
	block_priv->readers++;
	filp->private_data = block_priv;
	ret = try_module_get(THIS_MODULE);
	if (!ret)
		return -1;

	return 0;
}

static
int tracker_proc_release(struct inode *inode, struct file *filp)
{
	struct block_tracker *block_priv = filp->private_data;

	block_priv->readers--;
	module_put(THIS_MODULE);
	return 0;
}


static const
struct file_operations block_tracker_fops = {
	.owner = THIS_MODULE,
	.open = tracker_proc_open,
	.read = tracker_proc_read,
	.release = tracker_proc_release,
	.poll = tracker_proc_poll,
};

static
int __init block_latency_tp_init(void)
{
	int ret;
	struct block_tracker *block_priv;

	block_priv = kzalloc(sizeof(struct block_tracker), GFP_KERNEL);
	if (!block_priv) {
		ret = -ENOMEM;
		goto end;
	}
	block_priv->reason = BLOCK_TRACKER_WAIT;
	/* limit to 1 evt/sec */
	block_priv->ns_rate_limit = 1000000000;

	tracker = latency_tracker_create();
	if (!tracker)
		goto error;
	latency_tracker_set_max_events(tracker, 100);
	latency_tracker_set_timer_period(tracker, usec_gc_period * 1000);
	latency_tracker_set_threshold(tracker, usec_threshold * 1000);
	latency_tracker_set_timeout(tracker, usec_timeout * 1000);
	latency_tracker_set_callback(tracker, blk_cb);

	ret = lttng_wrapper_tracepoint_probe_register("block_rq_issue",
			probe_block_rq_issue, NULL);
	WARN_ON(ret);

	ret = lttng_wrapper_tracepoint_probe_register("block_rq_complete",
			probe_block_rq_complete, NULL);
	WARN_ON(ret);

	block_tracker_proc_dentry = proc_create_data("block_tracker",
			S_IRUSR, NULL, &block_tracker_fops, block_priv);

	if (!block_tracker_proc_dentry) {
		printk(KERN_ERR "Error creating tracker control file\n");
		ret = -ENOMEM;
		goto end;
	}


	ret = 0;
	goto end;

error:
	ret = -1;
end:
	return ret;
}
module_init(block_latency_tp_init);

static
void __exit block_latency_tp_exit(void)
{
	struct block_tracker *block_priv;

	lttng_wrapper_tracepoint_probe_unregister("block_rq_issue",
			probe_block_rq_issue, NULL);
	lttng_wrapper_tracepoint_probe_unregister("block_rq_complete",
			probe_block_rq_complete, NULL);
	tracepoint_synchronize_unregister();

	block_priv = latency_tracker_get_priv(tracker);
	kfree(block_priv);

	latency_tracker_destroy(tracker);

	printk("Total block alerts : %d\n", cnt);
	printk("Total block requests : %d\n", rq_cnt);
	if (block_tracker_proc_dentry)
		remove_proc_entry("block_tracker", NULL);
}
module_exit(block_latency_tp_exit);

MODULE_AUTHOR("Julien Desfossez <jdesfossez@efficios.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
