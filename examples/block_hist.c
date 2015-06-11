/*
 * block_hist.c
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
#include "block_hist.h"
#include "../latency_tracker.h"
#include "../wrapper/tracepoint.h"
#include "../wrapper/trace-clock.h"

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

#define LATENCY_BUCKETS 20
#define LATENCY_AGGREGATE 100

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

struct iohist {
	uint64_t min;
	uint64_t max;
	uint64_t steps; /* (max - min)/LATENCY_BUCKETS */
	uint64_t rvalues[LATENCY_BUCKETS];
	uint64_t wvalues[LATENCY_BUCKETS];
	uint64_t raw_values[LATENCY_AGGREGATE];
	int nb_values;
        spinlock_t lock;
} current_hist;

struct block_hist_tracker {
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

static struct proc_dir_entry *block_hist_tracker_proc_dentry;
static const struct file_operations block_hist_tracker_fops;

static
void blk_cb(unsigned long ptr)
{
#if 0
	struct latency_tracker_event *data =
		(struct latency_tracker_event *) ptr;
	struct blkkey *key = (struct blkkey *) data->tkey.key;
	struct block_hist_tracker *block_hist_priv =
		(struct block_hist_tracker *) data->priv;

	/*
	 * Don't log garbage collector and unique cleanups.
	 */
	if (data->cb_flag == LATENCY_TRACKER_CB_GC ||
			data->cb_flag == LATENCY_TRACKER_CB_UNIQUE)
		goto end;

	/*
	 * Rate limiter.
	 */
	if ((data->end_ts - block_hist_priv->last_alert_ts) <
			block_hist_priv->ns_rate_limit)
		goto end_ts;

	printk("BLOCK\n");
	trace_block_hist_latency(key->dev, key->sector,
			data->end_ts - data->start_ts);
	cnt++;

	if (block_hist_priv->readers > 0) {
		block_hist_priv->reason = BLOCK_TRACKER_WAKE_DATA;
		wake_up_interruptible(&block_hist_priv->read_wait);
		block_hist_priv->got_alert = true;
	}

end_ts:
	block_hist_priv->last_alert_ts = data->end_ts;
end:
	return;
#endif
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
	u64 thresh, timeout;
	enum latency_tracker_event_in_ret ret;

	rq_cnt++;
	if (rq->cmd_type == REQ_TYPE_BLOCK_PC)
		return;

	if (blk_rq_sectors(rq) == 0)
		return;

	rq_to_key(&key, rq);
	thresh = usec_threshold * 1000;
	timeout = usec_timeout * 1000;

	ret = latency_tracker_event_in(tracker, &key, sizeof(key),
		thresh, blk_cb, timeout, 0,
		latency_tracker_get_priv(tracker));
	if (ret == LATENCY_TRACKER_FULL) {
		printk("latency_tracker block: no more free events, consider "
				"increasing the max_events parameter\n");
	} else if (ret) {
		printk("latency_tracker block: error adding event\n");
	}
}

static
void update_step(void)
{
	current_hist.steps = (current_hist.max - current_hist.min) / LATENCY_BUCKETS;
}

static
int get_bucket(uint64_t v)
{
	/* TODO : binary search */
	int i;

	for(i = 0; i < LATENCY_BUCKETS; i++) {
		if (i * current_hist.steps > v)
			return i - 1;
	}
	return i - 1;
}

static
void output_hist(void)
{
	int i;

	printk("Latency histogram [%llu - %llu] usec:\n", current_hist.min / 1000,
			current_hist.max / 1000);
	for(i = 0; i < LATENCY_BUCKETS; i++) {
		printk("\t[%llu\t%llu]\t",
				((i * current_hist.steps) + current_hist.min) / 1000,
				(((i + 1) * current_hist.steps) + current_hist.min - 1) / 1000);
		printk("%llu read\t%llu write\n", current_hist.rvalues[i],
				current_hist.wvalues[i]);
		current_hist.rvalues[i] = 0;
		current_hist.wvalues[i] = 0;
	}
	printk("\n");
}

static
void update_hist(struct latency_tracker_event *s, struct request *rq)
{
	unsigned long flags;
	u64 now, delta;
	int bucket, i;

	now = trace_clock_read64();
	delta = now - s->start_ts;

	spin_lock_irqsave(&current_hist.lock, flags);
	if (delta < current_hist.min) {
		current_hist.min = delta;
		update_step();
	}
	if (delta > current_hist.max) {
		current_hist.max = delta;
		update_step();
	}
	bucket = get_bucket(delta);
	if (rq->cmd_flags % 2 == 0)
		current_hist.rvalues[bucket]++;
	else
		current_hist.wvalues[bucket]++;
	current_hist.raw_values[current_hist.nb_values] = delta;

	current_hist.nb_values++;
	if (current_hist.nb_values >= LATENCY_AGGREGATE) {
		output_hist();
//		for(i = 0; i < current_hist.nb_values; i++) {
//			bucket = get_bucket(current_hist.raw_values[i]);
//			current_hist.rvalues[bucket]++;
//		}
//		printk("real values:\n");
//		output_hist();
//		printk("real values end\n");
		current_hist.nb_values = 0;
	}
	spin_unlock_irqrestore(&current_hist.lock, flags);
}

static
void probe_block_rq_complete(void *ignore, struct request_queue *q,
		struct request *rq, unsigned int nr_bytes)
{
	struct blkkey key;
	struct latency_tracker_event *s;

	if (rq->cmd_type == REQ_TYPE_BLOCK_PC)
		return;

	rq_to_key(&key, rq);

	s = latency_tracker_get_event(tracker, &key, sizeof(key));
	if (!s)
		goto end;
	update_hist(s, rq);
	latency_tracker_put_event(s);

end:
	latency_tracker_event_out(tracker, &key, sizeof(key), 0);
	return;
}

#if 0
static
unsigned int tracker_proc_poll(struct file *filp,
		poll_table *wait)
{
	struct block_hist_tracker *block_hist_priv = filp->private_data;
	unsigned int mask = 0;

	if (filp->f_mode & FMODE_READ) {
		poll_wait(filp, &block_hist_priv->read_wait, wait);
		if (block_hist_priv->reason == BLOCK_TRACKER_WAKE_DATA)
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
	struct block_hist_tracker *block_hist_priv = filp->private_data;

	wait_event_interruptible(block_hist_priv->read_wait,
			block_hist_priv->got_alert);
	block_hist_priv->reason = BLOCK_TRACKER_WAIT;
	block_hist_priv->got_alert = false;

	return 0;
}

static
int tracker_proc_open(struct inode *inode, struct file *filp)
{
	struct block_hist_tracker *block_hist_priv = PDE_DATA(inode);
	int ret;

	init_waitqueue_head(&block_hist_priv->read_wait);
	block_hist_priv->got_alert = false;
	block_hist_priv->readers++;
	filp->private_data = block_hist_priv;
	ret = try_module_get(THIS_MODULE);
	if (!ret)
		return -1;

	return 0;
}

static
int tracker_proc_release(struct inode *inode, struct file *filp)
{
	struct block_hist_tracker *block_hist_priv = filp->private_data;

	block_hist_priv->readers--;
	module_put(THIS_MODULE);
	return 0;
}


static const
struct file_operations block_hist_tracker_fops = {
	.owner = THIS_MODULE,
	.open = tracker_proc_open,
	.read = tracker_proc_read,
	.release = tracker_proc_release,
	.poll = tracker_proc_poll,
};
#endif

static
int __init block_hist_latency_tp_init(void)
{
	int ret;
	struct block_hist_tracker *block_hist_priv;

	block_hist_priv = kzalloc(sizeof(struct block_hist_tracker), GFP_KERNEL);
	if (!block_hist_priv) {
		ret = -ENOMEM;
		goto end;
	}
	block_hist_priv->reason = BLOCK_TRACKER_WAIT;
	/* limit to 1 evt/sec */
	block_hist_priv->ns_rate_limit = 1000000000;

	tracker = latency_tracker_create(NULL, NULL, 100, 0,
			usec_gc_period * 1000,
			usec_gc_period * 1000,
			block_hist_priv);
	if (!tracker)
		goto error;

	spin_lock_init(&current_hist.lock);
	current_hist.min = -1ULL;
	current_hist.max = 0;

	ret = lttng_wrapper_tracepoint_probe_register("block_rq_issue",
			probe_block_rq_issue, NULL);
	WARN_ON(ret);

	ret = lttng_wrapper_tracepoint_probe_register("block_rq_complete",
			probe_block_rq_complete, NULL);
	WARN_ON(ret);

#if 0
	block_hist_tracker_proc_dentry = proc_create_data("block_hist_tracker",
			S_IRUSR, NULL, &block_hist_tracker_fops, block_hist_priv);

	if (!block_hist_tracker_proc_dentry) {
		printk(KERN_ERR "Error creating tracker control file\n");
		ret = -ENOMEM;
		goto end;
	}
#endif

	ret = 0;
	goto end;

error:
	ret = -1;
end:
	return ret;
}
module_init(block_hist_latency_tp_init);

static
void __exit block_hist_latency_tp_exit(void)
{
	struct block_hist_tracker *block_hist_priv;

	lttng_wrapper_tracepoint_probe_unregister("block_rq_issue",
			probe_block_rq_issue, NULL);
	lttng_wrapper_tracepoint_probe_unregister("block_rq_complete",
			probe_block_rq_complete, NULL);
	tracepoint_synchronize_unregister();

	block_hist_priv = latency_tracker_get_priv(tracker);
	kfree(block_hist_priv);

	latency_tracker_destroy(tracker);

	printk("Total block alerts : %d\n", cnt);
	printk("Total block requests : %d\n", rq_cnt);
	if (block_hist_tracker_proc_dentry)
		remove_proc_entry("block_hist_tracker", NULL);
}
module_exit(block_hist_latency_tp_exit);

MODULE_AUTHOR("Julien Desfossez <jdesfossez@efficios.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");