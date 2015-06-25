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

/*
 * log2 scale, so:
 * 0-9:   1ns, 2, 4, 8, 16, 32, 64, 128, 256, 512
 * 10-19: 1us, 2, 4...
 * 20-29: 1ms, ... 512ms
 * 30-39: 1s, ... 512s
 * 40: > 512s
 * = 41 intervals
 */
#define LATENCY_BUCKETS 41
#define LATENCY_AGGREGATE 1000

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

struct sched_key_t {
  pid_t pid;
} __attribute__((__packed__));

enum wake_reason {
	BLOCK_TRACKER_WAKE_DATA = 0,
	BLOCK_TRACKER_WAIT = 1,
	BLOCK_TRACKER_HUP = 2,
};

enum io_type {
	IO_SYSCALL_READ = 0,
	IO_SYSCALL_WRITE = 1,
	IO_SYSCALL_RW = 2,
	IO_SYSCALL_SYNC = 3,
	IO_SYSCALL_OPEN = 4,
	IO_SYSCALL_CLOSE = 5,

	IO_BLOCK_READ = 6,
	IO_BLOCK_WRITE = 7,

	/* must always be the last value in this enum */
	IO_TYPE_NR = 8,
};

struct iohist {
	uint64_t min;
	uint64_t max;
	uint64_t ts_begin;
	uint64_t ts_end;
	unsigned int values[IO_TYPE_NR][LATENCY_BUCKETS];
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
		//printk("latency_tracker block: no more free events, consider "
		//		"increasing the max_events parameter\n");
	} else if (ret) {
		printk("latency_tracker block: error adding event\n");
	}
}

static
unsigned int get_bucket(uint64_t v)
{
	if (v > (1ULL << (LATENCY_BUCKETS - 1)))
		return LATENCY_BUCKETS;
	return fls_long(v - 1);
}

static
void output_bucket_value(uint64_t v, struct seq_file *m)
{
	if (v > (1ULL<<29))
		seq_printf(m, "%llus", v >> 30);
	else if (v > (1ULL<<19))
		seq_printf(m, "%llums", v >> 20);
	else if (v > (1ULL<<9))
		seq_printf(m, "%lluus", v >> 10);
	else
		seq_printf(m, "%lluns", v);
}

static
void reset_hist(struct iohist *h)
{
	int i, j;

	for (i = 0; i < IO_TYPE_NR; i++)
		for (j = 0; j < LATENCY_BUCKETS; j++)
			h->values[i][j] = 0;
}


static
void output_hist(struct iohist *h, struct seq_file *m)
{
	int i, j;

//	seq_printf(m, "Latency histogram [%llu - %llu] ns:\n",
//			current_hist.min, current_hist.max);
	seq_printf(m, "Range    \t\ts_read\ts_write\ts_rw\ts_sync\t"
			"s_open\ts_close\tb_read\tb_write\n");
	for(i = 0; i < LATENCY_BUCKETS; i++) {
		seq_printf(m, "[");
		output_bucket_value(1ULL << i, m);
		seq_printf(m, ", ");
		output_bucket_value(1ULL << (i+1), m);
		seq_printf(m, "[\t");
		for (j = 0; j < IO_TYPE_NR; j++)
			seq_printf(m, "\t%u", h->values[j][i]);
		seq_printf(m, "\n");
		/*
		seq_printf(m, "%u read\t%u write\t%u syscalls\n",
				h->values[IO_BLOCK_READ][i],
				h->values[IO_BLOCK_WRITE][i],
				h->values[IO_SYSCALL_READ][i]);
				*/
	}
	seq_printf(m, "\n");
	reset_hist(h);
}

static
void update_hist(struct latency_tracker_event *s, enum io_type t, struct iohist *h)
{
	unsigned long flags;
	u64 now, delta;
	int bucket;

	now = trace_clock_read64();
	delta = now - s->start_ts;

	spin_lock_irqsave(&h->lock, flags);
	if (delta < h->min)
		h->min = delta;
	if (delta > h->max)
		h->max = delta;
	bucket = get_bucket(delta);
	h->values[t][bucket]++;

	h->nb_values++;
	/*
	if (h->nb_values >= LATENCY_AGGREGATE) {
		//output_hist(h);
		h->min = -1ULL;
		h->max = 0;
		h->nb_values = 0;
	}
	*/
	spin_unlock_irqrestore(&h->lock, flags);
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
	if (rq->cmd_flags % 2 == 0)
		update_hist(s, IO_BLOCK_READ, &current_hist);
	else
		update_hist(s, IO_BLOCK_WRITE, &current_hist);
	latency_tracker_put_event(s);

end:
	latency_tracker_event_out(tracker, &key, sizeof(key), 0);
	return;
}

static
int io_syscall(long id)
{
	switch(id) {
		case __NR_read:
		case __NR_pread64:
		case __NR_readv:
		case __NR_preadv:
		case __NR_recvfrom:
		case __NR_recvmsg:
		case __NR_getdents:
		case __NR_getdents64:
		case __NR_statfs:
		case __NR_fstatfs:
			return IO_SYSCALL_READ;

		case __NR_write:
		case __NR_pwrite64:
		case __NR_writev:
		case __NR_pwritev:
		case __NR_sendto:
		case __NR_sendmsg:
		case __NR_mkdir:
		case __NR_mkdirat:
		case __NR_rmdir:
		case __NR_creat:
		case __NR_mknod:
		case __NR_mknodat:
		case __NR_vmsplice:
		case __NR_sendmmsg:
			return IO_SYSCALL_WRITE;

		case __NR_sendfile:
		case __NR_splice:
			return IO_SYSCALL_RW;

		case __NR_fsync:
		case __NR_fdatasync:
		case __NR_sync:
		case __NR_sync_file_range:
		case __NR_syncfs:
			return IO_SYSCALL_SYNC;

		case __NR_open:
		case __NR_pipe:
		case __NR_pipe2:
		case __NR_dup2:
		case __NR_dup3:
		case __NR_socket:
		case __NR_connect:
//		case __NR_accept:
//		case __NR_accept4:
		case __NR_execve:
		case __NR_chdir:
		case __NR_fchdir:
		case __NR_mount:
		case __NR_umount2:
		case __NR_swapon:
		case __NR_openat:
			return IO_SYSCALL_OPEN;

		case __NR_close:
		case __NR_swapoff:
		case __NR_shutdown:
			return IO_SYSCALL_CLOSE;

		default:
			break;
	}
	return -1;
}

static
void probe_syscall_enter(void *ignore, struct pt_regs *regs,
		long id)
{
	struct task_struct* task = current;
	struct sched_key_t sched_key;
	u64 thresh, timeout;

	if (io_syscall(id) < 0)
		return;

	sched_key.pid = task->pid;
	thresh = usec_threshold * 1000;
	timeout = usec_timeout * 1000;

	latency_tracker_event_in(tracker, &sched_key, sizeof(sched_key),
			thresh, blk_cb, timeout, 0, (void *) id);
}

static
void probe_syscall_exit(void *__data, struct pt_regs *regs, long ret)
{
	struct sched_key_t key;
	struct latency_tracker_event *s;

	key.pid = current->pid;
	s = latency_tracker_get_event(tracker, &key, sizeof(key));
	if (!s)
		goto end;
	update_hist(s, io_syscall((unsigned long) s->priv), &current_hist);
	latency_tracker_put_event(s);

end:
	latency_tracker_event_out(tracker, &key, sizeof(key), 0);
}

static int block_hist_show(struct seq_file *m, void *v)
{
	output_hist(&current_hist, m);
	return 0;
}

static
int tracker_proc_open(struct inode *inode, struct file *filp)
{
	struct block_hist_tracker *block_hist_priv = PDE_DATA(inode);

	filp->private_data = block_hist_priv;

	return single_open(filp, block_hist_show, NULL);
}

static const
struct file_operations block_hist_tracker_fops = {
	.owner = THIS_MODULE,
	.open = tracker_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

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

	ret = lttng_wrapper_tracepoint_probe_register(
			"sys_enter", probe_syscall_enter, NULL);
	WARN_ON(ret);
	ret = lttng_wrapper_tracepoint_probe_register(
			"sys_exit", probe_syscall_exit, NULL);
	WARN_ON(ret);

	block_hist_tracker_proc_dentry = proc_create("block_hist_tracker",
			0, NULL, &block_hist_tracker_fops);
	/*
	block_hist_tracker_proc_dentry = proc_create_data("block_hist_tracker",
			S_IRUSR, NULL, &block_hist_tracker_fops, block_hist_priv);
			*/

	if (!block_hist_tracker_proc_dentry) {
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
module_init(block_hist_latency_tp_init);

static
void __exit block_hist_latency_tp_exit(void)
{
	struct block_hist_tracker *block_hist_priv;

	lttng_wrapper_tracepoint_probe_unregister("block_rq_issue",
			probe_block_rq_issue, NULL);
	lttng_wrapper_tracepoint_probe_unregister("block_rq_complete",
			probe_block_rq_complete, NULL);
	lttng_wrapper_tracepoint_probe_unregister(
			"sys_enter", probe_syscall_enter, NULL);
	lttng_wrapper_tracepoint_probe_unregister(
			"sys_exit", probe_syscall_exit, NULL);
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
