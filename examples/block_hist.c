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
#include <linux/cpu.h>
#include <linux/vmalloc.h>
#include "block_hist.h"
#include "block_hist_kprobes.h"
#include "../latency_tracker.h"
#include "../wrapper/tracepoint.h"
#include "../wrapper/trace-clock.h"
#include "../wrapper/percpu-defs.h"
#include "../wrapper/jiffies.h"
#include "../wrapper/vmalloc.h"

#include <trace/events/latency_tracker.h>

/*
 * microseconds because we can't guarantee the passing of 64-bit
 * arguments to insmod on all architectures.
 */
unsigned long usec_threshold = DEFAULT_USEC_BLK_LATENCY_THRESHOLD;
unsigned long usec_timeout = DEFAULT_USEC_BLK_LATENCY_TIMEOUT;
unsigned long usec_gc_threshold = DEFAULT_USEC_BLK_LATENCY_GC_THRESHOLD;
unsigned long usec_gc_period = DEFAULT_USEC_BLK_LATENCY_GC_PERIOD;

/*
 * FIXME: action on update (all modules)
 */
module_param(usec_threshold, ulong, 0644);
MODULE_PARM_DESC(usec_threshold, "Threshold in microseconds");

module_param(usec_timeout, ulong, 0644);
MODULE_PARM_DESC(usec_timeout, "Timeout in microseconds");

module_param(usec_gc_threshold, ulong, 0644);
MODULE_PARM_DESC(usec_gc_threshold, "Garbage collector threshold in microseconds");

module_param(usec_gc_period, ulong, 0644);
MODULE_PARM_DESC(usec_gc_period, "Garbage collector period in microseconds");

DEFINE_PER_CPU(struct iohist, live_hist);
DEFINE_PER_CPU(struct iohist, current_hist);

struct iohist global_live_hist;

static struct proc_dir_entry *block_hist_tracker_proc_dentry;
static const struct file_operations block_hist_tracker_fops;

static struct proc_dir_entry *block_hist_tracker_history_proc_dentry;
static const struct file_operations block_hist_tracker_history_fops;

static void enable_hist_timer(struct block_hist_tracker *b);

int cnt;
int rq_cnt;
int skip_cnt;

struct latency_tracker *tracker;

void blk_cb(struct latency_tracker_event_ctx *ctx)
{
#if 0
	struct latency_tracker_event *data =
		(struct latency_tracker_event *) ptr;
	struct blk_key_t *key = (struct blk_key_t *) data->tkey.key;
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
void rq_to_key(struct blk_key_t *key, struct request *rq,
		enum tracker_key_type type)
{
	if (!key || !rq)
		return;

	key->sector = blk_rq_pos(rq);
	key->dev = rq->rq_disk ? disk_devt(rq->rq_disk) : 0;
	key->type = type;
}

/*
 * Insert into the I/O scheduler.
 */
static
void probe_block_rq_insert(void *ignore, struct request_queue *q,
		struct request *rq)
{
	struct blk_key_t key;
	enum latency_tracker_event_in_ret ret;

	rq_cnt++;
	if (rq->cmd_type == REQ_TYPE_BLOCK_PC)
		return;

	if (blk_rq_sectors(rq) == 0)
		return;

	rq_to_key(&key, rq, KEY_SCHED);

	ret = latency_tracker_event_in(tracker, &key, sizeof(key),
		0, latency_tracker_get_priv(tracker));
	if (ret == LATENCY_TRACKER_FULL) {
		skip_cnt++;
		//printk("latency_tracker block: no more free events, consider "
		//		"increasing the max_events parameter\n");
	} else if (ret) {
		printk("latency_tracker block: error adding event\n");
	}
}

/*
 * Dequeue from the I/O scheduler and send to the disk.
 */
static
void probe_block_rq_issue(void *ignore, struct request_queue *q,
		struct request *rq)
{
	struct blk_key_t key;
	enum latency_tracker_event_in_ret ret;
	struct latency_tracker_event *s;

	rq_cnt++;
	if (rq->cmd_type == REQ_TYPE_BLOCK_PC)
		return;

	if (blk_rq_sectors(rq) == 0)
		return;

	/* Update the I/O scheduler stats */
	rq_to_key(&key, rq, KEY_SCHED);
	s = latency_tracker_get_event(tracker, &key, sizeof(key));
	if (s) {
		if (rq->cmd_flags % 2 == 0) {
			update_hist(s, IO_SCHED_READ,
					lttng_this_cpu_ptr(&live_hist));
			update_hist(s, IO_SCHED_READ,
					lttng_this_cpu_ptr(&current_hist));
		} else {
			update_hist(s, IO_SCHED_WRITE,
					lttng_this_cpu_ptr(&live_hist));
			update_hist(s, IO_SCHED_WRITE,
					lttng_this_cpu_ptr(&current_hist));
		}
		latency_tracker_put_event(s);
		latency_tracker_event_out(tracker, &key, sizeof(key), 0, 0);
	}

	/* Start tracking the request at the block level */
	rq_to_key(&key, rq, KEY_BLOCK);

	ret = latency_tracker_event_in(tracker, &key, sizeof(key),
		0, latency_tracker_get_priv(tracker));
	if (ret == LATENCY_TRACKER_FULL) {
		skip_cnt++;
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
	return fls_long(v - 1) - 1;
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
void merge_reset_per_cpu_live_hist(struct iohist *h)
{
	int cpu, i, j;
	struct iohist *c;
	unsigned long flags;

	get_online_cpus();
	for_each_online_cpu(cpu) {
		c = per_cpu_ptr(&live_hist, cpu);
		spin_lock_irqsave(&c->lock, flags);
		for (i = 0; i < IO_TYPE_NR; i++) {
			for (j = 0; j < LATENCY_BUCKETS; j++) {
				h->values[i][j] += c->values[i][j];
				c->values[i][j] = 0;
			}
		}
		spin_unlock_irqrestore(&c->lock, flags);
	}
	put_online_cpus();
}

static
void output_live_hist(struct seq_file *m)
{
	int i;

	merge_reset_per_cpu_live_hist(&global_live_hist);

	seq_printf(m, "Latency range   |                    syscall         "
			"           |      fs       |   iosched     |    block\n"
			"                |read   write    r+w     sync    open    "
			"close  |read    write  |read    write  |read    write\n"
			"########################################################"
			"######################################################");
	for(i = 0; i < LATENCY_BUCKETS; i++) {
		seq_printf(m, "\n[");
		output_bucket_value(1ULL << i, m);
		seq_printf(m, ", ");
		output_bucket_value(1ULL << (i+1), m);
		seq_printf(m, "[");
		seq_printf(m, "\t|%u", global_live_hist.values[IO_SYSCALL_READ][i]);
		seq_printf(m, "\t %u", global_live_hist.values[IO_SYSCALL_WRITE][i]);
		seq_printf(m, "\t %u", global_live_hist.values[IO_SYSCALL_RW][i]);
		seq_printf(m, "\t %u", global_live_hist.values[IO_SYSCALL_SYNC][i]);
		seq_printf(m, "\t %u", global_live_hist.values[IO_SYSCALL_OPEN][i]);
		seq_printf(m, "\t %u", global_live_hist.values[IO_SYSCALL_CLOSE][i]);

		seq_printf(m, "\t|%u", global_live_hist.values[IO_FS_READ][i]);
		seq_printf(m, "\t %u", global_live_hist.values[IO_FS_WRITE][i]);

		seq_printf(m, "\t|%u", global_live_hist.values[IO_SCHED_READ][i]);
		seq_printf(m, "\t %u", global_live_hist.values[IO_SCHED_WRITE][i]);

		seq_printf(m, "\t|%u", global_live_hist.values[IO_BLOCK_READ][i]);
		seq_printf(m, "\t %u", global_live_hist.values[IO_BLOCK_WRITE][i]);
	}
	seq_printf(m, "\n");
	reset_hist(&global_live_hist);
}

void update_hist(struct latency_tracker_event *s, enum io_type t,
		struct iohist *h)
{
	u64 now, delta;
	int bucket;
	unsigned long flags;

	now = trace_clock_read64();
	delta = now - latency_tracker_event_get_start_ts(s);

	spin_lock_irqsave(&h->lock, flags);
	if (h->ts_begin == 0)
		h->ts_begin = trace_clock_read64();
	if (delta < h->min)
		h->min = delta;
	if (delta > h->max)
		h->max = delta;
	bucket = get_bucket(delta);
	h->values[t][bucket]++;

	h->nb_values++;
	spin_unlock_irqrestore(&h->lock, flags);
}

static
void probe_block_rq_complete(void *ignore, struct request_queue *q,
		struct request *rq, unsigned int nr_bytes)
{
	struct blk_key_t key;
	struct latency_tracker_event *s;

	if (rq->cmd_type == REQ_TYPE_BLOCK_PC)
		return;

	rq_to_key(&key, rq, KEY_BLOCK);

	s = latency_tracker_get_event(tracker, &key, sizeof(key));
	if (!s)
		goto end;
	if (rq->cmd_flags % 2 == 0) {
		update_hist(s, IO_BLOCK_READ,
				lttng_this_cpu_ptr(&live_hist));
		update_hist(s, IO_BLOCK_READ,
				lttng_this_cpu_ptr(&current_hist));
	} else {
		update_hist(s, IO_BLOCK_WRITE,
				lttng_this_cpu_ptr(&live_hist));
		update_hist(s, IO_BLOCK_WRITE,
				lttng_this_cpu_ptr(&current_hist));
	}
	latency_tracker_put_event(s);

end:
	latency_tracker_event_out(tracker, &key, sizeof(key), 0, 0);
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
	struct syscall_key_t syscall_key;
	enum latency_tracker_event_in_ret ret;
	u64 thresh, timeout;

	if (io_syscall(id) < 0)
		return;

	syscall_key.pid = task->pid;
	syscall_key.type = KEY_SYSCALL;
	thresh = usec_threshold * 1000;
	timeout = usec_timeout * 1000;

	ret = latency_tracker_event_in(tracker, &syscall_key, sizeof(syscall_key),
			0, (void *) id);
	if (ret == LATENCY_TRACKER_FULL) {
		skip_cnt++;
		//printk("latency_tracker block: no more free events, consider "
		//		"increasing the max_events parameter\n");
	} else if (ret) {
		printk("latency_tracker block: error adding event\n");
	}
}

static
void probe_syscall_exit(void *__data, struct pt_regs *regs, long ret)
{
	struct syscall_key_t key;
	struct latency_tracker_event *s;

	key.pid = current->pid;
	key.type = KEY_SYSCALL;
	s = latency_tracker_get_event(tracker, &key, sizeof(key));
	if (!s)
		goto end;
	update_hist(s, io_syscall((unsigned long) latency_tracker_event_get_priv(s)),
			lttng_this_cpu_ptr(&live_hist));
	update_hist(s, io_syscall((unsigned long) latency_tracker_event_get_priv(s)),
			lttng_this_cpu_ptr(&current_hist));
	latency_tracker_put_event(s);

end:
	latency_tracker_event_out(tracker, &key, sizeof(key), 0, 0);
}

static int block_hist_show(struct seq_file *m, void *v)
{
	output_live_hist(m);
	return 0;
}

static
void output_history_hist(struct seq_file *m, struct iohist *h)
{
	int i, j;

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
	}
	seq_printf(m, "\n");
}

static inline
int get_index(struct block_hist_tracker *b, int minus)
{
	int diff = (b->current_min - minus) % AGGREGATES;

	if (diff >= 0)
		return diff;
	return AGGREGATES + diff;
}

static int block_hist_show_history(struct seq_file *m, void *v)
{
	struct block_hist_tracker *b = (struct block_hist_tracker *) m->private;
	int index, i, j, k;
	struct iohist *tmp;
	uint64_t begin = 0, end = 0;

	index = get_index(b, 1);
	if (b->latency_history[index].ts_end == 0) {
		seq_printf(m, "Not enough data, come back in less than 1 minute\n");
		return 0;
	}

	seq_printf(m, "1 minute [%llu, %llu]\n",
			b->latency_history[index].ts_begin,
			b->latency_history[index].ts_end);
	output_history_hist(m, &b->latency_history[index]);

	end = 0;
	begin = -1ULL;
	memset(&b->tmp_display, 0, sizeof(b->tmp_display));
	for (i = 1; i < 6; i++) {
		tmp = &b->latency_history[get_index(b, i)];
		if (tmp->ts_begin != 0 && tmp->ts_begin < begin)
			begin = tmp->ts_begin;
		if (tmp->ts_end != 0 && tmp->ts_end > end)
			end = tmp->ts_end;
		for (j = 0; j < IO_TYPE_NR; j++) {
			for (k = 0; k < LATENCY_BUCKETS; k++) {
				b->tmp_display.values[j][k] += tmp->values[j][k];
			}
		}
	}
	seq_printf(m, "5 min [%llu, %llu] %llu\n", begin, end, ((end - begin)/1000000000)/60);
	output_history_hist(m, &b->tmp_display);

	end = 0;
	begin = -1ULL;
	memset(&b->tmp_display, 0, sizeof(b->tmp_display));
	for (i = 1; i < 16; i++) {
		tmp = &b->latency_history[get_index(b, i)];
		if (tmp->ts_begin != 0 && tmp->ts_begin < begin)
			begin = tmp->ts_begin;
		if (tmp->ts_end != 0 && tmp->ts_end > end)
			end = tmp->ts_end;
		for (j = 0; j < IO_TYPE_NR; j++) {
			for (k = 0; k < LATENCY_BUCKETS; k++) {
				b->tmp_display.values[j][k] += tmp->values[j][k];
			}
		}
	}
	seq_printf(m, "15 min [%llu, %llu] %llu\n", begin, end, ((end - begin)/1000000000)/60);
	output_history_hist(m, &b->tmp_display);
	return 0;
}

static
int tracker_proc_open(struct inode *inode, struct file *filp)
{
	struct block_hist_tracker *block_hist_priv = PDE_DATA(inode);

	filp->private_data = block_hist_priv;

	return single_open(filp, block_hist_show, block_hist_priv);
}

static
int tracker_history_proc_open(struct inode *inode, struct file *filp)
{
	struct block_hist_tracker *block_hist_priv = PDE_DATA(inode);

//	filp->private_data = block_hist_priv;

	return single_open(filp, block_hist_show_history, block_hist_priv);
}

static const
struct file_operations block_hist_tracker_fops = {
	.owner = THIS_MODULE,
	.open = tracker_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static const
struct file_operations block_hist_tracker_history_fops = {
	.owner = THIS_MODULE,
	.open = tracker_history_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static
void init_histograms(void)
{
	int cpu;
	struct iohist *c;

	lttng_this_cpu_ptr(&live_hist)->min = -1ULL;
	lttng_this_cpu_ptr(&live_hist)->max = 0;

	lttng_this_cpu_ptr(&current_hist)->min = -1ULL;
	lttng_this_cpu_ptr(&current_hist)->max = 0;
	for_each_possible_cpu(cpu) {
		c = per_cpu_ptr(&live_hist, cpu);
		spin_lock_init(&c->lock);
		c = per_cpu_ptr(&current_hist, cpu);
		spin_lock_init(&c->lock);
	}
}

static
void merge_reset_per_cpu_current_hist(struct iohist *h)
{
	int cpu, i, j;
	struct iohist *c;
	unsigned long flags;

	get_online_cpus();
	for_each_online_cpu(cpu) {
		c = per_cpu_ptr(&current_hist, cpu);
		if (h->ts_begin == 0)
			h->ts_begin = c->ts_begin;
		else if (c->ts_begin < h->ts_begin)
			h->ts_begin = c->ts_begin;
		spin_lock_irqsave(&c->lock, flags);
		for (i = 0; i < IO_TYPE_NR; i++) {
			for (j = 0; j < LATENCY_BUCKETS; j++) {
				h->values[i][j] += c->values[i][j];
				c->values[i][j] = 0;
			}
		}
		c->ts_begin = 0;
		spin_unlock_irqrestore(&c->lock, flags);
	}
	put_online_cpus();
	h->ts_end = trace_clock_read64();
}


static
void timer_cb(unsigned long ptr)
{
	struct block_hist_tracker *b = (struct block_hist_tracker *) ptr;

	memset(&b->latency_history[b->current_min], 0, sizeof(struct iohist));
	merge_reset_per_cpu_current_hist(&b->latency_history[b->current_min]);
	b->current_min = (b->current_min + 1) % AGGREGATES;

	enable_hist_timer(b);
}

static
void enable_hist_timer(struct block_hist_tracker *b)
{
	del_timer(&b->timer);

	b->timer.function = timer_cb;
	/* 60 seconds */
	b->timer.expires = jiffies + wrapper_nsecs_to_jiffies(60000000000);
	/* 10 seconds */
	//b->timer.expires = jiffies + wrapper_nsecs_to_jiffies(10000000000);
	//b->timer.expires = jiffies + wrapper_nsecs_to_jiffies(1000000000);
	b->timer.data = (unsigned long) b;
	add_timer(&b->timer);
}

static
int __init block_hist_latency_tp_init(void)
{
	int ret;
	struct block_hist_tracker *block_hist_priv;

	cnt = rq_cnt = skip_cnt = 0;
	block_hist_priv = vzalloc(sizeof(struct block_hist_tracker));
	if (!block_hist_priv) {
		ret = -ENOMEM;
		goto end;
	}
	wrapper_vmalloc_sync_all();
	block_hist_priv->reason = BLOCK_TRACKER_WAIT;
	/* limit to 1 evt/sec */
	block_hist_priv->ns_rate_limit = 1000000000;

	tracker = latency_tracker_create("block_hist");
	if (!tracker)
		goto error;
	latency_tracker_set_startup_events(tracker, 100000);
	latency_tracker_set_timer_period(tracker, usec_gc_period * 1000);
	latency_tracker_set_priv(tracker, block_hist_priv);
	latency_tracker_set_threshold(tracker, usec_threshold * 1000);
	latency_tracker_set_timeout(tracker, usec_timeout * 1000);
	latency_tracker_set_callback(tracker, blk_cb);
	latency_tracker_set_key_size(tracker, MAX_KEY_SIZE);
	ret = latency_tracker_enable(tracker);
	if (ret)
		goto error;

	init_histograms();
	init_timer(&block_hist_priv->timer);
	block_hist_priv->current_min = 0;
	enable_hist_timer(block_hist_priv);

	ret = lttng_wrapper_tracepoint_probe_register("block_rq_insert",
			probe_block_rq_insert, NULL);
	WARN_ON(ret);

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

	ret = setup_kprobes();
	WARN_ON(ret);

	block_hist_tracker_proc_dentry = proc_create("block_hist_tracker",
			0, NULL, &block_hist_tracker_fops);

	if (!block_hist_tracker_proc_dentry) {
		printk(KERN_ERR "Error creating tracker control file\n");
		ret = -ENOMEM;
		goto end;
	}

	block_hist_tracker_history_proc_dentry = proc_create_data("block_hist_tracker_history",
			0, NULL, &block_hist_tracker_history_fops, block_hist_priv);

	if (!block_hist_tracker_history_proc_dentry) {
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

	lttng_wrapper_tracepoint_probe_unregister("block_rq_insert",
			probe_block_rq_insert, NULL);
	lttng_wrapper_tracepoint_probe_unregister("block_rq_issue",
			probe_block_rq_issue, NULL);
	lttng_wrapper_tracepoint_probe_unregister("block_rq_complete",
			probe_block_rq_complete, NULL);
	lttng_wrapper_tracepoint_probe_unregister(
			"sys_enter", probe_syscall_enter, NULL);
	lttng_wrapper_tracepoint_probe_unregister(
			"sys_exit", probe_syscall_exit, NULL);
	tracepoint_synchronize_unregister();
	remove_kprobes();

	block_hist_priv = latency_tracker_get_priv(tracker);
	del_timer_sync(&block_hist_priv->timer);
	vfree(block_hist_priv);

	latency_tracker_destroy(tracker);

	printk("Total block alerts : %d\n", cnt);
	printk("Total block requests : %d\n", rq_cnt);
	printk("Skipped : %d\n", skip_cnt);
	if (block_hist_tracker_proc_dentry)
		remove_proc_entry("block_hist_tracker", NULL);
	if (block_hist_tracker_history_proc_dentry)
		remove_proc_entry("block_hist_tracker_history", NULL);
}
module_exit(block_hist_latency_tp_exit);

MODULE_AUTHOR("Julien Desfossez <jdesfossez@efficios.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
