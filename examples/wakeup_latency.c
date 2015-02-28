/*
 * wakeup_latency.c
 *
 * Example of usage of latency_tracker with kernel tracepoints.
 *
 * In this example, we call the callback function wakeup_cb when the delay
 * between a sched wakeup and its completion (sched_switch) takes more than
 * DEFAULT_USEC_WAKEUP_LATENCY_THRESH microseconds. Moreover, if the task is
 * still not scheduled after DEFAULT_USEC_WAKEUP_LATENCY_TIMEOUT microseconds,
 * the callback is called with timeout = 1.
 *
 * The 2 parameters can be controlled at run-time by writing the value in
 * micro-seconds in:
 * /sys/module/wakeup_latency/parameters/usec_threshold and
 * /sys/module/wakeup_latency/parameters/usec_timeout
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
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/poll.h>
#include <linux/irq_work.h>
#include "wakeup_latency.h"
#include "../latency_tracker.h"
#include "../wrapper/tracepoint.h"

#include <trace/events/latency_tracker.h>

/*
 * Threshold to execute the callback (microseconds).
 */
#define DEFAULT_USEC_WAKEUP_LATENCY_THRESH 5 * 1000
/*
 * Timeout to execute the callback (microseconds).
 */
#define DEFAULT_USEC_WAKEUP_LATENCY_TIMEOUT 0

static pid_t current_pid[NR_CPUS];

/*
 * microseconds because we can't guarantee the passing of 64-bit
 * arguments to insmod on all architectures.
 */
static unsigned long usec_threshold = DEFAULT_USEC_WAKEUP_LATENCY_THRESH;
module_param(usec_threshold, ulong, 0644);
MODULE_PARM_DESC(usec_threshold, "Threshold in microseconds");

static unsigned long usec_timeout = DEFAULT_USEC_WAKEUP_LATENCY_TIMEOUT;
module_param(usec_timeout, ulong, 0644);
MODULE_PARM_DESC(usec_timeout, "Timeout in microseconds");

struct schedkey {
	pid_t pid;
} __attribute__((__packed__));

enum wake_reason {
	SCHED_TRACKER_WAKE_DATA = 0,
	SCHED_TRACKER_WAIT = 1,
	SCHED_TRACKER_HUP = 2,
};

struct wakeup_tracker {
	u64 last_alert_ts;
	u64 ns_rate_limit;
	wait_queue_head_t read_wait;
	enum wake_reason reason;
	bool got_alert;
	int readers;
	struct irq_work w_irq;
};

static struct latency_tracker *tracker;

static int cnt = 0;

static struct proc_dir_entry *wakeup_tracker_proc_dentry;
static const struct file_operations wakeup_tracker_fops;

void irq_wake(struct irq_work *entry)
{
	struct wakeup_tracker *wakeup_priv = container_of(entry,
			struct wakeup_tracker, w_irq);
	wakeup_priv->reason = SCHED_TRACKER_WAKE_DATA;
	wake_up_interruptible(&wakeup_priv->read_wait);
	wakeup_priv->got_alert = true;
}

static
void wakeup_cb(unsigned long ptr)
{
	struct latency_tracker_event *data =
		(struct latency_tracker_event *) ptr;
	struct schedkey *key = (struct schedkey *) data->tkey.key;
	struct wakeup_tracker *wakeup_priv =
		(struct wakeup_tracker *) data->priv;
	struct task_struct *p;
	u64 delay;

	if (data->cb_flag != LATENCY_TRACKER_CB_NORMAL)
		return;
	/* Rate limiter */
	if ((data->end_ts - wakeup_priv->last_alert_ts) <
			wakeup_priv->ns_rate_limit)
		return;

	delay = (data->end_ts - data->start_ts) / 1000;
#ifdef SCHEDWORST
	usec_threshold = delay;
#endif

	rcu_read_lock();
	p = pid_task(find_vpid(key->pid), PIDTYPE_PID);
	if (!p)
		goto end_unlock;
	trace_wakeup_latency(key->pid, data->end_ts - data->start_ts,
			data->cb_flag);
	printk("wakeup_latency: (%d) %s (%d), %llu us\n", data->cb_flag,
			p->comm, key->pid, delay);
	rcu_read_unlock();
	cnt++;

	if (wakeup_priv->readers > 0)
		irq_work_queue(&wakeup_priv->w_irq);
	wakeup_priv->last_alert_ts = data->end_ts;
	goto end;

end_unlock:
	rcu_read_unlock();
end:
	return;
}

static
void probe_sched_wakeup(void *ignore, struct task_struct *p, int success)
{
	struct schedkey key;
	u64 thresh, timeout;
	int i;
	enum latency_tracker_event_in_ret ret;

	if (!p || !p->pid)
		return;

	/*
	 * Make sure we won't wait for a process already running on another CPU.
	 */
	for (i = 0; i < NR_CPUS; i++)
		if (current_pid[i] == p->pid)
			return;

	key.pid = p->pid;
	thresh = usec_threshold * 1000;
	timeout = usec_timeout * 1000;

	ret = latency_tracker_event_in(tracker, &key, sizeof(key),
		thresh, wakeup_cb, timeout, 1,
		latency_tracker_get_priv(tracker));
	if (ret == LATENCY_TRACKER_FULL) {
//		printk("latency_tracker sched: no more free events, consider "
//				"increasing the max_events parameter\n");
	} else if (ret) {
		printk("latency_tracker sched: error adding event\n");
	}
}

static
void probe_sched_switch(void *ignore, struct task_struct *prev,
		struct task_struct *next)
{
	struct schedkey key;

	if (!next || !next->pid)
		return;

	current_pid[prev->on_cpu] = next->pid;

	key.pid = next->pid;
	latency_tracker_event_out(tracker, &key, sizeof(key), 0);
}

unsigned int tracker_proc_poll(struct file *filp,
		poll_table *wait)
{
	struct wakeup_tracker *wakeup_priv = filp->private_data;
	unsigned int mask = 0;

	if (filp->f_mode & FMODE_READ) {
		poll_wait(filp, &wakeup_priv->read_wait, wait);
		if (wakeup_priv->reason == SCHED_TRACKER_WAKE_DATA)
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
	struct wakeup_tracker *wakeup_priv = filp->private_data;

	wait_event_interruptible(wakeup_priv->read_wait,
			wakeup_priv->got_alert);
	wakeup_priv->reason = SCHED_TRACKER_WAIT;
	wakeup_priv->got_alert = false;

	return 0;
}

	static
int tracker_proc_open(struct inode *inode, struct file *filp)
{
	struct wakeup_tracker *wakeup_priv = PDE_DATA(inode);
	int ret;

	wakeup_priv->got_alert = false;
	wakeup_priv->readers++;
	filp->private_data = wakeup_priv;
	ret = try_module_get(THIS_MODULE);
	if (!ret)
		return -1;

	return 0;
}

	static
int tracker_proc_release(struct inode *inode, struct file *filp)
{
	struct wakeup_tracker *wakeup_priv = filp->private_data;

	wakeup_priv->readers--;
	module_put(THIS_MODULE);
	return 0;
}

static const
struct file_operations wakeup_tracker_fops = {
	.owner = THIS_MODULE,
	.open = tracker_proc_open,
	.read = tracker_proc_read,
	.release = tracker_proc_release,
	.poll = tracker_proc_poll,
};

static
int __init wakeup_latency_init(void)
{
	int ret;
	struct wakeup_tracker *wakeup_priv;

	wakeup_priv = kzalloc(sizeof(struct wakeup_tracker), GFP_KERNEL);
	if (!wakeup_priv) {
		ret = -ENOMEM;
		goto end;
	}
	wakeup_priv->reason = SCHED_TRACKER_WAIT;
	/* limit to 1 evt/sec */
	wakeup_priv->ns_rate_limit = 1000000000;

	tracker = latency_tracker_create(NULL, NULL, 200, 1000, 100000000, 0,
			wakeup_priv);
	if (!tracker)
		goto error;

	init_irq_work(&wakeup_priv->w_irq, irq_wake);

	ret = lttng_wrapper_tracepoint_probe_register("sched_wakeup",
			probe_sched_wakeup, NULL);
	WARN_ON(ret);

	ret = lttng_wrapper_tracepoint_probe_register("sched_switch",
			probe_sched_switch, NULL);
	WARN_ON(ret);

	wakeup_tracker_proc_dentry = proc_create_data("wake_latency",
			S_IRUSR, NULL, &wakeup_tracker_fops, wakeup_priv);

	if (!wakeup_tracker_proc_dentry) {
		printk(KERN_ERR "Error creating tracker control file\n");
		ret = -ENOMEM;
		goto end;
	}
	init_waitqueue_head(&wakeup_priv->read_wait);

	ret = 0;
	goto end;

error:
	ret = -1;
end:
	return ret;
}
module_init(wakeup_latency_init);

static
void __exit wakeup_latency_exit(void)
{
	uint64_t skipped;
	struct wakeup_tracker *wakeup_priv;

	lttng_wrapper_tracepoint_probe_unregister("sched_wakeup",
			probe_sched_wakeup, NULL);
	lttng_wrapper_tracepoint_probe_unregister("sched_switch",
			probe_sched_switch, NULL);
	tracepoint_synchronize_unregister();
	skipped = latency_tracker_skipped_count(tracker);
	wakeup_priv = latency_tracker_get_priv(tracker);
	irq_work_sync(&wakeup_priv->w_irq);
	kfree(wakeup_priv);
	latency_tracker_destroy(tracker);
	if (wakeup_tracker_proc_dentry)
		remove_proc_entry("wake_latency", NULL);
	printk("Missed events : %llu\n", skipped);
	printk("Total wakeup alerts : %d\n", cnt);
}
module_exit(wakeup_latency_exit);

MODULE_AUTHOR("Julien Desfossez <jdesfossez@efficios.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
