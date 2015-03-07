#ifndef _TP_WAKEUP_LATENCY_H
#define _TP_WAKEUP_LATENCY_H

/*
 * block_latency_tp.h
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

#include <linux/tracepoint.h>
#include <linux/blkdev.h>
#include "../latency_tracker.h"

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
	struct proc_dir_entry *proc_dentry;
};

static const struct file_operations wakeup_tracker_fops;

int tracker_proc_release(struct inode *inode, struct file *filp);
int tracker_proc_open(struct inode *inode, struct file *filp);
ssize_t tracker_proc_read(struct file *filp, char __user *buf, size_t n,
	loff_t *offset);
unsigned int tracker_proc_poll(struct file *filp, poll_table *wait);
void irq_wake(struct irq_work *entry);
struct wakeup_tracker *alloc_priv(void);
int setup_priv(struct wakeup_tracker *wakeup_priv);
void destroy_priv(struct wakeup_tracker *wakeup_priv);
void wakeup_proc(struct wakeup_tracker *wakeup_priv,
		struct latency_tracker_event *data);

static const
struct file_operations wakeup_tracker_fops = {
	.owner = THIS_MODULE,
	.open = tracker_proc_open,
	.read = tracker_proc_read,
	.release = tracker_proc_release,
	.poll = tracker_proc_poll,
};

DECLARE_TRACE(sched_wakeup,
	TP_PROTO(struct task_struct *p, int success),
	TP_ARGS(p, success));

DECLARE_TRACE(sched_switch,
	TP_PROTO(struct task_struct *prev, struct task_struct *next),
	TP_ARGS(prev, next));

#endif /* _TP_WAKEUP_LATENCY_H */
