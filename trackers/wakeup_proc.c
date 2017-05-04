/*
 * Copyright (C) 2015 Julien Desfossez <jdesfossez@efficios.com>
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

#include <linux/irq_work.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include "wakeup_latency.h"

struct wakeup_tracker *wakeup_alloc_priv(void)
{
	struct wakeup_tracker *wakeup_priv;

	wakeup_priv = kzalloc(sizeof(struct wakeup_tracker), GFP_KERNEL);
	if (!wakeup_priv)
		goto end;
	wakeup_priv->reason = SCHED_TRACKER_WAIT;
	/* limit to 1 evt/sec */
	wakeup_priv->ns_rate_limit = 1000000000;

end:
	return wakeup_priv;
}

static
void irq_wake(struct irq_work *entry)
{
	struct wakeup_tracker *wakeup_priv = container_of(entry,
			struct wakeup_tracker, w_irq);
	wakeup_priv->reason = SCHED_TRACKER_WAKE_DATA;
	wake_up_interruptible(&wakeup_priv->read_wait);
	wakeup_priv->got_alert = true;
}

int wakeup_setup_priv(struct wakeup_tracker *wakeup_priv)
{
	int ret;

	init_irq_work(&wakeup_priv->w_irq, irq_wake);
	wakeup_priv->proc_dentry = proc_create_data("wake_latency",
			S_IRUSR|S_IRGRP|S_IROTH, NULL, &wakeup_tracker_fops, wakeup_priv);
	if (!wakeup_priv->proc_dentry) {
		printk(KERN_ERR "Error creating tracker control file\n");
		ret = -ENOMEM;
		goto end;
	}
	init_waitqueue_head(&wakeup_priv->read_wait);
	ret = 0;

end:
	return ret;
}

void wakeup_destroy_priv(struct wakeup_tracker *wakeup_priv)
{
	irq_work_sync(&wakeup_priv->w_irq);
	if (wakeup_priv->proc_dentry)
		remove_proc_entry("wake_latency", NULL);
	kfree(wakeup_priv);

}

void wakeup_handle_proc(struct wakeup_tracker *wakeup_priv,
		uint64_t end_ts)
{
	/* Rate limiter */
	if ((end_ts - wakeup_priv->last_alert_ts) <
			wakeup_priv->ns_rate_limit)
		return;

	if (wakeup_priv->readers > 0)
		irq_work_queue(&wakeup_priv->w_irq);
	wakeup_priv->last_alert_ts = end_ts;
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

int tracker_proc_release(struct inode *inode, struct file *filp)
{
	struct wakeup_tracker *wakeup_priv = filp->private_data;

	wakeup_priv->readers--;
	module_put(THIS_MODULE);
	return 0;
}
