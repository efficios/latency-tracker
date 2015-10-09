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
#include "critical_timing.h"

struct critical_timing_tracker *critical_timing_alloc_priv(void)
{
	struct critical_timing_tracker *critical_timing_priv;

	critical_timing_priv = kzalloc(sizeof(struct critical_timing_tracker), GFP_KERNEL);
	if (!critical_timing_priv)
		goto end;
	critical_timing_priv->reason = CRITICAL_TRACKER_WAIT;
	/* limit to 1 evt/sec */
	critical_timing_priv->ns_rate_limit = 1000000000;

end:
	return critical_timing_priv;
}

static
void irq_wake(struct irq_work *entry)
{
	struct critical_timing_tracker *critical_timing_priv = container_of(entry,
			struct critical_timing_tracker, w_irq);
	critical_timing_priv->reason = CRITICAL_TRACKER_WAKE_DATA;
	wake_up_interruptible(&critical_timing_priv->read_wait);
	critical_timing_priv->got_alert = true;
}

int critical_timing_setup_priv(struct critical_timing_tracker *critical_timing_priv)
{
	int ret;

	init_irq_work(&critical_timing_priv->w_irq, irq_wake);
	critical_timing_priv->proc_dentry = proc_create_data("critical_timing_latency",
			S_IRUSR|S_IRGRP|S_IROTH, NULL, &wakeup_tracker_fops,
			critical_timing_priv);
	if (!critical_timing_priv->proc_dentry) {
		printk(KERN_ERR "Error creating tracker control file\n");
		ret = -ENOMEM;
		goto end;
	}
	init_waitqueue_head(&critical_timing_priv->read_wait);
	ret = 0;

end:
	return ret;
}

void critical_timing_destroy_priv(struct critical_timing_tracker *critical_timing_priv)
{
	irq_work_sync(&critical_timing_priv->w_irq);
	if (critical_timing_priv->proc_dentry)
		remove_proc_entry("critical_timing_latency", NULL);
	kfree(critical_timing_priv);

}

void critical_timing_handle_proc(struct critical_timing_tracker *critical_timing_priv,
		uint64_t end_ts)
{
	/* Rate limiter */
	if ((end_ts - critical_timing_priv->last_alert_ts) <
			critical_timing_priv->ns_rate_limit)
		return;

	if (critical_timing_priv->readers > 0)
		irq_work_queue(&critical_timing_priv->w_irq);
	critical_timing_priv->last_alert_ts = end_ts;
}

unsigned int tracker_proc_poll(struct file *filp,
		poll_table *wait)
{
	struct critical_timing_tracker *critical_timing_priv = filp->private_data;
	unsigned int mask = 0;

	if (filp->f_mode & FMODE_READ) {
		poll_wait(filp, &critical_timing_priv->read_wait, wait);
		if (critical_timing_priv->reason == CRITICAL_TRACKER_WAKE_DATA)
			mask |= POLLIN;
		else
			mask |= POLLHUP;
	}

	return mask;
}

ssize_t tracker_proc_read(struct file *filp, char __user *buf, size_t n,
		loff_t *offset)
{
	struct critical_timing_tracker *critical_timing_priv = filp->private_data;

	wait_event_interruptible(critical_timing_priv->read_wait,
			critical_timing_priv->got_alert);
	critical_timing_priv->reason = CRITICAL_TRACKER_WAIT;
	critical_timing_priv->got_alert = false;

	return 0;
}

int tracker_proc_open(struct inode *inode, struct file *filp)
{
	struct critical_timing_tracker *critical_timing_priv = PDE_DATA(inode);
	int ret;

	critical_timing_priv->got_alert = false;
	critical_timing_priv->readers++;
	filp->private_data = critical_timing_priv;
	ret = try_module_get(THIS_MODULE);
	if (!ret)
		return -1;

	return 0;
}

int tracker_proc_release(struct inode *inode, struct file *filp)
{
	struct critical_timing_tracker *critical_timing_priv = filp->private_data;

	critical_timing_priv->readers--;
	module_put(THIS_MODULE);
	return 0;
}
