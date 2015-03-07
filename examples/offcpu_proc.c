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
#include "offcpu.h"

struct offcpu_tracker *offcpu_alloc_priv(void)
{
	struct offcpu_tracker *offcpu_priv;

	offcpu_priv = kzalloc(sizeof(struct offcpu_tracker), GFP_KERNEL);
	if (!offcpu_priv)
		goto end;
	offcpu_priv->reason = OFFCPU_TRACKER_WAIT;
	/* limit to 1 evt/sec */
	offcpu_priv->ns_rate_limit = 1000000000;

end:
	return offcpu_priv;
}

static
void irq_wake(struct irq_work *entry)
{
	struct offcpu_tracker *offcpu_priv = container_of(entry,
			struct offcpu_tracker, w_irq);
	offcpu_priv->reason = OFFCPU_TRACKER_WAKE_DATA;
	wake_up_interruptible(&offcpu_priv->read_wait);
	offcpu_priv->got_alert = true;
}

int offcpu_setup_priv(struct offcpu_tracker *offcpu_priv)
{
	int ret;

	init_irq_work(&offcpu_priv->w_irq, irq_wake);
	offcpu_priv->proc_dentry = proc_create_data("offcpu_latency",
			S_IRUSR|S_IRGRP|S_IROTH, NULL, &wakeup_tracker_fops,
			offcpu_priv);
	if (!offcpu_priv->proc_dentry) {
		printk(KERN_ERR "Error creating tracker control file\n");
		ret = -ENOMEM;
		goto end;
	}
	init_waitqueue_head(&offcpu_priv->read_wait);
	ret = 0;

end:
	return ret;
}

void offcpu_destroy_priv(struct offcpu_tracker *offcpu_priv)
{
	irq_work_sync(&offcpu_priv->w_irq);
	if (offcpu_priv->proc_dentry)
		remove_proc_entry("offcpu_latency", NULL);
	kfree(offcpu_priv);

}

void offcpu_handle_proc(struct offcpu_tracker *offcpu_priv,
		struct latency_tracker_event *data)
{
	/* Rate limiter */
	if ((data->end_ts - offcpu_priv->last_alert_ts) <
			offcpu_priv->ns_rate_limit)
		return;

	if (offcpu_priv->readers > 0)
		irq_work_queue(&offcpu_priv->w_irq);
	offcpu_priv->last_alert_ts = data->end_ts;
}

unsigned int tracker_proc_poll(struct file *filp,
		poll_table *wait)
{
	struct offcpu_tracker *offcpu_priv = filp->private_data;
	unsigned int mask = 0;

	if (filp->f_mode & FMODE_READ) {
		poll_wait(filp, &offcpu_priv->read_wait, wait);
		if (offcpu_priv->reason == OFFCPU_TRACKER_WAKE_DATA)
			mask |= POLLIN;
		else
			mask |= POLLHUP;
	}

	return mask;
}

ssize_t tracker_proc_read(struct file *filp, char __user *buf, size_t n,
		loff_t *offset)
{
	struct offcpu_tracker *offcpu_priv = filp->private_data;

	wait_event_interruptible(offcpu_priv->read_wait,
			offcpu_priv->got_alert);
	offcpu_priv->reason = OFFCPU_TRACKER_WAIT;
	offcpu_priv->got_alert = false;

	return 0;
}

int tracker_proc_open(struct inode *inode, struct file *filp)
{
	struct offcpu_tracker *offcpu_priv = PDE_DATA(inode);
	int ret;

	offcpu_priv->got_alert = false;
	offcpu_priv->readers++;
	filp->private_data = offcpu_priv;
	ret = try_module_get(THIS_MODULE);
	if (!ret)
		return -1;

	return 0;
}

int tracker_proc_release(struct inode *inode, struct file *filp)
{
	struct offcpu_tracker *offcpu_priv = filp->private_data;

	offcpu_priv->readers--;
	module_put(THIS_MODULE);
	return 0;
}
