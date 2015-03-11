/*
 * Copyright (C) 2015 Francois Doray <francois.pierre-doray@polymtl.ca>
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
#include "syscalls.h"

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/uaccess.h>

#include "syscalls_abi.h"
#include "../wrapper/trace-clock.h"

static
void irq_wake(struct irq_work *entry)
{
  struct syscall_tracker *syscall_priv = container_of(entry,
      struct syscall_tracker, w_irq);
  syscall_priv->reason = SYSCALL_TRACKER_WAKE_DATA;
  wake_up_interruptible(&syscall_priv->read_wait);
  syscall_priv->got_alert = true;
}

struct syscall_tracker *syscall_tracker_alloc_priv(void)
{
  struct syscall_tracker *syscall_priv;

  syscall_priv = kzalloc(sizeof(struct syscall_tracker), GFP_KERNEL);
  if (!syscall_priv)
    goto end;
  syscall_priv->reason = SYSCALL_TRACKER_WAIT;
  /* limit to 1 evt/sec */
  syscall_priv->ns_rate_limit = 1000000000;

end:
  return syscall_priv;
}

int syscall_tracker_setup_proc_priv(struct syscall_tracker *tracker_priv)
{
  int ret;

  init_irq_work(&tracker_priv->w_irq, irq_wake);

  tracker_priv->proc_dentry = proc_create_data(SYSCALL_TRACKER_PROC,
      S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH,
      NULL, &syscall_tracker_fops, tracker_priv);
  if (!tracker_priv->proc_dentry) {
    printk(KERN_ERR "Error creating syscalls tracker control file.\n");
    ret = -ENOMEM;
    goto error;
  }

  init_waitqueue_head(&tracker_priv->read_wait);
  ret = 0;

  printk("Syscalls tracker module loaded successfully.");
  return ret;

error:
  return ret;
}

void syscall_tracker_destroy_proc_priv(struct syscall_tracker *tracker_priv)
{
  irq_work_sync(&tracker_priv->w_irq);
  if (tracker_priv->proc_dentry) {
    remove_proc_entry(SYSCALL_TRACKER_PROC, NULL);
  }
  kfree(tracker_priv);
}

void syscall_tracker_handle_proc(struct syscall_tracker *tracker_priv)
{
  uint64_t ts = trace_clock_read64();

  /* Rate limiter */
  if ((ts - tracker_priv->last_alert_ts) < tracker_priv->ns_rate_limit)
    return;

  if (tracker_priv->readers > 0)
    irq_work_queue(&tracker_priv->w_irq);
  tracker_priv->last_alert_ts = ts;
}

int syscall_tracker_proc_release(struct inode *inode, struct file *filp)
{
  struct syscall_tracker *tracker_priv = filp->private_data;

  tracker_priv->readers--;
  module_put(THIS_MODULE);
  return 0;
}

int syscall_tracker_proc_open(struct inode *inode, struct file *filp)
{
  struct syscall_tracker *tracker_priv = PDE_DATA(inode);
  int ret;

  tracker_priv->got_alert = false;
  tracker_priv->readers++;
  filp->private_data = tracker_priv;
  ret = try_module_get(THIS_MODULE);
  if (!ret)
    return -1;

  return 0;
}

ssize_t syscall_tracker_proc_read(struct file *filp, char __user *buf, size_t n,
    loff_t *offset)
{
  struct syscall_tracker *tracker_priv = filp->private_data;

  wait_event_interruptible(tracker_priv->read_wait,
      tracker_priv->got_alert);
  tracker_priv->reason = SYSCALL_TRACKER_WAIT;
  tracker_priv->got_alert = false;

  return 0;
}

unsigned int syscall_tracker_proc_poll(struct file *filp,
    poll_table *wait)
{
  struct syscall_tracker *tracker_priv = filp->private_data;
  unsigned int mask = 0;

  if (filp->f_mode & FMODE_READ) {
    poll_wait(filp, &tracker_priv->read_wait, wait);
    if (tracker_priv->reason == SYSCALL_TRACKER_WAKE_DATA)
      mask |= POLLIN;
    else
      mask |= POLLHUP;
  }

  return mask;
}

long syscall_tracker_ioctl(
    struct file *filp, unsigned int cmd, unsigned long arg)
{
  struct syscall_tracker *tracker_priv = filp->private_data;
  struct syscall_tracker_module_msg msg;
  int ret = 0;
  void __user *umsg = (void *) arg;

  if (cmd != SYSCALLS_TRACKER_IOCTL)
    return -ENOIOCTLCMD;

  if (copy_from_user(&msg, umsg, sizeof(msg)))
    return -EFAULT;

  switch(msg.cmd) {
  case SYSCALL_TRACKER_MODULE_REGISTER:
    process_register(current->tgid);
    break;
  case SYSCALL_TRACKER_MODULE_UNREGISTER:
    process_unregister(current->tgid);
    break;
  case SYSCALL_TRACKER_MODULE_STACK:
    syscall_tracker_handle_proc(tracker_priv);
    break;
  default:
    ret = -ENOTSUPP;
    break;
  }

  return ret;
}
