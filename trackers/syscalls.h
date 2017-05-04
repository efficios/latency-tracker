#ifndef _LATENCY_TRACKER_EXAMPLES_SYSCALLS_H
#define _LATENCY_TRACKER_EXAMPLES_SYSCALLS_H

/*
 * syscalls.h
 *
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
#include <linux/irq_work.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/types.h>
#include "../latency_tracker.h"

enum wake_reason {
  SYSCALL_TRACKER_WAKE_DATA = 0,
  SYSCALL_TRACKER_WAIT = 1,
};

struct syscall_tracker {
  u64 last_alert_ts;
  u64 ns_rate_limit;
  wait_queue_head_t read_wait;
  enum wake_reason reason;
  bool got_alert;
  int readers;
  struct irq_work w_irq;
  struct proc_dir_entry *proc_dentry;
};

void process_register(pid_t tgid);
void process_unregister(pid_t tgid);

struct syscall_tracker *syscall_tracker_alloc_priv(void);
int syscall_tracker_setup_proc_priv(struct syscall_tracker *tracker_priv);
void syscall_tracker_destroy_proc_priv(struct syscall_tracker *tracker_priv);
void syscall_tracker_handle_proc(struct syscall_tracker *tracker_priv);

int syscall_tracker_proc_release(struct inode *inode, struct file *filp);
int syscall_tracker_proc_open(struct inode *inode, struct file *filp);
ssize_t syscall_tracker_proc_read(struct file *filp, char __user *buf, size_t n,
  loff_t *offset);
unsigned int syscall_tracker_proc_poll(struct file *filp, poll_table *wait);
long syscall_tracker_ioctl(
    struct file *filp, unsigned int cmd, unsigned long arg);

static const struct file_operations syscall_tracker_fops = {
  .owner = THIS_MODULE,
  .open = syscall_tracker_proc_open,
  .read = syscall_tracker_proc_read,
  .release = syscall_tracker_proc_release,
  .poll = syscall_tracker_proc_poll,
  .unlocked_ioctl = syscall_tracker_ioctl,
#ifdef CONFIG_COMPAT
  .compat_ioctl = syscall_tracker_ioctl,
#endif
};

#endif /* _LATENCY_TRACKER_EXAMPLES_SYSCALLS_H */
