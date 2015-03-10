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
#include <linux/proc_fs.h>
#include <linux/types.h>
#include "../latency_tracker.h"

void process_register(pid_t tgid);
void process_unregister(pid_t tgid);
int syscall_tracker_setup_proc_priv(void);
void syscall_tracker_destroy_proc_priv(void);
long syscall_tracker_ioctl(
    struct file *file, unsigned int cmd, unsigned long arg);

static const struct file_operations syscall_tracker_fops = {
  .owner = THIS_MODULE,
  .unlocked_ioctl = syscall_tracker_ioctl,
#ifdef CONFIG_COMPAT
  .compat_ioctl = syscall_tracker_ioctl,
#endif
};

#endif /* _LATENCY_TRACKER_EXAMPLES_SYSCALLS_H */
