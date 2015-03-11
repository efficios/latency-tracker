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

#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/uaccess.h>

#include "syscalls_abi.h"

static struct proc_dir_entry *syscall_tracker_tracker_proc_dentry;

int syscall_tracker_setup_proc_priv(void)
{
  int ret = 0;

  syscall_tracker_tracker_proc_dentry = proc_create_data(SYSCALL_TRACKER_PROC,
      S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH,
      NULL, &syscall_tracker_fops, NULL);

  if (!syscall_tracker_tracker_proc_dentry) {
    printk(KERN_ERR "Error creating syscalls tracker control file.\n");
    ret = -ENOMEM;
    goto error;
  }

  printk("Syscalls tracker module loaded successfully.");
  return ret;

error:
  return ret;
}

void syscall_tracker_destroy_proc_priv(void)
{
  if (syscall_tracker_tracker_proc_dentry) {
    remove_proc_entry(SYSCALL_TRACKER_PROC, NULL);
  }
}

long syscall_tracker_ioctl(
    struct file *file, unsigned int cmd, unsigned long arg)
{
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
  default:
    ret = -ENOTSUPP;
    break;
  }

  return ret;
}
