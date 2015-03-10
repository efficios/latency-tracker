
/*
 * Copyright (C) 2015 Francois Doray <francois.doray@gmail.com>
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
 *
 * Inspired from https://github.com/giraldeau/perfuser, by Francis Giraldeau.
 */
#ifndef SYSCALLS_TRACKER_ABI_H_
#define SYSCALLS_TRACKER_ABI_H_

#define SYSCALL_TRACKER_PROC "syscalls"
#define SYSCALL_TRACKER_PATH "/proc/" SYSCALLS_TRACKER_PROC

enum syscall_module_cmd {
  SYSCALL_TRACKER_MODULE_REGISTER = 0,
  SYSCALL_TRACKER_MODULE_UNREGISTER = 1,  
};

/*
 * Structure to send messages to the kernel module.
 */
struct syscall_tracker_module_msg {
  int cmd;                 /* Command */
} __attribute__((packed));

/*
 * Borrow some unused range of LTTng ioctl ;-).
 */
#define SYSCALLS_TRACKER_IOCTL  _IO(0xF6, 0x90)

#endif  // SYSCALLS_TRACKER_ABI_H_
