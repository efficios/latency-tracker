#ifndef _LTTNG_WRAPPER_SCHED_H
#define _LTTNG_WRAPPER_SCHED_H

/*
 * wrapper/sched.h
 *
 * wrapper around sched.h functions. Using KALLSYMS to get its address when
 * available, else we need to have a kernel that exports this function to GPL
 * modules.
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

#ifdef CONFIG_KALLSYMS

#include <linux/kallsyms.h>
#include "kallsyms.h"

static inline
struct task_struct *wrapper_curr_task(int cpu)
{
	struct task_struct * (*curr_task_sym)(int cpu);

	curr_task_sym = (void *) kallsyms_lookup_funcptr("curr_task");
	if (curr_task_sym) {
		return curr_task_sym(cpu);
	} else {
		printk(KERN_WARNING "curr_task look up failed through kallsyms.\n");
		return NULL;
	}
}
#else

#include <linux/sched.h>

static inline
struct task_struct *wrapper_curr_task(int cpu)
{
	return curr_task(cpu);
}
#endif

#endif /* _LTTNG_WRAPPER_SCHED_H */
