#ifndef _LTTNG_WRAPPER_PRIO_H
#define _LTTNG_WRAPPER_PRIO_H

/*
 * wrapper/vmalloc.h
 *
 * wrapper around vmalloc_sync_all. Using KALLSYMS to get its address when
 * available, else we need to have a kernel that exports this function to GPL
 * modules.
 *
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
int wrapper_task_prio(struct task_struct *t)
{
	int (*wrapper_task_prio_sym)(struct task_struct *t);

	wrapper_task_prio_sym = (void *) kallsyms_lookup_funcptr("task_prio");
	if (!wrapper_task_prio_sym) {
		printk(KERN_WARNING "LTTng: task_prio symbol lookup failed.\n");
		return -EINVAL;
	}
	return wrapper_task_prio_sym(t);
}

#else
static inline
int wrapper_task_prio(struct task_struct *t)
{
	return -EINVAL;
}
#endif

#endif /* _LTTNG_WRAPPER_PRIO_H */
