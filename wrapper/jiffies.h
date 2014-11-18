#ifndef _WRAPPER_JIFFIES_H
#define _WRAPPER_JIFFIES_H

/*
 * wrapper/jiffies.h
 *
 * wrapper around jiffies functions and data structures. Using
 * KALLSYMS to get its address when available, else we need to have a
 * kernel that exports this function to GPL modules.
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

#include <linux/jiffies.h>

#ifdef CONFIG_KALLSYMS

#include <linux/kallsyms.h>
#include "kallsyms.h"

static inline
unsigned long wrapper_nsecs_to_jiffies(u64 n)
{
	unsigned long (*wrapper_nsecs_to_jiffies_sym)(u64 n);

	wrapper_nsecs_to_jiffies_sym = (void *) kallsyms_lookup_funcptr("nsecs_to_jiffies");
	if (wrapper_nsecs_to_jiffies_sym) {
		return wrapper_nsecs_to_jiffies_sym(n);
	} else {
		printk(KERN_WARNING "wrapper_nsecs_to_jiffies symbol lookup failed.\n");
		return 0;
	}
}

static inline
unsigned long wrapper_nsecs_to_jiffies64(u64 n)
{
	unsigned long (*wrapper_nsecs_to_jiffies64_sym)(u64 n);

	wrapper_nsecs_to_jiffies64_sym = (void *) kallsyms_lookup_funcptr("nsecs_to_jiffies64");
	if (wrapper_nsecs_to_jiffies64_sym) {
		return wrapper_nsecs_to_jiffies64_sym(n);
	} else {
		printk(KERN_WARNING "wrapper_nsecs_to_jiffies64 symbol lookup failed.\n");
		return 0;
	}
}

#else

static inline
unsigned long wrapper_nsecs_to_jiffies(u64 n)
{
	return nsecs_to_jiffies(n);
}

static inline
unsigned long wrapper_nsecs_to_jiffies64(u64 n)
{
	return nsecs_to_jiffies64(n);
}

#endif /* CONFIG_KALLSYMS */

#endif /* _WRAPPER_JIFFIES_H */
