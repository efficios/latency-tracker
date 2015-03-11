#ifndef _LTTNG_WRAPPER_SYSCALL_NAME_H
#define _LTTNG_WRAPPER_SYSCALL_NAME_H

/*
 * wrapper/syscall_name.h
 *
 * Copyright (C) 2015 Julien Desfossez <julien.desfossez@efficios.com>
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
const char *wrapper_kallsyms_lookup(unsigned long addr,
		unsigned long *symbolsize,
		unsigned long *offset,
		char **modname, char *namebuf)
{
	const char *(*kallsyms_lookup_sym)(unsigned long addr,
			unsigned long *symbolsize,
			unsigned long *offset,
			char **modname, char *namebuf);

	kallsyms_lookup_sym = (void *) kallsyms_lookup_funcptr("kallsyms_lookup");
	if (kallsyms_lookup_sym) {
		return kallsyms_lookup_sym(addr, symbolsize, offset, modname,
				namebuf);
	} else {
		return NULL;
	}
}

static inline
unsigned long wrapper_sys_call_table(int nr)
{
	unsigned long *sys_call_table_sym;

	sys_call_table_sym = (void *) kallsyms_lookup_dataptr("sys_call_table");
	if (sys_call_table_sym) {
		return (unsigned long) sys_call_table_sym[nr];
	} else {
		return 0;
	}
}

static inline
int wrapper_get_syscall_name(int nr, char *buf)
{
	unsigned long addr;

	addr = wrapper_sys_call_table(nr);
	if (!addr)
		return -1;
	wrapper_kallsyms_lookup(addr, NULL, NULL, NULL, buf);
	return 0;
}
#else

#include <linux/vmalloc.h>

static inline
void wrapper_kallsyms_lookup(unsigned long addr,
		unsigned long *symbolsize,
		unsigned long *offset,
		char **modname, char *namebuf)
{
	return NULL;
}

static inline
unsigned long wrapper_sys_call_table(int nr)
{
	return 0;
}

static inline
int wrapper_get_syscall_name(int nr, char *buf)
{
	return -1;
}
#endif

#endif /* _LTTNG_WRAPPER_SYSCALL_NAME_H */
