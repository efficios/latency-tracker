#ifndef _URCU_ARCH_LINUX_H
#define _URCU_ARCH_LINUX_H

/*
 * arch_linux.h: trivial definitions for the Linux kernel
 *
 * Copyright (c) 2009 Paul E. McKenney, IBM Corporation.
 * Copyright (c) 2009 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "compiler.h"

#include <asm/processor.h>

#ifdef __cplusplus
extern "C" {
#endif 

#define CAA_CACHE_LINE_SIZE	CACHE_LINE_SIZE

#define cmm_mb()    mb()

#define cmm_rmb()     rmb()
#define cmm_wmb()     wmb()
#define cmm_smp_rmb() smp_rmb()
#define cmm_smp_wmb() smp_wmb()

#define caa_cpu_relax()	cpu_relax()

#ifdef __cplusplus 
}
#endif

#include "urcu-arch-generic.h"

#endif /* _URCU_ARCH_LINUX_H */
