#ifndef _URCU_ARCH_UATOMIC_LINUX_H
#define _URCU_ARCH_UATOMIC_LINUX_H

/* 
 * Copyright (c) 1991-1994 by Xerox Corporation.  All rights reserved.
 * Copyright (c) 1996-1999 by Silicon Graphics.  All rights reserved.
 * Copyright (c) 1999-2004 Hewlett-Packard Development Company, L.P.
 * Copyright (c) 2009      Mathieu Desnoyers
 *
 * THIS MATERIAL IS PROVIDED AS IS, WITH ABSOLUTELY NO WARRANTY EXPRESSED
 * OR IMPLIED.  ANY USE IS AT YOUR OWN RISK.
 *
 * Permission is hereby granted to use or copy this program
 * for any purpose,  provided the above notices are retained on all copies.
 * Permission to modify the code and to distribute modified code is granted,
 * provided the above notices are retained, and a notice that the code was
 * modified is included with the above copyright notice.
 *
 * Code inspired from libuatomic_ops-1.2, inherited in part from the
 * Boehm-Demers-Weiser conservative garbage collector.
 */

#include "compiler.h"
#include "system.h"
#include <asm/cmpxchg.h>

#define UATOMIC_HAS_ATOMIC_BYTE
#define UATOMIC_HAS_ATOMIC_SHORT

#ifdef __cplusplus
extern "C" {
#endif 

#define uatomic_cmpxchg(addr, old, _new)				      \
	cmpxchg(addr, old, _new)

/* xchg */
#define uatomic_xchg(addr, v)						      \
	xchg(addr, v)

#ifdef __cplusplus 
}
#endif

#include "uatomic-generic.h"

#endif /* _URCU_ARCH_UATOMIC_LINUX_H */
