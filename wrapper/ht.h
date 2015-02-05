#ifndef _LTTNG_WRAPPER_HT_H
#define _LTTNG_WRAPPER_HT_H

/*
 * wrapper/ht.h
 *
 * wrapper around hash table implementation to use.
 *
 * Copyright (C) 2014-2015 Julien Desfossez <jdesfossez@efficios.com>
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

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0))
//#define RHASHTABLE
#define URCUHT
#endif
#include <linux/jhash.h>

#include "../latency_tracker.h"
#include "../tracker_private.h"

//#ifdef RHASHTABLE
//#include "ht-rhashtable.h"
//#elif defined URCUHT /* RHASHTABLE */
#include "ht-urcuht.h"
//#else
//#include "ht-base.h"
//#endif /* RHASHTABLE */

#endif /* _LTTNG_WRAPPER_HT_H */
