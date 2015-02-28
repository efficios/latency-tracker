#ifndef _TP_BLOCK_LATENCY_H
#define _TP_BLOCK_LATENCY_H

/*
 * block_latency_tp.h
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

#include <linux/tracepoint.h>
#include <linux/blkdev.h>

DECLARE_TRACE(sched_switch,
	TP_PROTO(struct task_struct *prev, struct task_struct *next),
	TP_ARGS(prev, next));

#endif /* _TP_BLOCK_LATENCY_H */
