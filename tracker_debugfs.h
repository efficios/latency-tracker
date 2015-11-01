#if !defined(LATENCY_DEBUGFS_H)
#define LATENCY_DEBUGFS_H

/*
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

#include "latency_tracker.h"

/*
 * debugfs structure:
 * root: /sys/kernel/debug/latency
 * each tracker create its own directory below that.
 */

int latency_tracker_debugfs_setup(void);
void latency_tracker_debugfs_cleanup(void);

int latency_tracker_debugfs_add_tracker(
		struct latency_tracker *tracker);
int latency_tracker_debugfs_default_entries(struct latency_tracker *tracker);
struct dentry *latency_tracker_debugfs_add_subfolder(
		struct latency_tracker *tracker,
		const char *name);
void latency_tracker_debugfs_remove_tracker(struct latency_tracker
		*tracker);

#endif /* LATENCY_DEBUGFS_H */
