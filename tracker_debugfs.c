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

#include <linux/debugfs.h>
#include "tracker_debugfs.h"

#define DEBUGFSNAME "latency"

static struct dentry *debugfs_root;

int latency_tracker_debugfs_setup(void)
{
	debugfs_root = debugfs_create_dir(DEBUGFSNAME, NULL);
	if (!debugfs_root)
		goto error;

	return 0;

error:
	return -1;
}

struct dentry *latency_tracker_debugfs_add_tracker(
		const char *name)
{
	return debugfs_create_dir(name, debugfs_root);
}

void latency_tracker_debugfs_remove_tracker(struct dentry *dir)
{
	if (!dir)
		return;
	debugfs_remove_recursive(dir);
}

void latency_tracker_debugfs_cleanup(void)
{
	debugfs_remove_recursive(debugfs_root);
}
