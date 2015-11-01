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
#include "latency_tracker.h"
#include "tracker_private.h"

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

void latency_tracker_debugfs_cleanup(void)
{
	debugfs_remove_recursive(debugfs_root);
}

int setup_default_entries(struct latency_tracker *tracker)
{
	struct dentry *dir;

	dir = debugfs_create_u64("threshold", S_IRUSR|S_IWUSR,
			tracker->debugfs_dir, &tracker->threshold);
	if (!dir)
		goto error;
	dir = debugfs_create_u64("timeout", S_IRUSR|S_IWUSR,
			tracker->debugfs_dir, &tracker->timeout);
	if (!dir)
		goto error;

	return 0;
error:
	return -1;
}


int latency_tracker_debugfs_add_tracker(
		struct latency_tracker *tracker)
{
	struct dentry *dir;
	int ret;

	dir = debugfs_create_dir(tracker->tracker_name, debugfs_root);
	if (!dir)
		goto error;
	tracker->debugfs_dir = dir;

	ret = setup_default_entries(tracker);
	if (ret != 0)
		goto error_cleanup;

	return 0;

error_cleanup:
	latency_tracker_debugfs_remove_tracker(tracker);

error:
	return -1;
}

void latency_tracker_debugfs_remove_tracker(struct latency_tracker *tracker)
{
	if (!tracker->debugfs_dir)
		return;
	debugfs_remove_recursive(tracker->debugfs_dir);
}

struct dentry *latency_tracker_debugfs_add_subfolder(
		struct latency_tracker *tracker, const char *name)
{
	struct dentry *dir;

	if (!tracker->debugfs_dir)
		goto error;

	dir = debugfs_create_dir(name, tracker->debugfs_dir);
	if (!dir)
		goto error;

	return dir;

error:
	return NULL;
}
