/*
 * latency_tracker_begin_end.c
 *
 * Expose two files to track user-space begin and end events
 *
 * Most/all of the code comes from probes/lttng.c in lttng-modules.
 *
 * Copyright (C) 2008-2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <linux/module.h>
#include <linux/tracepoint.h>
#include <linux/uaccess.h>
#include <linux/gfp.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/mm.h>

#include "wrapper/vmalloc.h"
#include <trace/events/latency_tracker.h>

#define LT_BEGIN_FILE	"latency-tracker-begin"
#define LT_END_FILE	"latency-tracker-end"

static struct proc_dir_entry *lt_begin_dentry, *lt_end_dentry;

/**
 * lttng_logger_write - write a userspace string into the trace system
 * @file: file pointer
 * @user_buf: user string
 * @count: length to copy
 * @ppos: file position
 * @begin: emit the "begin" (1) or "end" (0) tracepoint
 *
 * Copy a userspace string into a trace event named "lttng:logger".
 * Copies at most @count bytes into the event "msg" dynamic array.
 * Truncates the count at LT_MAX_JOBID_SIZE. Returns the number of
 * bytes copied from the source.
 * Return -1 on error, with EFAULT errno.
 */
static
ssize_t lttng_logger_write(struct file *file, const char __user *user_buf,
		    size_t count, loff_t *ppos, int begin)
{
	unsigned int nr_pages = 1, i;
	unsigned long uaddr = (unsigned long) user_buf;
	struct page *pages[2];
	ssize_t written;
	int ret;

	/* Truncate count */
	if (unlikely(count > LT_MAX_JOBID_SIZE))
		count = LT_MAX_JOBID_SIZE;

	/* How many pages are we dealing with ? */
	if (unlikely((uaddr & PAGE_MASK) != ((uaddr + count) & PAGE_MASK)))
		nr_pages = 2;

	/* Pin userspace pages */
	ret = get_user_pages_fast(uaddr, nr_pages, 0, pages);
	if (unlikely(ret < nr_pages)) {
		if (ret > 0) {
			BUG_ON(ret != 1);
			put_page(pages[0]);
		}
		written = -EFAULT;
		goto end;
	}

	/* Trace the event */
	if (begin)
		trace_latency_tracker_begin(user_buf, count);
	else
		trace_latency_tracker_end(user_buf, count);
	written = count;
	*ppos += written;

	for (i = 0; i < nr_pages; i++)
		put_page(pages[i]);
end:
	return written;
}

static
ssize_t lt_begin_write(struct file *file, const char __user *user_buf,
		    size_t count, loff_t *ppos)
{
	return lttng_logger_write(file, user_buf, count, ppos, 1);
}

static
ssize_t lt_end_write(struct file *file, const char __user *user_buf,
		    size_t count, loff_t *ppos)
{
	return lttng_logger_write(file, user_buf, count, ppos, 0);
}

static const struct file_operations lt_begin_operations = {
	.write = lt_begin_write,
};

static const struct file_operations lt_end_operations = {
	.write = lt_end_write,
};

int __init lttng_logger_init(void)
{
	int ret = 0;

	wrapper_vmalloc_sync_all();
	lt_begin_dentry = proc_create_data(LT_BEGIN_FILE,
				S_IRUGO | S_IWUGO, NULL,
				&lt_begin_operations, NULL);
	if (!lt_begin_dentry) {
		printk(KERN_ERR "Error creating latency-tracker begin file\n");
		ret = -ENOMEM;
		goto error;
	}
	lt_end_dentry = proc_create_data(LT_END_FILE,
				S_IRUGO | S_IWUGO, NULL,
				&lt_end_operations, NULL);
	if (!lt_end_dentry) {
		printk(KERN_ERR "Error creating latency-tracker end file\n");
		ret = -ENOMEM;
		goto error2;
	}
	return ret;

error2:
	remove_proc_entry(LT_BEGIN_FILE, NULL);
error:
	return ret;
}

void __exit lttng_logger_exit(void)
{
	if (lt_begin_dentry)
		remove_proc_entry(LT_BEGIN_FILE, NULL);
	if (lt_end_dentry)
		remove_proc_entry(LT_END_FILE, NULL);
}

module_init(lttng_logger_init);
module_exit(lttng_logger_exit);
MODULE_AUTHOR("Julien Desfossez <jdesfossez@efficios.com>");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL");
