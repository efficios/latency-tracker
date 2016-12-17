/*
 * critical_timing.c
 *
 * Example of usage of latency_tracker with kernel tracepoints.
 *
 * In this example, we call the callback function critical_timing_cb when the
 * core_critical_timing_hit is called.
 *
 * Copyright (C) 2015 Julien Desfossez <jdesfossez@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; only version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/jhash.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/stacktrace.h>
#include <asm/stacktrace.h>
#include "critical_timing.h"
#include "../latency_tracker.h"
#include "../wrapper/tracepoint.h"
#include "../wrapper/trace-clock.h"
#include "../wrapper/lt_probe.h"
#include "../tracker_debugfs.h"

#include <trace/events/latency_tracker.h>

#define MAX_STACK_TXT 256

static struct latency_tracker *tracker;

static int cnt = 0;

static
void extract_stack(struct task_struct *p, char *stacktxt, int skip)
{
	struct stack_trace trace;
	unsigned long entries[32];
	char tmp[48];
	int i, j;
	size_t frame_len;

	trace.nr_entries = 0;
	trace.max_entries = ARRAY_SIZE(entries);
	trace.entries = entries;
	trace.skip = 0;

	save_stack_trace(&trace);

	//	print_stack_trace(&trace, 0);

	j = 0;
	for (i = 0; i < trace.nr_entries; i++) {
		if (i < skip)
			continue;
		snprintf(tmp, 48, "%pS\n", (void *) trace.entries[i]);
		frame_len = strlen(tmp);
		snprintf(stacktxt + j, MAX_STACK_TXT - j, tmp);
		j += frame_len;
		if (MAX_STACK_TXT - j < 0)
			return;
	}
}

LT_PROBE_DEFINE(core_critical_timing_hit, unsigned long ip,
		unsigned long parent_ip, unsigned long flags, int preempt_cnt,
		cycles_t delta_ns)
{
	struct task_struct *p = current;
	char stacktxt[MAX_STACK_TXT];

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	rcu_read_lock();
	extract_stack(p, stacktxt, 0);
	trace_latency_tracker_critical_timing_stack(current->comm, current->pid, stacktxt);
	cnt++;
	latency_tracker_debugfs_wakeup_pipe(tracker);
	rcu_read_unlock();
}

static
int __init critical_timing_init(void)
{
	int ret;

	tracker = latency_tracker_create("critical_timings");
	if (!tracker)
		goto error;
	latency_tracker_debugfs_setup_wakeup_pipe(tracker);

	ret = lttng_wrapper_tracepoint_probe_register("core_critical_timing_hit",
			probe_core_critical_timing_hit, NULL);
	WARN_ON(ret);

	goto end;

error:
	ret = -1;
end:
	return ret;
}
module_init(critical_timing_init);

static
void __exit critical_timing_exit(void)
{
	lttng_wrapper_tracepoint_probe_unregister("core_critical_timing_hit",
			probe_core_critical_timing_hit, NULL);
	tracepoint_synchronize_unregister();
	latency_tracker_destroy(tracker);
	printk("Total critical_timing alerts : %d\n", cnt);
}
module_exit(critical_timing_exit);

MODULE_AUTHOR("Julien Desfossez <jdesfossez@efficios.com>");
MODULE_LICENSE("GPL and additional rights");
MODULE_VERSION("1.0");
