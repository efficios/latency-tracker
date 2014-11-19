/*
 * sched_latency_tp.c
 *
 * Example of usage of latency_tracker with kernel tracepoints.
 * In this example, we call the callback function sched_cb when the delay
 * between a sched wakeup and its completion (sched_switch) takes more than
 * SCHED_LATENCY_THRESH nanoseconds. Moreover, if the task is still not scheduled
 * after SCHED_LATENCY_TIMEOUT nanoseconds, the callback is called with timeout = 1.
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

#include <linux/module.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include "sched_latency_tp.h"
#include "../latency_tracker.h"

#define CREATE_TRACE_POINTS
#include <trace/events/latency_tracker.h>

/*
 * Threshold to execute the callback (nanoseconds).
 */
#define SCHED_LATENCY_THRESH 5 * 1000000
/*
 * Timeout to execute the callback (nanoseconds).
 */
#define SCHED_LATENCY_TIMEOUT 0 * 1000000

struct schedkey {
	pid_t pid;
} __attribute__((__packed__));

struct latency_tracker *tracker;

static int cnt = 0;

void sched_cb(unsigned long ptr, unsigned int timeout)
{
	struct latency_tracker_event *data =
		(struct latency_tracker_event *) ptr;
	struct schedkey *key = (struct schedkey *) data->key;

	trace_sched_latency(key->pid, data->end_ts - data->start_ts);
	cnt++;
}

static
void probe_sched_wakeup(void *ignore, struct task_struct *p, int success)
{
	struct schedkey key;

	if (!p || !p->pid)
		return;

	key.pid = p->pid;
	latency_tracker_event_in(tracker, &key, sizeof(key),
		SCHED_LATENCY_THRESH, sched_cb, SCHED_LATENCY_TIMEOUT,
		NULL);
}

static
void probe_sched_switch(void *ignore, struct task_struct *prev,
		struct task_struct *next)
{
	struct schedkey key;

	if (!next || !next->pid)
		return;

	key.pid = next->pid;
	latency_tracker_event_out(tracker, &key, sizeof(key));
}

static
int __init sched_latency_tp_init(void)
{
	int ret;

	tracker = latency_tracker_create(NULL, NULL, 100);
	if (!tracker)
		goto error;

	ret = tracepoint_probe_register("sched_wakeup",
			probe_sched_wakeup, NULL);
	WARN_ON(ret);

	ret = tracepoint_probe_register("sched_switch",
			probe_sched_switch, NULL);
	WARN_ON(ret);

	ret = 0;
	goto end;

error:
	ret = -1;
end:
	return ret;
}
module_init(sched_latency_tp_init);

static
void __exit sched_latency_tp_exit(void)
{
	tracepoint_probe_unregister("sched_wakeup",
			probe_sched_wakeup, NULL);
	tracepoint_probe_unregister("sched_switch",
			probe_sched_switch, NULL);
	tracepoint_synchronize_unregister();
	latency_tracker_destroy(tracker);
	printk("Total sched alerts : %d\n", cnt);
}
module_exit(sched_latency_tp_exit);

MODULE_AUTHOR("Julien Desfossez <jdesfossez@efficios.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
