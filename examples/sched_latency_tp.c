/*
 * sched_latency_tp.c
 *
 * Example of usage of latency_tracker with kernel tracepoints.
 *
 * In this example, we call the callback function sched_cb when the delay
 * between a sched wakeup and its completion (sched_switch) takes more than
 * DEFAULT_USEC_SCHED_LATENCY_THRESH microseconds. Moreover, if the task is
 * still not scheduled after DEFAULT_USEC_SCHED_LATENCY_TIMEOUT microseconds,
 * the callback is called with timeout = 1.
 *
 * The 2 parameters can be controlled at run-time by writing the value in
 * micro-seconds in:
 * /sys/module/sched_latency_tp/parameters/usec_threshold and
 * /sys/module/sched_latency_tp/parameters/usec_timeout
 *
 * It is possible to use nanoseconds, but you have to write manually the value
 * in this source code.
 *
 * Copyright (C) 2014 Julien Desfossez <jdesfossez@efficios.com>
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
#include <linux/fs.h>
#include <linux/sched.h>
#include "sched_latency_tp.h"
#include "../latency_tracker.h"
#include "../wrapper/tracepoint.h"

#include <trace/events/latency_tracker.h>

/*
 * Threshold to execute the callback (microseconds).
 */
#define DEFAULT_USEC_SCHED_LATENCY_THRESH 5 * 1000
/*
 * Timeout to execute the callback (microseconds).
 */
#define DEFAULT_USEC_SCHED_LATENCY_TIMEOUT 0

static pid_t current_pid[NR_CPUS];

/*
 * microseconds because we can't guarantee the passing of 64-bit
 * arguments to insmod on all architectures.
 */
static unsigned long usec_threshold = DEFAULT_USEC_SCHED_LATENCY_THRESH;
module_param(usec_threshold, ulong, 0644);
MODULE_PARM_DESC(usec_threshold, "Threshold in microseconds");

static unsigned long usec_timeout = DEFAULT_USEC_SCHED_LATENCY_TIMEOUT;
module_param(usec_timeout, ulong, 0644);
MODULE_PARM_DESC(usec_timeout, "Timeout in microseconds");

struct schedkey {
	pid_t pid;
} __attribute__((__packed__));

static struct latency_tracker *tracker;

static int cnt = 0;

static
void sched_cb(unsigned long ptr)
{
	struct latency_tracker_event *data =
		(struct latency_tracker_event *) ptr;
	struct schedkey *key = (struct schedkey *) data->tkey.key;

	trace_sched_latency(key->pid, data->end_ts - data->start_ts,
			data->cb_flag);
	cnt++;
}

static
void probe_sched_wakeup(void *ignore, struct task_struct *p, int success)
{
	struct schedkey key;
	u64 thresh, timeout;
	int i;
	enum latency_tracker_event_in_ret ret;

	if (!p || !p->pid)
		return;

	/*
	 * Make sure we won't wait for a process already running on another CPU.
	 */
	for (i = 0; i < NR_CPUS; i++) {
		if (current_pid[i] == p->pid)
			return;
	}
	key.pid = p->pid;
	thresh = usec_threshold * 1000;
	timeout = usec_timeout * 1000;

	ret = latency_tracker_event_in(tracker, &key, sizeof(key),
		thresh, sched_cb, timeout, 0,
		NULL);
	if (ret == LATENCY_TRACKER_FULL) {
		printk("latency_tracker sched: no more free events, consider "
				"increasing the max_events parameter\n");
	} else if (ret) {
		printk("latency_tracker sched: error adding event\n");
	}
}

static
void probe_sched_switch(void *ignore, struct task_struct *prev,
		struct task_struct *next)
{
	struct schedkey key;

	if (!next || !next->pid)
		return;

	current_pid[prev->on_cpu] = next->pid;

	key.pid = next->pid;
	latency_tracker_event_out(tracker, &key, sizeof(key), 0);
}

static
int __init sched_latency_tp_init(void)
{
	int ret;

	tracker = latency_tracker_create(NULL, NULL, 2048, 0, 0,
			NULL);
	if (!tracker)
		goto error;

	ret = lttng_wrapper_tracepoint_probe_register("sched_wakeup",
			probe_sched_wakeup, NULL);
	WARN_ON(ret);

	ret = lttng_wrapper_tracepoint_probe_register("sched_switch",
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
	lttng_wrapper_tracepoint_probe_unregister("sched_wakeup",
			probe_sched_wakeup, NULL);
	lttng_wrapper_tracepoint_probe_unregister("sched_switch",
			probe_sched_switch, NULL);
	tracepoint_synchronize_unregister();
	latency_tracker_destroy(tracker);
	printk("Total sched alerts : %d\n", cnt);
}
module_exit(sched_latency_tp_exit);

MODULE_AUTHOR("Julien Desfossez <jdesfossez@efficios.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
