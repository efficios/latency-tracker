/*
 * offcpu.c
 *
 * Example of usage of latency_tracker with kernel tracepoints.
 *
 * In this example, we call the callback function offcpu_cb when a task has
 * been scheduled out for longer that DEFAULT_USEC_OFFCPU_THRESH microseconds.
 *
 * The 2 parameters can be controlled at run-time by writing the value in
 * micro-seconds in:
 * /sys/module/offcpu/parameters/usec_threshold and
 * /sys/module/offcpu/parameters/usec_timeout
 *
 * It is possible to use nanoseconds, but you have to write manually the value
 * in this source code.
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
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/stacktrace.h>
#include <asm/stacktrace.h>
#include "offcpu.h"
#include "../latency_tracker.h"
#include "../wrapper/tracepoint.h"

#include <trace/events/latency_tracker.h>

/*
 * Threshold to execute the callback (microseconds).
 */
#define DEFAULT_USEC_OFFCPU_THRESH 5 * 1000 * 1000
/*
 * Timeout to execute the callback (microseconds).
 */
#define DEFAULT_USEC_OFFCPU_TIMEOUT 0

#define MAX_STACK_TXT 256

/*
 * microseconds because we can't guarantee the passing of 64-bit
 * arguments to insmod on all architectures.
 */
static unsigned long usec_threshold = DEFAULT_USEC_OFFCPU_THRESH;
module_param(usec_threshold, ulong, 0644);
MODULE_PARM_DESC(usec_threshold, "Threshold in microseconds");

static unsigned long usec_timeout = DEFAULT_USEC_OFFCPU_TIMEOUT;
module_param(usec_timeout, ulong, 0644);
MODULE_PARM_DESC(usec_timeout, "Timeout in microseconds");

struct schedkey {
	pid_t pid;
} __attribute__((__packed__));

enum sched_exitcode {
	SCHED_EXIT_NORMAL = 0,
	SCHED_EXIT_DIED = 1,
};

static struct latency_tracker *tracker;

static int cnt = 0;

static int print_trace_stack(void *data, char *name)
{
        return 0;
}

static void
__save_stack_address(void *data, unsigned long addr, bool reliable, bool nosched)
{
        struct stack_trace *trace = data;
#ifdef CONFIG_FRAME_POINTER
        if (!reliable)
                return;
#endif
        if (nosched && in_sched_functions(addr))
                return;
        if (trace->skip > 0) {
                trace->skip--;
                return;
        }
        if (trace->nr_entries < trace->max_entries)
                trace->entries[trace->nr_entries++] = addr;
}

static void save_stack_address(void *data, unsigned long addr, int reliable)
{
        return __save_stack_address(data, addr, reliable, false);
}

static const struct stacktrace_ops backtrace_ops = {
        .stack                  = print_trace_stack,
        .address                = save_stack_address,
        .walk_stack             = print_context_stack,
};

static
void extract_stack(struct task_struct *p, char *stacktxt, uint64_t delay)
{
	struct stack_trace trace;
	unsigned long entries[32];
	char tmp[48];
	int i, j;
	size_t frame_len;

	//	printk("offcpu: %s (%d) %llu us\n", p->comm, key->pid, delay);
	trace.nr_entries = 0;
	trace.max_entries = ARRAY_SIZE(entries);
	trace.entries = entries;
	trace.skip = 0;
	dump_trace(p, NULL, NULL, 0, &backtrace_ops, &trace);
	//	print_stack_trace(&trace, 0);

	j = 0;
	for (i = 0; i < trace.nr_entries; i++) {
		printk("%pS\n", (void *) trace.entries[i]);
		snprintf(tmp, 48, "%pS ", (void *) trace.entries[i]);
		frame_len = strlen(tmp);
		snprintf(stacktxt + j, MAX_STACK_TXT - j, tmp);
		j += frame_len;
	}
	printk("%s\n%llu\n\n", p->comm, delay/1000);
}

static
void offcpu_cb(unsigned long ptr)
{
	struct latency_tracker_event *data =
		(struct latency_tracker_event *) ptr;
	struct schedkey *key = (struct schedkey *) data->tkey.key;
	struct offcpu_tracker *offcpu_priv =
		(struct offcpu_tracker *) data->priv;
	struct task_struct *p;
	char stacktxt[MAX_STACK_TXT];
	u64 delay;

	if (data->cb_flag != LATENCY_TRACKER_CB_NORMAL)
		return;
	if (data->cb_out_id == SCHED_EXIT_DIED)
		return;

	delay = (data->end_ts - data->start_ts) / 1000;
#ifdef SCHEDWORST
	usec_threshold = delay;
#endif

	rcu_read_lock();
	p = pid_task(find_vpid(key->pid), PIDTYPE_PID);
	if (!p)
		goto end;
	extract_stack(p, stacktxt, delay);
	trace_offcpu_latency(p->comm, key->pid, data->end_ts - data->start_ts,
			data->cb_flag, stacktxt);
	cnt++;
	offcpu_handle_proc(offcpu_priv, data);

end:
	rcu_read_unlock();
}

static
void probe_sched_switch(void *ignore, struct task_struct *prev,
		struct task_struct *next)
{
	struct schedkey key;
	enum latency_tracker_event_in_ret ret;
	u64 thresh, timeout;

	if (!next || !prev)
		return;

	thresh = usec_threshold * 1000;
	timeout = usec_timeout * 1000;

	if (!(prev->flags & PF_KTHREAD)) {
		key.pid = prev->pid;
		ret = latency_tracker_event_in(tracker, &key, sizeof(key),
				thresh, offcpu_cb, timeout, 1,
				latency_tracker_get_priv(tracker));
	}

	if (!(next->flags & PF_KTHREAD)) {
		key.pid = next->pid;
		latency_tracker_event_out(tracker, &key, sizeof(key),
				SCHED_EXIT_NORMAL);
	}
}

static
int __init offcpu_init(void)
{
	int ret;
	struct offcpu_tracker *offcpu_priv;

	offcpu_priv = offcpu_alloc_priv();
	if (!offcpu_priv) {
		ret = -ENOMEM;
		goto end;
	}

	tracker = latency_tracker_create(NULL, NULL, 200, 1000, 100000000, 0,
			offcpu_priv);
	if (!tracker)
		goto error;

	ret = lttng_wrapper_tracepoint_probe_register("sched_switch",
			probe_sched_switch, NULL);
	WARN_ON(ret);

	ret = offcpu_setup_priv(offcpu_priv);
	goto end;

error:
	ret = -1;
end:
	return ret;
}
module_init(offcpu_init);

static
void __exit offcpu_exit(void)
{
	uint64_t skipped;
	struct offcpu_tracker *offcpu_priv;

	lttng_wrapper_tracepoint_probe_unregister("sched_switch",
			probe_sched_switch, NULL);
	tracepoint_synchronize_unregister();
	skipped = latency_tracker_skipped_count(tracker);
	offcpu_priv = latency_tracker_get_priv(tracker);
	offcpu_destroy_priv(offcpu_priv);
	latency_tracker_destroy(tracker);
	printk("Missed events : %llu\n", skipped);
	printk("Total sched alerts : %d\n", cnt);
}
module_exit(offcpu_exit);

MODULE_AUTHOR("Julien Desfossez <jdesfossez@efficios.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
