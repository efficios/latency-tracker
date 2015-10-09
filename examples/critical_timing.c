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

#include <trace/events/latency_tracker.h>

#define MAX_STACK_TXT 256

struct critical_timing_tracker *critical_timing_priv;

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
	dump_trace(p, NULL, NULL, 0, &backtrace_ops, &trace);
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

static
void probe_core_critical_timing_hit(void *ignore, unsigned long ip,
		unsigned long parent_ip, unsigned long flags, int preempt_cnt,
		cycles_t delta_ns)
{
	struct task_struct *p = current;
	char stacktxt[MAX_STACK_TXT];
	u64 end_ts = trace_clock_monotonic_wrapper();

	rcu_read_lock();
	extract_stack(p, stacktxt, 0);
	trace_latency_tracker_critical_timing_stack(current->comm, current->pid, stacktxt);
	cnt++;
	critical_timing_handle_proc(critical_timing_priv, end_ts);
	rcu_read_unlock();
}

static
int __init critical_timing_init(void)
{
	int ret;

	critical_timing_priv = critical_timing_alloc_priv();
	if (!critical_timing_priv) {
		ret = -ENOMEM;
		goto end;
	}

	ret = lttng_wrapper_tracepoint_probe_register("core_critical_timing_hit",
			probe_core_critical_timing_hit, NULL);
	WARN_ON(ret);

	ret = critical_timing_setup_priv(critical_timing_priv);
	WARN_ON(ret);

	goto end;

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
	critical_timing_destroy_priv(critical_timing_priv);
	printk("Total critical_timing alerts : %d\n", cnt);
}
module_exit(critical_timing_exit);

MODULE_AUTHOR("Julien Desfossez <jdesfossez@efficios.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
