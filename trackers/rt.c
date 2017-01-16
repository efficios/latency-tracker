/*
 * rt.c
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
#include <linux/kprobes.h>
#include <linux/kernel.h>
#include <linux/debugfs.h>
#include <asm/stacktrace.h>
#include "../latency_tracker.h"
#include "../tracker_debugfs.h"
#include "../wrapper/tracepoint.h"
#include "../wrapper/trace-clock.h"
#include "../wrapper/task_prio.h"
#include "../wrapper/lt_probe.h"
#include "../wrapper/vmalloc.h"
//#include "../measure.h"
#include "../lt-kernel-version.h"

//#define BENCH
#ifdef BENCH
#include "../measure.h"
#endif

#include <trace/events/latency_tracker.h>

//#define DEBUG 1
#undef DEBUG

/*
 * Threshold to execute the callback (microseconds).
 */
#define DEFAULT_USEC_RT_THRESH 5 * 1000 * 1000
/*
 * Timeout to execute the callback (microseconds).
 */
#define DEFAULT_USEC_RT_TIMEOUT 0

#define DEFAULT_TIMER_TRACING 1

/*
 * On x86, if we have kretprobes, we can use it to hook on the do_IRQ function
 * and get closer to the interrupts entry point. For other architectures or
 * when kretprobes is not available, we fallback to the irq_handler_entry
 * tracepoint.
 */
#if defined(CONFIG_KRETPROBES) && (defined(__x86_64__) || defined(__i386__))
#define DO_IRQ_KRETPROBE
#endif

/*
 * microseconds because we can't guarantee the passing of 64-bit
 * arguments to insmod on all architectures.
 */
static unsigned long usec_threshold = DEFAULT_USEC_RT_THRESH;
module_param(usec_threshold, ulong, 0644);
MODULE_PARM_DESC(usec_threshold, "Threshold in microseconds");

static unsigned long usec_timeout = DEFAULT_USEC_RT_TIMEOUT;
module_param(usec_timeout, ulong, 0644);
MODULE_PARM_DESC(usec_timeout, "Timeout in microseconds");

static unsigned long timer_tracing = DEFAULT_TIMER_TRACING;
module_param(timer_tracing, ulong, 0644);
MODULE_PARM_DESC(timer_tracing, "Enable/Disable tracing of timer interrupts "
		"and hrtimer latency");

static struct latency_tracker *tracker;

static int cnt = 0;
static int tracker_aborted = 0;

struct tracker_config {
	/* enable/disable tracing of local_timer and hrtimer events */
	int timer_tracing;
	/* enable/disable tracing of do_IRQ and irq_handler_* */
	int irq_tracing;
	/* irq number to track (-1 for all) */
	int irq_filter;
	/* softirq number to track (-1 for all) */
	int softirq_filter;
	/* output an event when a woken up task gets blocked */
	int output_switch_out_blocked;
	/* output an event when a target process write to the work_done file */
	int out_work_done;
	/* append in the payload of the event the breakdown (costly). */
	int text_breakdown;
	/* maximum number of duplicate we allow iterating over before aborting. */
	int nr_duplicates_max;
	/*
	 * output an event and stop the tracking as soon as a chain of
	 * event results in a user-space entry.
	 */
	int enter_userspace;
	char procname_filter[TASK_COMM_LEN];
	int procname_filter_size;
};

static
struct tracker_config config  = {
	.timer_tracing = 0,
	.irq_tracing = 1,
	.irq_filter = -1,
	.softirq_filter = -1,
	.output_switch_out_blocked = 1,
	.out_work_done = 1,
	.text_breakdown = 0,
	.enter_userspace = 1,
	.procname_filter_size = 0,
	.nr_duplicates_max = 10,
};

enum rt_key_type {
	KEY_DO_IRQ = 0,
	KEY_HARDIRQ = 1,
	KEY_RAISE_SOFTIRQ = 2,
	KEY_SOFTIRQ = 3,
	KEY_WAKEUP = 4,
	KEY_SWITCH = 5,
	KEY_TIMER_INTERRUPT = 6,
	KEY_HRTIMER = 7,
	KEY_WORK_BEGIN = 8,
	KEY_WORK_DONE = 9,
};

enum event_out_types {
	OUT_IRQHANDLER_NO_CB = 0,
	OUT_SWITCH_BLOCKED = 1,
	OUT_ENTER_USERSPACE = 2,
	OUT_WORK_DONE = 3,
	OUT_NO_CB = 4,
};

struct generic_key_t {
	enum rt_key_type type;
} __attribute__((__packed__));

struct do_irq_key_t {
	struct generic_key_t p;
	unsigned int cpu;
} __attribute__((__packed__));

struct local_timer_key_t {
	struct generic_key_t p;
	unsigned int cpu;
} __attribute__((__packed__));

struct hrtimer_key_t {
	struct generic_key_t p;
	unsigned int cpu;
} __attribute__((__packed__));

struct hardirq_key_t {
	struct generic_key_t p;
	unsigned int cpu;
} __attribute__((__packed__));

struct raise_softirq_key_t {
	struct generic_key_t p;
	unsigned int cpu;
	unsigned int vector;
} __attribute__((__packed__));

struct softirq_key_t {
	struct generic_key_t p;
	unsigned int cpu;
	int pid;
} __attribute__((__packed__));

struct waking_key_t {
	struct generic_key_t p;
	int cpu;
	int pid;
} __attribute__((__packed__));

struct switch_key_t {
	struct generic_key_t p;
	int cpu;
	int pid;
} __attribute__((__packed__));

struct work_begin_key_t {
	struct generic_key_t p;
	char cookie[LT_MAX_JOBID_SIZE];
	int cookie_size;
} __attribute__((__packed__));

/* Keep up-to-date with a list of all key structs. */
union max_key_size {
	struct do_irq_key_t do_irq_key;
	struct local_timer_key_t local_timer_key;
	struct hrtimer_key_t hrtimer_key;
	struct hardirq_key_t hardirq_key_t;
	struct raise_softirq_key_t raise_softirq_key;
	struct softirq_key_t softirq_key;
	struct waking_key_t waking_key;
	struct switch_key_t switch_key;
	struct work_begin_key_t work_begin_key;
};

#undef MAX_KEY_SIZE
#define MAX_KEY_SIZE sizeof(union max_key_size)

#if !defined(MAX_FILTER_STR_VAL)
#define MAX_FILTER_STR_VAL 256
#endif

#define MAX_PAYLOAD (4 * MAX_FILTER_STR_VAL)

struct event_data {
	char breakdown[MAX_PAYLOAD];
	char userspace_proc[TASK_COMM_LEN + 1];
	u64 enter_userspace_ts;
	u64 prev_ts;
	unsigned int pos;
	int irq;
	unsigned int preempt_count;
	union {
		/*
		 * When the event is a child event (not the origin).
		 * Is this event the tip of a relevant branch ?
		 * 0 : unknown
		 * 1 : yes
		 */
		unsigned int good_branch;
		/*
		 * When the event is the origin event, flag to inform
		 * the child branches if the relevant branch has been
		 * identified.
		 * 0 : no
		 * 1 : yes
		 */
		unsigned int good_branch_found;
	} u;
	/*
	 * Final flag in the root to inform all branches to complete
	 * regardless of their good_branch flag. This protects the case where
	 * a branch completes even if it was not flagged as good (work_done
	 * without work_begin).
	 */
	unsigned int tree_closed;
	struct latency_tracker_event *root;
} __attribute__((__packed__));

static
void append_delta_ts(struct latency_tracker_event *s, enum rt_key_type type,
		char *txt, u64 ts, int field1, char *field2, int field3)
{
	u64 now;
	struct event_data *data;
	char tmp[64];
	size_t len;
	uint64_t last_ts;
	char buf[32];

	if (ts)
		now = ts;
	else
		now = trace_clock_monotonic_wrapper();
	data = (struct event_data *) latency_tracker_event_get_priv_data(s);
	if (!data) {
		BUG_ON(1);
		return;
	}
	last_ts = data->prev_ts;
	data->prev_ts = now;

	if (!config.text_breakdown)
		return;

	if (data->pos == MAX_PAYLOAD)
		return;

	switch (type) {
	case KEY_DO_IRQ:
		snprintf(tmp, 64, "%s [%03d] = %llu, ", txt, smp_processor_id(),
				now - last_ts);
		break;
	case KEY_HARDIRQ:
	case KEY_RAISE_SOFTIRQ:
	case KEY_SOFTIRQ:
	case KEY_WAKEUP:
		snprintf(tmp, 64, "%s(%d) [%03d] = %llu, ", txt, field1,
				smp_processor_id(), now - last_ts);
		break;
	case KEY_SWITCH:
		snprintf(tmp, 64, "%s(%s-%d, %d) [%03d] = %llu, ", txt, field2,
				field1, field3, smp_processor_id(),
				now - last_ts);
		break;
	case KEY_TIMER_INTERRUPT:
	case KEY_HRTIMER:
		snprintf(tmp, 64, "%s [%03d] = %llu, ", txt, smp_processor_id(),
				now - last_ts);
		break;
	case KEY_WORK_DONE:
		snprintf(tmp, 64, "%s [%03d] = %llu, ", txt, smp_processor_id(),
				now - last_ts);
		break;
	case KEY_WORK_BEGIN:
		snprintf(buf, min_t(unsigned int, field1, 32), "%s", field2);
		snprintf(tmp, 64, "%s(%s) [%03d] = %llu, ", txt,
				buf, smp_processor_id(),
				now - last_ts);
		break;
	}
	len = strlen(tmp);
	if ((data->pos + len) > MAX_PAYLOAD) {
		data->breakdown[data->pos] = '+';
		data->pos = MAX_PAYLOAD;
		return;
	}
	memcpy(data->breakdown + data->pos, tmp, len);
	data->pos += len;
}

static
void rt_cb(struct latency_tracker_event_ctx *ctx)
{
	struct event_data *data = latency_tracker_event_ctx_get_priv_data(ctx);
	unsigned int cb_out_id = latency_tracker_event_ctx_get_cb_out_id(ctx);
	uint64_t start_ts = latency_tracker_event_ctx_get_start_ts(ctx);
	uint64_t end_ts = 0;
	char *comm;

	if (!data) {
		BUG_ON(1);
		return;
	}
	switch(cb_out_id) {
	case OUT_NO_CB:
	case OUT_IRQHANDLER_NO_CB:
		return;
	case OUT_SWITCH_BLOCKED:
		if (!config.output_switch_out_blocked)
			return;
		if (config.procname_filter_size)
			if (strncmp(data->userspace_proc, config.procname_filter,
						TASK_COMM_LEN) != 0)
				return;
		comm = current->comm;
		break;
	case OUT_ENTER_USERSPACE:
		if (!config.enter_userspace)
			return;
		if (config.procname_filter_size)
			if (strncmp(data->userspace_proc, config.procname_filter,
						TASK_COMM_LEN) != 0)
				return;
		comm = data->userspace_proc;
		break;
	case OUT_WORK_DONE:
		if (config.procname_filter_size)
			if (strncmp(data->userspace_proc, config.procname_filter,
						TASK_COMM_LEN) != 0)
				return;
		comm = data->userspace_proc;
		break;
	default:
		return;
	}

	end_ts = data->prev_ts;
	trace_latency_tracker_rt(data->irq, comm, current->pid,
		data->enter_userspace_ts ? data->enter_userspace_ts - start_ts : 0,
		end_ts - start_ts,
		data->preempt_count, data->breakdown);
	latency_tracker_debugfs_wakeup_pipe(tracker);
	/*
	trace_printk("%s (%d), total = %llu ns, breakdown (ns): %s\n",
			current->comm, current->pid,
			end_ts - start_ts, data->data);
			*/
}

static
int exit_do_irq(struct kretprobe_instance *p, struct pt_regs *regs)
{
	struct do_irq_key_t key;

	if (!latency_tracker_get_tracking_on(tracker))
		return 0;

	if (!config.irq_tracing)
		return 0;
	key.p.type = KEY_DO_IRQ;
	key.cpu = smp_processor_id();
	latency_tracker_event_out(tracker, NULL, &key,
			sizeof(key), OUT_IRQHANDLER_NO_CB, 0);

	return 0;
}

#ifdef DO_IRQ_KRETPROBE
static
int entry_do_irq(struct kretprobe_instance *p, struct pt_regs *regs)
{
	enum latency_tracker_event_in_ret ret;
	struct latency_tracker_event *s;
	struct do_irq_key_t key;
	u64 now;

	if (!latency_tracker_get_tracking_on(tracker))
		return 0;

	if (!config.irq_tracing)
		return 0;

	now = trace_clock_monotonic_wrapper();
	key.p.type = KEY_DO_IRQ;
	key.cpu = smp_processor_id();
	ret = _latency_tracker_event_in_get(tracker, &key, sizeof(key), 1, now,
			NULL, &s);
	if (ret != LATENCY_TRACKER_OK)
		return 0;
	WARN_ON_ONCE(!s);

	if (config.text_breakdown) {
		append_delta_ts(s, KEY_DO_IRQ, "do_IRQ", now, 0, NULL, 0);
	}
	latency_tracker_unref_event(s);

#ifdef DEBUG
	trace_printk("%llu do_IRQ (cpu %u)\n", trace_clock_monotonic_wrapper(),
			key.cpu);
#endif

	return 0;
}

static
struct kretprobe probe_do_irq = {
	.entry_handler = entry_do_irq,
	.handler = exit_do_irq,
	.kp.symbol_name = "do_IRQ",
};
#endif

/*
 * Check if the event is in a branch that can continue or needs to be
 * collected. If the current branch is invalid, this function releases the
 * refcount on the root and returns 1.
 * Returns 0 if the branch is still valid
 */
static
int check_current_branch(struct event_data *data_in)
{
	struct event_data *root_data;

	/*
	 * The root is not a branch, it does not need to be flagged.
	 */
	if (!data_in->root)
		return 0;

	root_data = (struct event_data *)
		latency_tracker_event_get_priv_data(data_in->root);
	/*
	 * If the good branch has been identified and it's not this
	 * one, release the refcount on the root and clear this
	 * branch.
	 */
	if ((root_data->u.good_branch_found && !data_in->u.good_branch) ||
			(root_data->tree_closed))
		return 1;

	return 0;
}

/*
 * Flag the current branch as valid and set the flag in the root branch
 * to inform that the good branch has been found.
 */
static
void set_good_branch(struct event_data *data_in)
{
	struct event_data *root_data;

	/*
	 * The root is not a branch, it does not need to be flagged.
	 */
	if (!data_in->root)
		return;

	root_data = (struct event_data *)
		latency_tracker_event_get_priv_data(data_in->root);
	/*
	 * Might race if a new branch is created in event_transition(), but
	 * it resolves itself automatically when any valid branch actually
	 * completes (tree_closed).
	 */
	root_data->u.good_branch_found = 1;
	data_in->u.good_branch = 1;

	return;
}

void abort_tracker(void)
{
	latency_tracker_set_tracking_on(tracker, 0, 0);
	tracker_aborted++;
}

/*
 * - create the key_out with the original timestamp
 * - copy the payload of key_in to key_out
 * - if del == 1: delete the original key
 * - return event_out (needs to be "put" afterwards)
 *
 * The same key could be in the tracker multiple times (unique = 0 in
 * event_in), in this case, the caller must make sure to iterate over all
 * duplicates.
 *
 * The branch parameter informs if the new event creates a new branch in
 * the tree.
 */
static
struct latency_tracker_event *event_transition(
		struct latency_tracker_event *event_in, void *key_out,
		int key_out_len, int del, int unique, int branch)
{
	struct latency_tracker_event *event_out = NULL;
	struct event_data *data_in, *data_out;
	u64 orig_ts;
	int ret;
#ifdef BENCH
	BENCH_PREAMBULE;
#endif

#ifdef BENCH
	BENCH_GET_TS1;
#endif

	if (!event_in) {
		event_out = NULL;
		goto end;
	}
	data_in = (struct event_data *)
		latency_tracker_event_get_priv_data(event_in);
	if (!data_in) {
		BUG_ON(1);
		goto end;
	}

	/*
	 * If we are in a branch, check if it is still valid before performing
	 * a state transition.
	 */
	ret = check_current_branch(data_in);
	if (ret != 0) {
		del = 1;
		goto end_del;
	}
	orig_ts = latency_tracker_event_get_start_ts(event_in);

	ret = _latency_tracker_event_in_get(tracker, key_out,
			key_out_len, unique, orig_ts, NULL, &event_out);
	if (ret != LATENCY_TRACKER_OK)
		goto end_del;
	WARN_ON_ONCE(!event_out);
	data_out = (struct event_data *)
		latency_tracker_event_get_priv_data(event_out);
	if (!data_out) {
		BUG_ON(1);
		goto end_del;
	}
	memcpy(data_out, data_in, sizeof(struct event_data));
	if (data_in->root) {
		ret = latency_tracker_ref_event(data_in->root);
		WARN_ON_ONCE(!ret);
	}

	if (branch) {
		struct event_data *data_root;

		/* First branch, the others get the pointer from the memcpy */
		if (!data_in->root) {
			data_out->root = event_in;
			ret = latency_tracker_ref_event(event_in);
			WARN_ON_ONCE(!ret);
		}
		/*
		 * When branching, we have to reset the good_branch flags
		 * regardless of the current state since we don't know if the
		 * new branch is valid and it should not inherit the state of
		 * its parent (memcpy).
		 */
		data_root = (struct event_data *)
			latency_tracker_event_get_priv_data(data_out->root);
		data_root->u.good_branch_found = 0;
		data_out->u.good_branch = 0;
	}

end_del:
	if (del)
		latency_tracker_event_out(tracker, event_in, NULL, 0,
				OUT_NO_CB, 0);

end:
#ifdef BENCH
	BENCH_GET_TS2;
#endif
#ifdef BENCH
	BENCH_APPEND(!!event_in);
#endif
	return event_out;
}

#if defined(__i386) || defined(__x86_64)
LT_PROBE_DEFINE(local_timer_entry, int vector)
{
	enum latency_tracker_event_in_ret ret;
	struct latency_tracker_event *s;
	struct local_timer_key_t key;
	u64 now;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	if (!config.timer_tracing)
		goto end;

	now = trace_clock_monotonic_wrapper();
	key.p.type = KEY_TIMER_INTERRUPT;
	key.cpu = smp_processor_id();
	ret = _latency_tracker_event_in_get(tracker, &key, sizeof(key), 1, now,
			NULL, &s);
	if (ret != LATENCY_TRACKER_OK)
		goto end;
	WARN_ON_ONCE(!s);
	if (config.text_breakdown) {
		append_delta_ts(s, KEY_TIMER_INTERRUPT, "local_timer_entry", now,
				vector, NULL, 0);
	}
	latency_tracker_unref_event(s);

#ifdef DEBUG
	trace_printk("%llu local_timer_entry (cpu %u)\n",
			trace_clock_monotonic_wrapper(), key.cpu);
#endif

end:
	return;
}

LT_PROBE_DEFINE(local_timer_exit, int vector)
{
	struct local_timer_key_t local_timer_key;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	if (!config.timer_tracing)
		goto end;
	local_timer_key.p.type = KEY_TIMER_INTERRUPT;
	local_timer_key.cpu = smp_processor_id();
	latency_tracker_event_out(tracker, NULL, &local_timer_key,
			sizeof(local_timer_key), OUT_IRQHANDLER_NO_CB, 0);
end:
	return;
}
#endif

#ifndef DO_IRQ_KRETPROBE
static
void irq_handler_entry_no_do_irq(int irq)
{
	enum latency_tracker_event_in_ret ret;
	struct latency_tracker_event *s;
	struct hardirq_key_t key;
	struct event_data *data;
	u64 now;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	if (!config.irq_tracing)
		return;

	now = trace_clock_monotonic_wrapper();
	key.p.type = KEY_HARDIRQ;
	key.cpu = smp_processor_id();
	ret = _latency_tracker_event_in_get(tracker, &key, sizeof(key), 1, now,
			NULL, &s);
	if (ret != LATENCY_TRACKER_OK)
		return;
	WARN_ON_ONCE(!s);

	if (config.text_breakdown) {
		/* fake do_IRQ text entry */
		append_delta_ts(s, KEY_DO_IRQ, "irq_handler_entry",
				now, 0, NULL, 0);
	}
	data = (struct event_data *)
		latency_tracker_event_get_priv_data(s);
	data->irq = irq;
	latency_tracker_unref_event(s);

#ifdef DEBUG
	trace_printk("%llu irq_handler_entry_no_do_irq (cpu %u)\n",
			trace_clock_monotonic_wrapper(), key.cpu);
#endif
	return;
}
#endif /* DO_IRQ_KRETPROBE */

LT_PROBE_DEFINE(irq_handler_entry, int irq, struct irqaction *action)
{
	struct do_irq_key_t do_irq_key;
	struct hardirq_key_t hardirq_key;
	struct latency_tracker_event *event_in, *event_out;
	struct event_data *data;

#ifndef DO_IRQ_KRETPROBE
	return irq_handler_entry_no_do_irq(irq);
#endif

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	if (!config.irq_tracing)
		goto end;

	if (config.irq_filter > 0 && config.irq_filter != irq) {
		exit_do_irq(NULL, NULL);
		goto end;
	}

	do_irq_key.p.type = KEY_DO_IRQ;
	do_irq_key.cpu = smp_processor_id();

	hardirq_key.p.type = KEY_HARDIRQ;
	hardirq_key.cpu = smp_processor_id();

	event_in = latency_tracker_get_event_by_key(tracker, &do_irq_key,
			sizeof(do_irq_key), NULL);
	if (!event_in)
		goto end;

	data = (struct event_data *)
		latency_tracker_event_get_priv_data(event_in);
	data->irq = irq;

	event_out = event_transition(event_in, &hardirq_key,
			sizeof(hardirq_key), 0, 1, 0);

	latency_tracker_unref_event(event_in);
	if (!event_out)
		goto end;
	append_delta_ts(event_out, KEY_HARDIRQ, "to irq_handler_entry", 0, irq,
			NULL, 0);
	latency_tracker_unref_event(event_out);

#ifdef DEBUG
		trace_printk("%llu hard_irq_entry (cpu: %u)\n", trace_clock_monotonic_wrapper(),
				do_irq_key.cpu);
#endif
end:
	return;
}

LT_PROBE_DEFINE(irq_handler_exit, int irq, struct irqaction *action,
		int ret)
{
	struct hardirq_key_t hardirq_key;
	struct latency_tracker_event *event;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	if (!config.irq_tracing)
		goto end;

	if (config.irq_filter > 0 && config.irq_filter != irq) {
		exit_do_irq(NULL, NULL);
		goto end;
	}

	hardirq_key.p.type = KEY_HARDIRQ;
	hardirq_key.cpu = smp_processor_id();

	event = latency_tracker_get_event_by_key(tracker, &hardirq_key,
			sizeof(hardirq_key), NULL);
	if (!event)
		goto end;
	append_delta_ts(event, KEY_HARDIRQ, "to irq_handler_exit", 0,
			irq, NULL, 0);
	latency_tracker_unref_event(event);

	latency_tracker_event_out(tracker, event, NULL, 0,
			OUT_IRQHANDLER_NO_CB, 0);

end:
	return;
}

#ifdef CONFIG_PREEMPT_RT_FULL
LT_PROBE_DEFINE(softirq_raise, unsigned int vec_nr)
{
	struct raise_softirq_key_t raise_softirq_key;
	struct switch_key_t switch_key;
	struct latency_tracker_event *event_in, *event_out;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	if (config.softirq_filter > 0 && config.softirq_filter != vec_nr)
		goto end;

	switch_key.p.type = KEY_SWITCH;
	switch_key.pid = current->pid;
	if (!current->pid)
		switch_key.cpu = smp_processor_id();
	else
		switch_key.cpu = -1;

	raise_softirq_key.p.type = KEY_RAISE_SOFTIRQ;
	raise_softirq_key.cpu = smp_processor_id();
	raise_softirq_key.vector = vec_nr;

	event_in = latency_tracker_get_event_by_key(tracker, &switch_key,
			sizeof(switch_key), NULL);
	if (!event_in)
		goto end;

	event_out = event_transition(event_in, &raise_softirq_key,
			sizeof(raise_softirq_key), 0, 0, 1);
	latency_tracker_unref_event(event_in);
	if (!event_out)
		goto end;

	append_delta_ts(event_out, KEY_RAISE_SOFTIRQ, "to softirq_raise", 0,
			vec_nr, NULL, 0);
	latency_tracker_unref_event(event_out);

#ifdef DEBUG
	trace_printk("%llu softirq_raise %u\n", trace_clock_monotonic_wrapper(),
			vec_nr);
#endif
end:
	return;
}
#else /* CONFIG_PREEMPT_RT_FULL */
LT_PROBE_DEFINE(softirq_raise, unsigned int vec_nr)
{
	struct hardirq_key_t hardirq_key;
	struct raise_softirq_key_t raise_softirq_key;
	struct latency_tracker_event *event_in, *event_out;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	event_in = NULL;

	if (config.softirq_filter > 0 && config.softirq_filter != vec_nr)
		goto end;

	hardirq_key.p.type = KEY_HARDIRQ;
	hardirq_key.cpu = smp_processor_id();

	raise_softirq_key.p.type = KEY_RAISE_SOFTIRQ;
	raise_softirq_key.cpu = smp_processor_id();
	raise_softirq_key.vector = vec_nr;

	event_in = latency_tracker_get_event_by_key(tracker, &hardirq_key,
			sizeof(hardirq_key), NULL);
	if (!event_in)
		goto end;

	event_out = event_transition(event_in, &raise_softirq_key,
			sizeof(raise_softirq_key), 0, 0, 1);
	latency_tracker_unref_event(event_in);
	if (!event_out)
		goto end;
	append_delta_ts(event_out, KEY_RAISE_SOFTIRQ, "to softirq_raise", 0,
			vec_nr, NULL, 0);
	latency_tracker_unref_event(event_out);

#ifdef DEBUG
	trace_printk("%llu softirq_raise %u\n", trace_clock_monotonic_wrapper(),
			vec_nr);
#endif
end:
	return;
}
#endif /* CONFIG_PREEMPT_RT_FULL */

LT_PROBE_DEFINE(softirq_entry, unsigned int vec_nr)
{
	struct raise_softirq_key_t raise_softirq_key;
	struct softirq_key_t softirq_key;
	struct latency_tracker_event *event_in, *event_out;
	struct latency_tracker_event_iter iter;
	int nr_duplicates = 0;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	if (config.softirq_filter > 0 && config.softirq_filter != vec_nr)
		goto end;

	raise_softirq_key.p.type = KEY_RAISE_SOFTIRQ;
	raise_softirq_key.cpu = smp_processor_id();
	raise_softirq_key.vector = vec_nr;

	/*
	 * Insert the softirq_entry event.
	 * TODO: Use the CPU as key on non-RT kernel and PID on PREEMPT_RT.
	 */
	softirq_key.p.type = KEY_SOFTIRQ;
	softirq_key.cpu = smp_processor_id();
	softirq_key.pid = current->pid;

	event_in = latency_tracker_get_event_by_key(tracker,
			&raise_softirq_key, sizeof(raise_softirq_key), &iter);
	while (event_in) {
		event_out = event_transition(event_in, &softirq_key,
				sizeof(softirq_key), 1, 1, 0);
		latency_tracker_unref_event(event_in);
		if (event_out) {
			append_delta_ts(event_out, KEY_SOFTIRQ,
					"to softirq_entry", 0, vec_nr, NULL, 0);
			latency_tracker_unref_event(event_out);
		}
		event_in = latency_tracker_get_next_duplicate(tracker,
				&raise_softirq_key, sizeof(raise_softirq_key),
				&iter);
		if (nr_duplicates++ > config.nr_duplicates_max) {
			abort_tracker();
			break;
		}
	}

#ifdef DEBUG
	trace_printk("%llu softirq_entry %u\n", trace_clock_monotonic_wrapper(),
			vec_nr);
#endif
end:
	return;
}

LT_PROBE_DEFINE(hrtimer_expire_entry, struct hrtimer *hrtimer,
		ktime_t *now)
{
	struct local_timer_key_t local_timer_key;
	struct hrtimer_key_t hrtimer_key;
	struct latency_tracker_event *event_in, *event_out;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	if (!config.timer_tracing)
		goto end;
	local_timer_key.p.type = KEY_TIMER_INTERRUPT;
	local_timer_key.cpu = smp_processor_id();

	/*
	 * Insert the hrtimer_expire_entry event.
	 * TODO: Use the CPU as key on non-RT kernel and PID on PREEMPT_RT.
	 */
	hrtimer_key.p.type = KEY_HRTIMER;
	hrtimer_key.cpu = smp_processor_id();

	event_in = latency_tracker_get_event_by_key(tracker, &local_timer_key,
			sizeof(local_timer_key), NULL);
	if (!event_in)
		goto end;

	event_out = event_transition(event_in, &hrtimer_key,
			sizeof(hrtimer_key), 0, 1, 0);
	latency_tracker_unref_event(event_in);
	if (!event_out)
		goto end;
	append_delta_ts(event_out, KEY_HRTIMER, "to hrtimer_expire_entry", 0,
			-1, NULL, 0);
	latency_tracker_unref_event(event_out);

#ifdef DEBUG
	trace_printk("%llu hrtimer_entry\n", trace_clock_monotonic_wrapper());
#endif
end:
	return;
}

LT_PROBE_DEFINE(hrtimer_expire_exit, struct timer_list *timer)
{
	struct hrtimer_key_t hrtimer_key;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	if (!config.timer_tracing)
		goto end;
	hrtimer_key.p.type = KEY_HRTIMER;
	hrtimer_key.cpu = smp_processor_id();

	/*
	 * Insert the hrtimer_expire_entry event.
	 * TODO: Use the CPU as key on non-RT kernel and PID on PREEMPT_RT.
	 */
	hrtimer_key.p.type = KEY_HRTIMER;
	hrtimer_key.cpu = smp_processor_id();

	latency_tracker_event_out(tracker, NULL, &hrtimer_key,
			sizeof(hrtimer_key), OUT_IRQHANDLER_NO_CB, 0);

end:
	return;
}

LT_PROBE_DEFINE(softirq_exit, unsigned int vec_nr)
{
	struct softirq_key_t softirq_key;
	struct latency_tracker_event *event;
	struct latency_tracker_event_iter iter;
	int nr_duplicates = 0;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	if (config.softirq_filter > 0 && config.softirq_filter != vec_nr)
		goto end;

	/*
	 * Just cleanup the softirq_entry event(s)
	 */
	softirq_key.p.type = KEY_SOFTIRQ;
	softirq_key.cpu = smp_processor_id();
	softirq_key.pid = current->pid;

	event = latency_tracker_get_event_by_key(tracker, &softirq_key,
			sizeof(softirq_key), &iter);
	while (event) {
		append_delta_ts(event, KEY_SOFTIRQ, "to softirq_exit", 0, vec_nr,
				NULL, 0);
		latency_tracker_unref_event(event);

		latency_tracker_event_out(tracker, event, NULL, 0,
				OUT_IRQHANDLER_NO_CB, 0);
		event = latency_tracker_get_next_duplicate(tracker, &softirq_key,
				sizeof(softirq_key), &iter);
		if (nr_duplicates++ > config.nr_duplicates_max) {
			abort_tracker();
			break;
		}
	}
end:
	return;
}

/*
 * sched_waking from an IRQ context, unique origin.
 */
static
void irq_waking(struct waking_key_t *waking_key)
{
	struct latency_tracker_event *event_in, *event_out;
	struct do_irq_key_t do_irq_key;

	do_irq_key.p.type = KEY_DO_IRQ;
	do_irq_key.cpu = smp_processor_id();

	event_in = latency_tracker_get_event_by_key(tracker, &do_irq_key,
			sizeof(do_irq_key), NULL);
	if (!event_in)
		goto end;

	event_out = event_transition(event_in, waking_key,
			sizeof(*waking_key), 0, 0, 1);
	latency_tracker_unref_event(event_in);
	if (!event_out)
		goto end;

	append_delta_ts(event_out, KEY_WAKEUP, "to sched_waking", 0, waking_key->pid,
			NULL, 0);
	latency_tracker_unref_event(event_out);
#ifdef DEBUG
	trace_printk("%llu waking %d\n", trace_clock_monotonic_wrapper(),
			waking_key->pid);
#endif

end:
	return;
}

/*
 * sched_waking from a softirq context.
 */
static
void softirq_waking(struct waking_key_t *waking_key)
{
	struct softirq_key_t softirq_key;
	struct latency_tracker_event *event_in, *event_out;
	struct latency_tracker_event_iter iter;
	int nr_duplicates = 0;

	softirq_key.p.type = KEY_SOFTIRQ;
	softirq_key.cpu = smp_processor_id();
	softirq_key.pid = current->pid;

	event_in = latency_tracker_get_event_by_key(tracker, &softirq_key,
			sizeof(softirq_key), &iter);
	while (event_in) {
		event_out = event_transition(event_in, waking_key,
				sizeof(*waking_key), 0, 0, 1);
		latency_tracker_unref_event(event_in);
		if (event_out) {
			append_delta_ts(event_out, KEY_WAKEUP,
					"to sched_waking", 0, waking_key->pid,
					NULL, 0);
			latency_tracker_unref_event(event_out);
		}
		event_in = latency_tracker_get_next_duplicate(tracker,&softirq_key,
				sizeof(softirq_key), &iter);
		if (nr_duplicates++ > config.nr_duplicates_max) {
			abort_tracker();
			break;
		}
	}
#ifdef DEBUG
	trace_printk("%llu waking %d\n", trace_clock_monotonic_wrapper(),
			waking_key->pid);
#endif
}

/*
 * sched_waking from a hrtimer handler context, unique origin.
 * Return 0 if the waking did not originate from a hrtimer
 */
static
int hrtimer_waking(struct waking_key_t *waking_key)
{
	struct hrtimer_key_t hrtimer_key;
	struct latency_tracker_event *event_in, *event_out;
	int ret;

	/* TODO: PREEMPT_RT */
	hrtimer_key.p.type = KEY_HRTIMER;
	hrtimer_key.cpu = smp_processor_id();

	event_in = latency_tracker_get_event_by_key(tracker, &hrtimer_key,
			sizeof(hrtimer_key), NULL);
	if (!event_in) {
		ret = 0;
		goto end;
	}

	event_out = event_transition(event_in, waking_key,
			sizeof(*waking_key), 0, 0, 1);
	latency_tracker_unref_event(event_in);
	if (!event_out) {
		ret = 0;
		goto end;
	}

	append_delta_ts(event_out, KEY_WAKEUP, "to sched_waking", 0,
			waking_key->pid, NULL, 0);
	latency_tracker_unref_event(event_out);

	ret = 1;

end:
	return ret;
}

/*
 * A thread is waking up another thread.
 * If we are interested in the waking, we should have tracked
 * the switch_in of the current process.
 */
static
void thread_waking(struct waking_key_t *waking_key)
{
	struct switch_key_t switch_key;
	struct latency_tracker_event *event_in, *event_out;
	struct latency_tracker_event_iter iter;
	int nr_duplicates = 0;
	u64 now = trace_clock_monotonic_wrapper();

	switch_key.p.type = KEY_SWITCH;
	switch_key.pid = current->pid;
	if (!current->pid)
		switch_key.cpu = smp_processor_id();
	else
		switch_key.cpu = -1;

	event_in = latency_tracker_get_event_by_key(tracker, &switch_key,
			sizeof(switch_key), &iter);
	while (event_in) {
		event_out = event_transition(event_in, waking_key,
				sizeof(*waking_key), 0, 0, 1);
		if (event_out) {
			/* switch_in after a waking */
			append_delta_ts(event_out, KEY_WAKEUP, "to sched_waking", now,
					waking_key->pid, NULL, 0);
			latency_tracker_unref_event(event_out);
		}

		append_delta_ts(event_in, KEY_WAKEUP, "to sched_waking", now,
				waking_key->pid, NULL, 0);
		latency_tracker_unref_event(event_in);
		event_in = latency_tracker_get_next_duplicate(tracker, &switch_key,
				sizeof(switch_key), &iter);
		if (nr_duplicates++ > config.nr_duplicates_max) {
			abort_tracker();
			break;
		}
	}
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0) || \
	LT_RT_KERNEL_RANGE(4,1,10,11, 4,2,0,0))
LT_PROBE_DEFINE(sched_waking, struct task_struct *p)
#else
LT_PROBE_DEFINE(sched_waking, struct task_struct *p, int success)
#endif
{
	/*
	 * On a non-RT kernel, if we are here while handling a softirq, lookup
	 * the softirq currently active on the current CPU to get the origin
	 * timestamp. If we are here in a thread context, we cannot deduce
	 * anything (need sched_waking instead).
	 * On a PREEMPT_RT we match on the PID of the current task instead
	 * of the CPU.
	 */
	struct waking_key_t waking_key;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	if (!p)
		goto end;

	waking_key.p.type = KEY_WAKEUP;
	waking_key.pid = p->pid;
	if (!p->pid)
		waking_key.cpu = smp_processor_id();
	else
		waking_key.cpu = -1;

	/* In order of nesting */
	if (in_nmi()) {
		/* TODO */
		goto end;
	} else if (in_irq()) {
		int ret;

		ret = hrtimer_waking(&waking_key);
		if (ret)
			goto end;
		irq_waking(&waking_key);
	} else if (in_serving_softirq()) {
		softirq_waking(&waking_key);
	} else {
		int ret;

		/* hrtimer or thread waking */
		ret = hrtimer_waking(&waking_key);
		if (ret)
			goto end;
		thread_waking(&waking_key);
	}

end:
	return;
}

static
void sched_switch_in(struct task_struct *next)
{
	struct waking_key_t waking_key;
	struct latency_tracker_event *event_in, *event_out;
	struct latency_tracker_event_iter iter;
	struct switch_key_t switch_key;
	struct event_data *data;
	int ret;
	int nr_duplicates = 0;
	u64 now = trace_clock_monotonic_wrapper();

	switch_key.p.type = KEY_SWITCH;
	switch_key.pid = next->pid;
	if (!next->pid)
		switch_key.cpu = smp_processor_id();
	else
		switch_key.cpu = -1;

	/* We can switch from a wakeup/waking or after being preempted */

	/* sched in */
	waking_key.p.type = KEY_WAKEUP;
	waking_key.pid = next->pid;
	if (!next->pid)
		waking_key.cpu = smp_processor_id();
	else
		waking_key.cpu = -1;

	/* Switch after one or multiple waking. */
	event_in = latency_tracker_get_event_by_key(tracker,
			&waking_key, sizeof(waking_key), &iter);
	while (event_in) {
		event_out = event_transition(event_in, &switch_key,
				sizeof(switch_key), 1, 0, 0);
		latency_tracker_unref_event(event_in);
		if (event_out) {
			append_delta_ts(event_out, KEY_SWITCH, "to switch_in",
					now, next->pid, next->comm,
					wrapper_task_prio(next));
			data = (struct event_data *)
				latency_tracker_event_get_priv_data(event_out);
			strncpy(data->userspace_proc, next->comm,
					TASK_COMM_LEN);
			if (next->mm)
				data->enter_userspace_ts = now;
			latency_tracker_unref_event(event_out);
			if (config.enter_userspace && next->mm) {
				latency_tracker_event_out(tracker, event_out,
						NULL, 0, OUT_ENTER_USERSPACE,
						now);
			}
		}
		event_in = latency_tracker_get_next_duplicate(tracker,
				&waking_key, sizeof(waking_key), &iter);
		if (nr_duplicates++ > config.nr_duplicates_max) {
			abort_tracker();
			break;
		}
	}

	/*
	 * Switch after a preempt, no transition, just check the current
	 * branch and eventually append text.
	 */
	nr_duplicates = 0;
	event_in = latency_tracker_get_event_by_key(tracker,
			&switch_key, sizeof(switch_key), &iter);
	while (event_in) {
		data = (struct event_data *)
			latency_tracker_event_get_priv_data(event_in);
		ret = check_current_branch(data);
		if (ret != 0) {
			latency_tracker_unref_event(event_in);
			latency_tracker_event_out(tracker, event_in, NULL, 0,
					OUT_NO_CB, 0);
			goto end;
		}
		append_delta_ts(event_in, KEY_SWITCH, "to switch_in", now,
				next->pid, next->comm, wrapper_task_prio(next));
		latency_tracker_unref_event(event_in);
		event_in = latency_tracker_get_next_duplicate(tracker,
				&switch_key, sizeof(switch_key), &iter);
		if (nr_duplicates++ > config.nr_duplicates_max) {
			abort_tracker();
			break;
		}
	}

#ifdef DEBUG
	trace_printk("%llu switch_in %d (%s)\n",
			trace_clock_monotonic_wrapper(),
			next->pid, next->comm);
#endif
end:
	return;
}

static
void sched_switch_out(struct task_struct *prev, struct task_struct *next)
{
	struct switch_key_t switch_key;
	int ret;
	struct latency_tracker_event *event;
	struct latency_tracker_event_iter iter;
	int nr_duplicates = 0;
	u64 now = trace_clock_monotonic_wrapper();

	/* switch out */
	switch_key.p.type = KEY_SWITCH;
	switch_key.pid = prev->pid;
	if (!prev->pid)
		switch_key.cpu = smp_processor_id();
	else
		switch_key.cpu = -1;

	event = latency_tracker_get_event_by_key(tracker, &switch_key,
			sizeof(switch_key), &iter);
	/* Handle duplicates */
	while (event) {
		/*
		 * If the task is still running, but just got preempted, it
		 * means that it is still actively working on an event, so we
		 * continue tracking its state until it blocks.
		 */
		if (prev->state == TASK_RUNNING) {
			struct event_data *data;

			append_delta_ts(event, KEY_SWITCH, "to switch_out_preempt",
					now, next->pid, next->comm,
					wrapper_task_prio(next));
			data = (struct event_data *)
				latency_tracker_event_get_priv_data(event);
			if (!data) {
				WARN_ON_ONCE(1);
				latency_tracker_unref_event(event);
				goto end;
			}
			data->preempt_count++;
		} else {
			/* blocked */
			append_delta_ts(event, KEY_SWITCH,
					"to switch_out_blocked", now,
					next->pid, next->comm,
					wrapper_task_prio(next));
			if (config.output_switch_out_blocked) {
				ret = latency_tracker_event_out(tracker, event,
						NULL, 0, OUT_SWITCH_BLOCKED,
						now);
			} else {
				ret = latency_tracker_event_out(tracker, event,
						NULL, 0, OUT_NO_CB, now);
			}
			WARN_ON_ONCE(ret);
#ifdef DEBUG
			trace_printk("%llu switch_out %d (%s)\n",
					trace_clock_read64(),
					prev->pid, prev->comm);
#endif
		}

		latency_tracker_unref_event(event);
		event = latency_tracker_get_next_duplicate(tracker,
				&switch_key, sizeof(switch_key), &iter);
		if (nr_duplicates++ > config.nr_duplicates_max) {
			abort_tracker();
			break;
		}
	}
end:
	return;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0))
LT_PROBE_DEFINE(sched_switch, bool preempt, struct task_struct *prev,
		struct task_struct *next)
#else
LT_PROBE_DEFINE(sched_switch, struct task_struct *prev,
		struct task_struct *next)
#endif
{
	if (!latency_tracker_get_tracking_on(tracker))
		return;

	if (!prev || !next)
		goto end;

	sched_switch_in(next);
	sched_switch_out(prev, next);

end:
	return;
}

static
ssize_t read_procname_filter(struct file *filp, char __user *ubuf,
		size_t count, loff_t *ppos)
{
	struct tracker_config *cfg = filp->private_data;
	char buf[TASK_COMM_LEN + 1];
	int r;

	r = snprintf(buf, TASK_COMM_LEN, "%s\n", cfg->procname_filter);
	return simple_read_from_buffer(ubuf, count, ppos, buf, r);
}

static ssize_t
write_procname_filter(struct file *filp, const char __user *ubuf,
		size_t cnt, loff_t *ppos)
{
	struct tracker_config *cfg = filp->private_data;
	int ret, r;
	char buf[TASK_COMM_LEN];

	r = min_t(unsigned int, cnt, TASK_COMM_LEN);
	ret = copy_from_user(buf, ubuf, r);
	if (ret)
		return ret;

	buf[r] = '\0';
	memset(cfg->procname_filter, 0, TASK_COMM_LEN);
	snprintf(cfg->procname_filter, r, "%s", buf);
	cfg->procname_filter_size = r - 1;
	if (cfg->procname_filter[0] == '\0')
		cfg->procname_filter_size = 0;

	return cnt;
}

static const
struct file_operations procname_filter_fops = {
	.open           = latency_open_generic,
	.read           = read_procname_filter,
	.write          = write_procname_filter,
	.llseek         = default_llseek,
};

LT_PROBE_DEFINE(tracker_end, char *tp_data, size_t len)
{
	struct latency_tracker_event *event;
	struct latency_tracker_event_iter iter;
	struct work_begin_key_t work_begin_key;
	struct event_data *data;
	int nr_duplicates = 0;

	//struct tracker_config *cfg = filp->private_data;
	u64 now = trace_clock_monotonic_wrapper();

	if (!config.out_work_done)
		return;

	memset(&work_begin_key.cookie, 0, sizeof(work_begin_key.cookie));
	memcpy(&work_begin_key.cookie, tp_data, len);

	/*
	 * If we got \n or \0, we don't expect to find a cookie created
	 * by work_begin, so lookup the current process instead.
	 */
	if (len == 1 && (work_begin_key.cookie[0] == '\n' ||
				work_begin_key.cookie[0] == '\0')) {
		struct switch_key_t switch_key;

		/*
		 * The current process should be tracked otherwise we can't
		 * link this event to an origin.
		 */
		switch_key.p.type = KEY_SWITCH;
		switch_key.pid = current->pid;
		if (!current->pid)
			switch_key.cpu = smp_processor_id();
		else
			switch_key.cpu = -1;
		event = latency_tracker_get_event_by_key(tracker, &switch_key,
				sizeof(switch_key), &iter);
		while (event) {
			append_delta_ts(event, KEY_WORK_DONE, "to work_done", now, 0,
					NULL, 0);
			latency_tracker_event_out(tracker, event, NULL, 0,
					OUT_WORK_DONE, now);
			latency_tracker_unref_event(event);
			data = (struct event_data *)
				latency_tracker_event_get_priv_data(event);
			if (data->root) {
				struct event_data *data_root;

				data_root = (struct event_data *)
					latency_tracker_event_get_priv_data(data->root);
				data_root->tree_closed = 1;
				latency_tracker_unref_event(data->root);
				data->root = NULL;
			}
			event = latency_tracker_get_next_duplicate(tracker, &switch_key,
					sizeof(switch_key), &iter);
			if (nr_duplicates++ > config.nr_duplicates_max) {
				abort_tracker();
				break;
			}
		}
	} else {
		work_begin_key.p.type = KEY_WORK_BEGIN;
		work_begin_key.cookie_size = len;

		event = latency_tracker_get_event_by_key(tracker, &work_begin_key,
				sizeof(work_begin_key), &iter);
		while (event) {
			append_delta_ts(event, KEY_WORK_DONE, "to work_done", now, 0,
					NULL, 0);
			latency_tracker_event_out(tracker, event, NULL, 0,
					OUT_WORK_DONE, now);
			latency_tracker_unref_event(event);
			data = (struct event_data *)
				latency_tracker_event_get_priv_data(event);
			if (data->root) {
				struct event_data *data_root;

				data_root = (struct event_data *)
					latency_tracker_event_get_priv_data(data->root);
				data_root->tree_closed = 1;
				latency_tracker_unref_event(data->root);
				data->root = NULL;
			}
			event = latency_tracker_get_next_duplicate(tracker, &work_begin_key,
					sizeof(work_begin_key), &iter);
			if (nr_duplicates++ > config.nr_duplicates_max) {
				abort_tracker();
				break;
			}
		}
	}

	return;
}

/*
 * This should be called from a task that has been woken up in the
 * path of interrupt processing.
 */
LT_PROBE_DEFINE(tracker_begin, char *tp_data, size_t len)
{
	struct switch_key_t switch_key;
	struct work_begin_key_t work_begin_key;
	struct latency_tracker_event *event_in, *event_out;
	struct latency_tracker_event_iter iter;
	struct event_data *data;
	int nr_duplicates = 0;
	u64 now = trace_clock_monotonic_wrapper();

	memset(&work_begin_key.cookie, 0, sizeof(work_begin_key.cookie));
	memcpy(&work_begin_key.cookie, tp_data, len);

	/*
	 * Cookies must be strings, just a "echo > work_begin" is not
	 * accepted, empty strings are valid for work_done.
	 */
	if (len == 1 && (work_begin_key.cookie[0] == '\n' ||
				work_begin_key.cookie[0] == '\0'))
		return;

	/*
	 * The current process should be tracked otherwise we can't link
	 * this event to an origin.
	 */
	switch_key.p.type = KEY_SWITCH;
	switch_key.pid = current->pid;
	if (!current->pid)
		switch_key.cpu = smp_processor_id();
	else
		switch_key.cpu = -1;

	work_begin_key.p.type = KEY_WORK_BEGIN;
	work_begin_key.cookie_size = len;

	event_in = latency_tracker_get_event_by_key(tracker, &switch_key,
			sizeof(switch_key), &iter);
	while (event_in) {
		/*
		 * From now on, only a work_done event can complete this branch.
		 */
		event_out = event_transition(event_in, &work_begin_key,
				sizeof(work_begin_key), 1, 1, 0);
		if (event_out) {
			data = (struct event_data *)
				latency_tracker_event_get_priv_data(event_out);
			set_good_branch(data);

			append_delta_ts(event_out, KEY_WORK_BEGIN,
					"to work_begin", now, len,
					work_begin_key.cookie, 0);
			latency_tracker_unref_event(event_out);
		}
		latency_tracker_unref_event(event_in);
		event_in = latency_tracker_get_next_duplicate(tracker,
				&switch_key, sizeof(switch_key), &iter);
		if (nr_duplicates++ > config.nr_duplicates_max) {
			abort_tracker();
			break;
		}
	}

	return;
}

static
int setup_debugfs_extras(void)
{
	struct dentry *file;
	static struct dentry *filters_dir, *actions_dir;
	int ret;

	filters_dir = latency_tracker_debugfs_add_subfolder(tracker,
			"filters");
	if (!filters_dir)
		goto error;

	actions_dir = latency_tracker_debugfs_add_subfolder(tracker,
			"actions");
	if (!actions_dir)
		goto error;

	file = debugfs_create_u32("timer_tracing",
			S_IRUSR|S_IWUSR, filters_dir, &config.timer_tracing);
	if (!file)
		goto error;

	file = debugfs_create_u32("irq_tracing",
			S_IRUSR|S_IWUSR, filters_dir, &config.irq_tracing);
	if (!file)
		goto error;

	file = debugfs_create_u32("nr_duplicates_max",
			S_IRUSR|S_IWUSR, filters_dir,
			&config.nr_duplicates_max);
	if (!file)
		goto error;

	file = debugfs_create_u32("output_switch_out_blocked",
			S_IRUSR|S_IWUSR, filters_dir,
			&config.output_switch_out_blocked);
	if (!file)
		goto error;

	file = debugfs_create_u32("out_work_done",
			S_IRUSR|S_IWUSR, filters_dir, &config.out_work_done);
	if (!file)
		goto error;

	file = debugfs_create_u32("enter_userspace",
			S_IRUSR|S_IWUSR, filters_dir, &config.enter_userspace);
	if (!file)
		goto error;

	file = debugfs_create_u32("text_breakdown",
			S_IRUSR|S_IWUSR, filters_dir, &config.text_breakdown);
	if (!file)
		goto error;

	file = debugfs_create_file("procname", S_IRUSR,
			filters_dir, &config, &procname_filter_fops);
	if (!file)
		goto error;

	file = debugfs_create_int("irq_filter",
			S_IRUSR|S_IWUSR, filters_dir, &config.irq_filter);
	if (!file)
		goto error;

	file = debugfs_create_int("softirq_filter",
			S_IRUSR|S_IWUSR, filters_dir, &config.softirq_filter);
	if (!file)
		goto error;

	ret = latency_tracker_debugfs_setup_wakeup_pipe(tracker);
	if (ret != 0)
		goto error;

	return 0;

error:
	return -1;
}

void destroy_event_cb(struct latency_tracker_event *event)
{
	struct event_data *data;

	data = (struct event_data *) latency_tracker_event_get_priv_data(event);
	if (data->root)
		latency_tracker_unref_event(data->root);
	return;
}

void unregister_tracepoints(void)
{
#if defined(__i386) || defined(__x86_64)
	lttng_wrapper_tracepoint_probe_unregister("local_timer_entry",
			probe_local_timer_entry, NULL);
	lttng_wrapper_tracepoint_probe_unregister("local_timer_exit",
			probe_local_timer_exit, NULL);
#endif
	lttng_wrapper_tracepoint_probe_unregister("hrtimer_expire_entry",
			probe_hrtimer_expire_entry, NULL);
	lttng_wrapper_tracepoint_probe_unregister("hrtimer_expire_exit",
			probe_hrtimer_expire_exit, NULL);
	lttng_wrapper_tracepoint_probe_unregister("sched_switch",
			probe_sched_switch, NULL);
	lttng_wrapper_tracepoint_probe_unregister("sched_waking",
			probe_sched_waking, NULL);
	lttng_wrapper_tracepoint_probe_unregister("irq_handler_entry",
			probe_irq_handler_entry, NULL);
	lttng_wrapper_tracepoint_probe_unregister("irq_handler_exit",
			probe_irq_handler_exit, NULL);
	lttng_wrapper_tracepoint_probe_unregister("softirq_raise",
			probe_softirq_raise, NULL);
	lttng_wrapper_tracepoint_probe_unregister("softirq_entry",
			probe_softirq_entry, NULL);
	lttng_wrapper_tracepoint_probe_unregister("softirq_exit",
			probe_softirq_exit, NULL);
	lttng_wrapper_tracepoint_probe_unregister("latency_tracker_begin",
			probe_tracker_begin, NULL);
	lttng_wrapper_tracepoint_probe_unregister("latency_tracker_end",
			probe_tracker_end, NULL);

}

static
int __init rt_init(void)
{
	int ret;

	tracker = latency_tracker_create("rt");
	if (!tracker)
		goto error;
	latency_tracker_set_startup_events(tracker, 10000);
	/* FIXME: makes us crash after rmmod */
	//latency_tracker_set_timer_period(tracker, 100000000);
	latency_tracker_set_threshold(tracker, usec_threshold * 1000);
	latency_tracker_set_timeout(tracker, usec_timeout * 1000);
	latency_tracker_set_callback(tracker, rt_cb);
	latency_tracker_set_key_size(tracker, MAX_KEY_SIZE);
	latency_tracker_set_priv_data_size(tracker, sizeof(struct event_data));
	latency_tracker_set_destroy_event_cb(tracker, destroy_event_cb);
	ret = setup_debugfs_extras();
	if (ret != 0)
		goto error;

	if (!timer_tracing)
		config.timer_tracing = 0;

#ifdef BENCH
	alloc_measurements();
#endif

	/* Required tracepoints */
#if defined(__i386) || defined(__x86_64)
	ret = lttng_wrapper_tracepoint_probe_register("local_timer_entry",
			probe_local_timer_entry, NULL);
	if (ret) {
		printk("latency-tracker: Error, required tracepoint local_timer_entry"
				" not available\n");
		goto end_unregister;
	}
	ret = lttng_wrapper_tracepoint_probe_register("local_timer_exit",
			probe_local_timer_exit, NULL);
	if (ret) {
		printk("latency-tracker: Error, required tracepoint local_timer_exit"
				" not available\n");
		goto end_unregister;
	}
#endif

	ret = lttng_wrapper_tracepoint_probe_register("hrtimer_expire_entry",
			probe_hrtimer_expire_entry, NULL);
	if (ret) {
		printk("latency-tracker: Error, required tracepoint hrtimer_expire_entry"
				" not available\n");
		goto end_unregister;
	}
	ret = lttng_wrapper_tracepoint_probe_register("hrtimer_expire_exit",
			probe_hrtimer_expire_exit, NULL);
	if (ret) {
		printk("latency-tracker: Error, required tracepoint hrtimer_expire_exit"
				" not available\n");
		goto end_unregister;
	}
	ret = lttng_wrapper_tracepoint_probe_register("irq_handler_entry",
			probe_irq_handler_entry, NULL);
	if (ret) {
		printk("latency-tracker: Error, required tracepoint irq_handler_entry"
				" not available\n");
		goto end_unregister;
	}
	ret = lttng_wrapper_tracepoint_probe_register("irq_handler_exit",
			probe_irq_handler_exit, NULL);
	if (ret) {
		printk("latency-tracker: Error, required tracepoint irq_handler_exit"
				" not available\n");
		goto end_unregister;
	}
	ret = lttng_wrapper_tracepoint_probe_register("softirq_raise",
			probe_softirq_raise, NULL);
	if (ret) {
		printk("latency-tracker: Error, required tracepoint softirq_raise"
				" not available\n");
		goto end_unregister;
	}
	ret = lttng_wrapper_tracepoint_probe_register("softirq_entry",
			probe_softirq_entry, NULL);
	if (ret) {
		printk("latency-tracker: Error, required tracepoint softirq_entry"
				" not available\n");
		goto end_unregister;
	}
	ret = lttng_wrapper_tracepoint_probe_register("softirq_exit",
			probe_softirq_exit, NULL);
	if (ret) {
		printk("latency-tracker: Error, required tracepoint softirq_exit"
				" not available\n");
		goto end_unregister;
	}
	ret = lttng_wrapper_tracepoint_probe_register("sched_switch",
			probe_sched_switch, NULL);
	if (ret) {
		printk("latency-tracker: Error, required tracepoint sched_switch"
				" not available\n");
		goto end_unregister;
	}
	ret = lttng_wrapper_tracepoint_probe_register("sched_waking",
			probe_sched_waking, NULL);
	if (ret) {
		printk("latency-tracker: Error, required tracepoint sched_waking"
				" not available\n");
		goto end_unregister;
	}

	/* Optional */
	ret = lttng_wrapper_tracepoint_probe_register("latency_tracker_begin",
			probe_tracker_begin, NULL);
	WARN_ON(ret);

	ret = lttng_wrapper_tracepoint_probe_register("latency_tracker_end",
			probe_tracker_end, NULL);
	WARN_ON(ret);

#ifdef DO_IRQ_KRETPROBE
	ret = register_kretprobe(&probe_do_irq);
	WARN_ON(ret);
#endif
	ret = 0;

	goto end;

error:
	ret = -1;
end:
	return ret;
end_unregister:
	unregister_tracepoints();
	latency_tracker_destroy(tracker);
	return ret;
}
module_init(rt_init);

static
void __exit rt_exit(void)
{
	uint64_t skipped, tracked;

	unregister_tracepoints();
#ifdef DO_IRQ_KRETPROBE
	unregister_kretprobe(&probe_do_irq);
#endif
	tracepoint_synchronize_unregister();
	skipped = latency_tracker_skipped_count(tracker);
	tracked = latency_tracker_tracked_count(tracker);
	latency_tracker_destroy(tracker);
	printk("Tracked events : %llu\n", tracked);
	printk("Missed events : %llu\n", skipped);
	printk("Tracker aborted : %d\n", tracker_aborted);
	printk("Total rt alerts : %d\n", cnt);
#ifdef BENCH
	output_measurements();
	free_measurements();
#endif
}
module_exit(rt_exit);

MODULE_AUTHOR("Julien Desfossez <jdesfossez@efficios.com>");
MODULE_LICENSE("GPL and additional rights");
MODULE_VERSION("1.0");
