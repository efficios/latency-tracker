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
static int failed_event_in = 0;

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
	int switch_out_blocked;
	/* output an event when a target process write to the work_done file */
	int out_work_done;
	/* append in the payload of the event the breakdown (costly). */
	int text_breakdown;
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
	.switch_out_blocked = 0,
	.out_work_done = 0,
	.text_breakdown = 1,
	.enter_userspace = 1,
	.procname_filter_size = 0,
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
};

struct do_irq_key_t {
	unsigned int cpu;
	enum rt_key_type type;
} __attribute__((__packed__));

struct local_timer_key_t {
	unsigned int cpu;
	enum rt_key_type type;
} __attribute__((__packed__));

struct hrtimer_key_t {
	unsigned int cpu;
	enum rt_key_type type;
} __attribute__((__packed__));

struct hardirq_key_t {
	unsigned int cpu;
	enum rt_key_type type;
} __attribute__((__packed__));

struct raise_softirq_key_t {
	unsigned int cpu;
	unsigned int vector;
	enum rt_key_type type;
} __attribute__((__packed__));

struct softirq_key_t {
	unsigned int cpu;
	int pid;
	enum rt_key_type type;
} __attribute__((__packed__));

struct waking_key_t {
	int pid;
	enum rt_key_type type;
} __attribute__((__packed__));

struct switch_key_t {
	int pid;
	enum rt_key_type type;
} __attribute__((__packed__));

struct work_begin_key_t {
	char cookie[TASK_COMM_LEN];
	int cookie_size;
	enum rt_key_type type;
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
	unsigned int pos;
	unsigned int in_use;
	unsigned int preempt_count;
	u64 prev_ts;
	char userspace_proc[TASK_COMM_LEN];
	char breakdown[MAX_PAYLOAD];
} __attribute__((__packed__));

#if 0
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
void extract_stack(struct task_struct *p, char *stacktxt, uint64_t delay, int skip)
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
	//printk("%s\n%llu\n\n", p->comm, delay/1000);
}
#endif

static
void append_delta_ts(struct latency_tracker_event *s, enum rt_key_type type,
		char *txt, u64 ts, int field1, char *field2, int field3)
{
	u64 now;
	struct event_data *data;
	char tmp[64];
	size_t len;

	if (!config.text_breakdown)
		return;

	if (ts)
		now = ts;
	else
		now = trace_clock_monotonic_wrapper();
	data = (struct event_data *) latency_tracker_event_get_priv_data(s);
	if (!data) {
		BUG_ON(1);
		return;
	}
	if (data->pos == MAX_PAYLOAD) {
		data->prev_ts = now;
		return;
	}

	switch (type) {
	case KEY_DO_IRQ:
		snprintf(tmp, 64, "%s [%03d] = %llu, ", txt, smp_processor_id(),
				now - data->prev_ts);
		break;
	case KEY_HARDIRQ:
	case KEY_RAISE_SOFTIRQ:
	case KEY_SOFTIRQ:
	case KEY_WAKEUP:
		snprintf(tmp, 64, "%s(%d) [%03d] = %llu, ", txt, field1,
				smp_processor_id(), now - data->prev_ts);
		break;
	case KEY_SWITCH:
		snprintf(tmp, 64, "%s(%s-%d, %d) [%03d] = %llu, ", txt, field2,
				field1, field3, smp_processor_id(),
				now - data->prev_ts);
		break;
	case KEY_TIMER_INTERRUPT:
	case KEY_HRTIMER:
		snprintf(tmp, 64, "%s [%03d] = %llu, ", txt, smp_processor_id(),
				now - data->prev_ts);
		break;
	case KEY_WORK_DONE:
		snprintf(tmp, 64, "%s [%03d] = %llu, ", txt, smp_processor_id(),
				now - data->prev_ts);
		break;
	case KEY_WORK_BEGIN:
		snprintf(tmp, 64, "%s [%03d] = %llu, ", txt, smp_processor_id(),
				now - data->prev_ts);
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
	data->prev_ts = now;
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
	case OUT_IRQHANDLER_NO_CB:
		return;
	case OUT_SWITCH_BLOCKED:
		if (!config.switch_out_blocked)
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
	if (cb_out_id == OUT_IRQHANDLER_NO_CB)
		return;

	end_ts = data->prev_ts;
	trace_latency_tracker_rt(comm, current->pid,
			end_ts - start_ts, data->preempt_count,
			data->breakdown);
	latency_tracker_debugfs_wakeup_pipe(tracker);
	/*
	printk("%s (%d), total = %llu ns, breakdown (ns): %s\n",
			current->comm, current->pid,
			end_ts - start_ts, data->data);
			*/
}

static
int entry_do_irq(struct kretprobe_instance *p, struct pt_regs *regs)
{
	enum latency_tracker_event_in_ret ret;
	struct do_irq_key_t key;
	u64 now;

	if (!config.irq_tracing)
		return 0;

	now = trace_clock_monotonic_wrapper();
	key.cpu = smp_processor_id();
	key.type = KEY_DO_IRQ;
	ret = _latency_tracker_event_in(tracker, &key, sizeof(key), 1, now,
			NULL);
	if (ret != LATENCY_TRACKER_OK) {
		failed_event_in++;
		return 0;
	}

	if (config.text_breakdown) {
		struct latency_tracker_event *s;

		s = latency_tracker_get_event(tracker, &key, sizeof(key));
		if (!s) {
			BUG_ON(1);
			return 0;
		}
		append_delta_ts(s, KEY_DO_IRQ, "do_IRQ", now, 0, NULL, 0);
		latency_tracker_put_event(s);
	}

#ifdef DEBUG
	printk("%llu do_IRQ (cpu %u)\n", trace_clock_monotonic_wrapper(),
			key.cpu);
#endif

	return 0;
}

static
int exit_do_irq(struct kretprobe_instance *p, struct pt_regs *regs)
{
	struct do_irq_key_t key;

	if (!config.irq_tracing)
		return 0;
	key.cpu = smp_processor_id();
	key.type = KEY_DO_IRQ;
	latency_tracker_event_out(tracker, &key,
			sizeof(key), OUT_IRQHANDLER_NO_CB, 0);

	return 0;
}

static
struct kretprobe probe_do_irq = {
	.entry_handler = entry_do_irq,
	.handler = exit_do_irq,
	.kp.symbol_name = "do_IRQ",
};

/*
 * Lookup the key_in, if it does not exist return NULL.
 * Otherwise:
 * - create the key_out with the original timestamp
 * - copy the payload of key_in to key_out
 * - if del == 1: delete the original key
 * - return event_out (needs to be "put" afterwards)
 */
static
struct latency_tracker_event *event_transition(void *key_in, int key_in_len,
		void *key_out, int key_out_len, int del)
{
	struct latency_tracker_event *event_in = NULL, *event_out = NULL;
	struct event_data *data_in, *data_out;
	u64 orig_ts;
	int ret;

	/* TODO: loop here to handle duplicates when del == 1 */
	event_in = latency_tracker_get_event(tracker, key_in, key_in_len);
	if (!event_in)
		return NULL;
	data_in = (struct event_data *) latency_tracker_event_get_priv_data(event_in);
	if (!data_in) {
		BUG_ON(1);
		goto end;
	}
	orig_ts = latency_tracker_event_get_start_ts(event_in);

	ret = _latency_tracker_event_in(tracker, key_out,
			key_out_len, 1, orig_ts, NULL);
	if (ret != LATENCY_TRACKER_OK) {
		goto end_del;
		failed_event_in++;
	}
	event_out = latency_tracker_get_event(tracker, key_out, key_out_len);
	if (!event_out)
		return NULL;
	data_out = (struct event_data *) latency_tracker_event_get_priv_data(event_out);
	if (!data_out) {
		BUG_ON(1);
		goto end;
	}
	memcpy(data_out, data_in, sizeof(struct event_data));

end_del:
	if (del)
		latency_tracker_event_out(tracker, key_in, key_in_len,
				OUT_IRQHANDLER_NO_CB, 0);

end:
	latency_tracker_put_event(event_in);
	return event_out;
}

static
void probe_local_timer_entry(void *ignore, int vector)
{
	enum latency_tracker_event_in_ret ret;
	struct local_timer_key_t key;
	u64 now;

	if (!config.timer_tracing)
		return;

	now = trace_clock_monotonic_wrapper();
	key.cpu = smp_processor_id();
	key.type = KEY_TIMER_INTERRUPT;
	ret = _latency_tracker_event_in(tracker, &key, sizeof(key), 1, now,
			NULL);
	if (ret != LATENCY_TRACKER_OK) {
		failed_event_in++;
		return;
	}

	if (config.text_breakdown) {
		struct latency_tracker_event *s;
		s = latency_tracker_get_event(tracker, &key, sizeof(key));
		if (!s) {
			BUG_ON(1);
			return;
		}
		append_delta_ts(s, KEY_TIMER_INTERRUPT, "local_timer_entry", now,
				vector, NULL, 0);
		latency_tracker_put_event(s);
	}

#ifdef DEBUG
	printk("%llu local_timer_entry (cpu %u)\n", trace_clock_monotonic_wrapper(),
			key.cpu);
#endif

	return;
}

static
void probe_local_timer_exit(void *ignore, int vector)
{
	struct local_timer_key_t local_timer_key;

	if (!config.timer_tracing)
		return;
	local_timer_key.cpu = smp_processor_id();
	local_timer_key.type = KEY_TIMER_INTERRUPT;
	latency_tracker_event_out(tracker, &local_timer_key,
			sizeof(local_timer_key), OUT_IRQHANDLER_NO_CB, 0);
}

static
void probe_irq_handler_entry(void *ignore, int irq, struct irqaction *action)
{
	struct do_irq_key_t do_irq_key;
	struct hardirq_key_t hardirq_key;
	struct latency_tracker_event *s;

	if (!config.irq_tracing)
		return;

	if (config.irq_filter > 0 && config.irq_filter != irq) {
		exit_do_irq(NULL, NULL);
		return;
	}

	do_irq_key.cpu = smp_processor_id();
	do_irq_key.type = KEY_DO_IRQ;

	hardirq_key.cpu = smp_processor_id();
	hardirq_key.type = KEY_HARDIRQ;

	s = event_transition(&do_irq_key, sizeof(do_irq_key), &hardirq_key,
			sizeof(hardirq_key), 0);
	if (!s)
		return;
	append_delta_ts(s, KEY_HARDIRQ, "to irq_handler_entry", 0, irq,
			NULL, 0);
	latency_tracker_put_event(s);

#ifdef DEBUG
		printk("%llu hard_irq_entry (cpu: %u)\n", trace_clock_monotonic_wrapper(),
				do_irq_key.cpu);
#endif
}

static
void probe_irq_handler_exit(void *ignore, int irq, struct irqaction *action,
		int ret)
{
	struct hardirq_key_t hardirq_key;

	if (!config.irq_tracing)
		return;

	if (config.irq_filter > 0 && config.irq_filter != irq) {
		exit_do_irq(NULL, NULL);
		return;
	}

	hardirq_key.cpu = smp_processor_id();
	hardirq_key.type = KEY_HARDIRQ;

	if (config.text_breakdown) {
		struct latency_tracker_event *s;

		s = latency_tracker_get_event(tracker, &hardirq_key,
				sizeof(hardirq_key));
		if (!s)
			goto end;
		append_delta_ts(s, KEY_HARDIRQ, "to irq_handler_exit", 0,
				irq, NULL, 0);
		latency_tracker_put_event(s);
	}

	latency_tracker_event_out(tracker, &hardirq_key, sizeof(hardirq_key),
			OUT_IRQHANDLER_NO_CB, 0);

end:
	return;
}

#ifdef CONFIG_PREEMPT_RT_FULL
static
void probe_softirq_raise(void *ignore, unsigned int vec_nr)
{
	struct raise_softirq_key_t raise_softirq_key;
	struct switch_key_t switch_key;
	struct latency_tracker_event *s;

	if (config.softirq_filter > 0 && config.softirq_filter != vec_nr)
		return;

	switch_key.pid = current->pid;
	switch_key.type = KEY_SWITCH;

	raise_softirq_key.cpu = smp_processor_id();
	raise_softirq_key.vector = vec_nr;
	raise_softirq_key.type = KEY_RAISE_SOFTIRQ;

	s = event_transition(&switch_key, sizeof(switch_key),
			&raise_softirq_key, sizeof(raise_softirq_key), 0);
	if (!s)
		return;
	append_delta_ts(s, KEY_RAISE_SOFTIRQ, "to softirq_raise", 0,
			vec_nr, NULL, 0);
	latency_tracker_put_event(s);

#ifdef DEBUG
	printk("%llu softirq_raise %u\n", trace_clock_monotonic_wrapper(),
			vec_nr);
#endif
}
#else /* CONFIG_PREEMPT_RT_FULL */
static
void probe_softirq_raise(void *ignore, unsigned int vec_nr)
{
	struct hardirq_key_t hardirq_key;
	struct raise_softirq_key_t raise_softirq_key;
	struct latency_tracker_event *s;

	if (config.softirq_filter > 0 && config.softirq_filter != vec_nr)
		return;

	hardirq_key.cpu = smp_processor_id();
	hardirq_key.type = KEY_HARDIRQ;

	raise_softirq_key.cpu = smp_processor_id();
	raise_softirq_key.vector = vec_nr;
	raise_softirq_key.type = KEY_RAISE_SOFTIRQ;

	s = event_transition(&hardirq_key, sizeof(hardirq_key),
			&raise_softirq_key, sizeof(raise_softirq_key), 0);
	if (!s)
		return;
	append_delta_ts(s, KEY_RAISE_SOFTIRQ, "to softirq_raise", 0,
			vec_nr, NULL, 0);
	latency_tracker_put_event(s);

#ifdef DEBUG
	printk("%llu softirq_raise %u\n", trace_clock_monotonic_wrapper(),
			vec_nr);
#endif
}
#endif /* CONFIG_PREEMPT_RT_FULL */

static
void probe_softirq_entry(void *ignore, unsigned int vec_nr)
{
	struct raise_softirq_key_t raise_softirq_key;
	struct softirq_key_t softirq_key;
	struct latency_tracker_event *s;

	if (config.softirq_filter > 0 && config.softirq_filter != vec_nr)
		return;

	raise_softirq_key.cpu = smp_processor_id();
	raise_softirq_key.vector = vec_nr;
	raise_softirq_key.type = KEY_RAISE_SOFTIRQ;

	/*
	 * Insert the softirq_entry event.
	 * TODO: Use the CPU as key on non-RT kernel and PID on PREEMPT_RT.
	 */
	softirq_key.cpu = smp_processor_id();
	softirq_key.pid = current->pid;
	softirq_key.type = KEY_SOFTIRQ;

	s = event_transition(&raise_softirq_key, sizeof(raise_softirq_key),
			&softirq_key, sizeof(softirq_key), 1);
	if (!s)
		return;
	append_delta_ts(s, KEY_SOFTIRQ, "to softirq_entry", 0, vec_nr, NULL, 0);
	latency_tracker_put_event(s);

#ifdef DEBUG
	printk("%llu softirq_entry %u\n", trace_clock_monotonic_wrapper(),
			vec_nr);
#endif
}

static
void probe_hrtimer_expire_entry(void *ignore, struct hrtimer *hrtimer,
		ktime_t *now)
{
	struct local_timer_key_t local_timer_key;
	struct hrtimer_key_t hrtimer_key;
	struct latency_tracker_event *s;

	if (!config.timer_tracing)
		return;
	local_timer_key.cpu = smp_processor_id();
	local_timer_key.type = KEY_TIMER_INTERRUPT;

	/*
	 * Insert the hrtimer_expire_entry event.
	 * TODO: Use the CPU as key on non-RT kernel and PID on PREEMPT_RT.
	 */
	hrtimer_key.cpu = smp_processor_id();
	hrtimer_key.type = KEY_HRTIMER;

	s = event_transition(&local_timer_key, sizeof(local_timer_key),
			&hrtimer_key, sizeof(hrtimer_key), 0);
	if (!s)
		return;
	append_delta_ts(s, KEY_HRTIMER, "to hrtimer_expire_entry", 0, -1,
			NULL, 0);
	latency_tracker_put_event(s);

#ifdef DEBUG
	printk("%llu hrtimer_entry %u\n", trace_clock_monotonic_wrapper(),
			vec_nr);
#endif
}

static
void probe_hrtimer_expire_exit(void *ignore, struct timer_list *timer)
{
	struct hrtimer_key_t hrtimer_key;

	if (!config.timer_tracing)
		return;
	hrtimer_key.cpu = smp_processor_id();
	hrtimer_key.type = KEY_HRTIMER;

	/*
	 * Insert the hrtimer_expire_entry event.
	 * TODO: Use the CPU as key on non-RT kernel and PID on PREEMPT_RT.
	 */
	hrtimer_key.cpu = smp_processor_id();
	hrtimer_key.type = KEY_HRTIMER;

	latency_tracker_event_out(tracker, &hrtimer_key, sizeof(hrtimer_key),
			OUT_IRQHANDLER_NO_CB, 0);
}

static
void probe_softirq_exit(void *ignore, unsigned int vec_nr)
{
	struct softirq_key_t softirq_key;

	if (config.softirq_filter > 0 && config.softirq_filter != vec_nr)
		return;

	/*
	 * Just cleanup the softirq_entry event
	 */
	softirq_key.cpu = smp_processor_id();
	softirq_key.pid = current->pid;
	softirq_key.type = KEY_SOFTIRQ;
	if (config.text_breakdown) {
		struct latency_tracker_event *s;

		s = latency_tracker_get_event(tracker, &softirq_key,
				sizeof(softirq_key));
		if (!s)
			return;
		append_delta_ts(s, KEY_SOFTIRQ, "to softirq_exit", 0, vec_nr,
				NULL, 0);
		latency_tracker_put_event(s);
	}
	latency_tracker_event_out(tracker, &softirq_key, sizeof(softirq_key),
			OUT_IRQHANDLER_NO_CB, 0);
}

static
void irq_waking(struct waking_key_t *waking_key)
{
	struct latency_tracker_event *s;
	struct do_irq_key_t do_irq_key;

	do_irq_key.cpu = smp_processor_id();
	do_irq_key.type = KEY_DO_IRQ;

	s = event_transition(&do_irq_key, sizeof(do_irq_key),
			waking_key, sizeof(waking_key), 0);
	if (!s)
		return;
	append_delta_ts(s, KEY_WAKEUP, "to sched_waking", 0, waking_key->pid,
			NULL, 0);
	latency_tracker_put_event(s);
#ifdef DEBUG
	printk("%llu waking %d (%s)\n", trace_clock_monotonic_wrapper(),
			p->pid, p->comm);
#endif
}

static
void softirq_waking(struct waking_key_t *waking_key)
{
	struct softirq_key_t softirq_key;
	struct latency_tracker_event *s;

	softirq_key.cpu = smp_processor_id();
	softirq_key.pid = current->pid;
	softirq_key.type = KEY_SOFTIRQ;

	s = event_transition(&softirq_key, sizeof(softirq_key),
			waking_key, sizeof(waking_key), 0);
	if (!s)
		return;
	append_delta_ts(s, KEY_WAKEUP, "to sched_waking", 0, waking_key->pid,
			NULL, 0);
	latency_tracker_put_event(s);
#ifdef DEBUG
	printk("%llu waking %d (%s)\n", trace_clock_monotonic_wrapper(),
			p->pid, p->comm);
#endif
}

/*
 * Return 0 if the waking did not originate from a hrtimer
 */
static
int hrtimer_waking(struct waking_key_t *waking_key)
{
	struct hrtimer_key_t hrtimer_key;
	struct latency_tracker_event *s;

	/* TODO: PREEMPT_RT */
	hrtimer_key.cpu = smp_processor_id();
	hrtimer_key.type = KEY_HRTIMER;
	s = event_transition(&hrtimer_key, sizeof(hrtimer_key),
			waking_key, sizeof(waking_key), 0);
	if (!s)
		return 0;
	append_delta_ts(s, KEY_WAKEUP, "to sched_waking", 0, waking_key->pid,
			NULL, 0);
	latency_tracker_put_event(s);
	return 1;
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
	struct latency_tracker_event *s;
	u64 now = trace_clock_monotonic_wrapper();

	switch_key.pid = current->pid;
	switch_key.type = KEY_SWITCH;

	s = event_transition(&switch_key, sizeof(switch_key), waking_key,
			sizeof(waking_key), 0);
	if (s) {
		/* switch_in after a waking */
		append_delta_ts(s, KEY_WAKEUP, "to sched_waking", now,
				waking_key->pid, NULL, 0);
		latency_tracker_put_event(s);
	}

	s = latency_tracker_get_event(tracker, &switch_key,
			sizeof(switch_key));
	if (s) {
		append_delta_ts(s, KEY_WAKEUP, "to sched_waking", now,
				waking_key->pid, NULL, 0);
		latency_tracker_put_event(s);
	}
}

static
void probe_sched_waking(void *ignore, struct task_struct *p, int success)
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
	struct latency_tracker_event *s;

	/* FIXME: do we need some RCU magic here to make sure p stays alive ? */
	if (!p)
		goto end;

	/*
	 * TODO: allow non-unique inserts here.
	 * This would allow multiple processes to be waiting for the same
	 * target process.
	 */

	waking_key.pid = p->pid;
	waking_key.type = KEY_WAKEUP;

	/*
	 * If the process was already woken up, we cannot link
	 * its waking to the current event, so we exit here.
	 */
	s = latency_tracker_get_event(tracker, &waking_key,
			sizeof(waking_key));
	if (s) {
		latency_tracker_put_event(s);
		goto end;
	}

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
	struct latency_tracker_event *s;
	struct switch_key_t switch_key;
	struct event_data *data;
	u64 now = trace_clock_monotonic_wrapper();

	switch_key.pid = next->pid;
	switch_key.type = KEY_SWITCH;

	/* We can switch from a wakeup/waking or after being preempted */

	/* sched in */
	waking_key.pid = next->pid;
	waking_key.type = KEY_WAKEUP;

	s = event_transition(&waking_key, sizeof(waking_key), &switch_key,
			sizeof(switch_key), 1);
	if (s) {
		/* switch_in after a waking */
		append_delta_ts(s, KEY_SWITCH, "to switch_in", now, next->pid,
				next->comm, wrapper_task_prio(next));
		data = (struct event_data *) latency_tracker_event_get_priv_data(s);
		strncpy(data->userspace_proc, next->comm, TASK_COMM_LEN);
		latency_tracker_put_event(s);
		if (config.enter_userspace && next->mm) {
			latency_tracker_event_out(tracker, &switch_key,
					sizeof(switch_key),
					OUT_ENTER_USERSPACE, now);
		}
	} else {
		if (config.text_breakdown) {
			/* switch after a preempt */
			s = latency_tracker_get_event(tracker, &switch_key,
					sizeof(switch_key));
			if (!s)
				goto end;
			append_delta_ts(s, KEY_SWITCH, "to switch_in", now,
					next->pid, next->comm,
					wrapper_task_prio(next));
			latency_tracker_put_event(s);
		}
	}

#ifdef DEBUG
	printk("%llu switch_in %d (%s)\n",
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
	u64 now = trace_clock_monotonic_wrapper();

	/* switch out */
	switch_key.pid = prev->pid;
	switch_key.type = KEY_SWITCH;
	if (config.text_breakdown) {
		struct latency_tracker_event *s;

		s = latency_tracker_get_event(tracker, &switch_key,
				sizeof(switch_key));
		if (!s)
			goto end;
		if (prev->state == TASK_RUNNING) {
			struct event_data *data;

			append_delta_ts(s, KEY_SWITCH, "to switch_out", now,
					next->pid, next->comm,
					wrapper_task_prio(next));
			data = (struct event_data *)
				latency_tracker_event_get_priv_data(s);
			if (!data)
				return;
			data->preempt_count++;
		} else {
			append_delta_ts(s, KEY_SWITCH,
					"to switch_out_blocked", now,
					next->pid, next->comm,
					wrapper_task_prio(next));
		}
		latency_tracker_put_event(s);
	}

	/*
	 * If the task is still running, but just got preempted, it means that
	 * it is still actively working on an event, so we continue tracking
	 * its state until it blocks.
	 */
	if (prev->state == TASK_RUNNING)
		goto end;

	ret = latency_tracker_event_out(tracker, &switch_key, sizeof(switch_key),
			OUT_SWITCH_BLOCKED, now);
#ifdef DEBUG
	if (ret == 0)
		printk("%llu switch_out %d (%s)\n",
				trace_clock_read64(),
				prev->pid, prev->comm);
#endif
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
	/* FIXME: do we need some RCU magic here to make sure p stays alive ? */
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

static
ssize_t write_work_done(struct file *filp, const char __user *ubuf,
		size_t cnt, loff_t *ppos)
{
	int ret, r;
	struct latency_tracker_event *s;
	struct work_begin_key_t work_begin_key;
	//struct tracker_config *cfg = filp->private_data;
	u64 now = trace_clock_monotonic_wrapper();

	if (!config.out_work_done)
		return -EINVAL;

	/*
	 * The data is unused for now, but it might become an ID
	 * someday on which we could apply filters.
	 */
	r = min_t(unsigned int, cnt, sizeof(work_begin_key.cookie));
	memset(&work_begin_key.cookie, 0, sizeof(work_begin_key.cookie));
	ret = copy_from_user(&work_begin_key.cookie, ubuf, r);
	if (ret)
		return ret;

	/*
	 * If we got \n or \0, we don't expect to find a cookie created
	 * by work_begin, so lookup the current process instead.
	 */
	if (r == 1 && (work_begin_key.cookie[0] == '\n' ||
				work_begin_key.cookie[0] == '\0')) {
		struct switch_key_t switch_key;

		/*
		 * The current process should be tracked otherwise we can't
		 * link this event to an origin.
		 */
		switch_key.pid = current->pid;
		switch_key.type = KEY_SWITCH;
		if (config.text_breakdown) {
			s = latency_tracker_get_event(tracker, &switch_key,
					sizeof(switch_key));
			if (!s)
				return -ENOENT;
			append_delta_ts(s, KEY_WORK_DONE, "to work_done", now, 0,
					NULL, 0);
			latency_tracker_put_event(s);
		}

		ret = latency_tracker_event_out(tracker, &switch_key,
				sizeof(switch_key),
				OUT_WORK_DONE, now);
	} else {
		work_begin_key.cookie_size = r;
		work_begin_key.type = KEY_WORK_BEGIN;

		if (config.text_breakdown) {
			s = latency_tracker_get_event(tracker, &work_begin_key,
					sizeof(work_begin_key));
			if (!s)
				return -ENOENT;
			append_delta_ts(s, KEY_WORK_DONE, "to work_done", now, 0,
					NULL, 0);
			latency_tracker_put_event(s);
		}

		ret = latency_tracker_event_out(tracker, &work_begin_key,
				sizeof(work_begin_key),
				OUT_WORK_DONE, now);
	}

	return cnt;
}

static const
struct file_operations work_done_fops = {
	.open           = latency_open_generic,
	.write          = write_work_done,
};

/*
 * This should be called from a task that has been woken up in the
 * path of interrupt processing.
 * FIXME: what happens if the task was already awake when the interrupt
 * arrived ?
 */
static
ssize_t write_work_begin(struct file *filp, const char __user *ubuf,
		size_t cnt, loff_t *ppos)
{
	int ret, r;
	struct switch_key_t switch_key;
	struct work_begin_key_t work_begin_key;
	struct latency_tracker_event *s;
	u64 now = trace_clock_monotonic_wrapper();

	r = min_t(unsigned int, cnt, sizeof(work_begin_key.cookie));
	memset(&work_begin_key.cookie, 0, sizeof(work_begin_key.cookie));
	ret = copy_from_user(&work_begin_key.cookie, ubuf, r);
	if (ret)
		return ret;

	/*
	 * Cookies must be strings, just a "echo > work_begin" is not
	 * accepted, empty strings are valid for work_done if no cookie was
	 * created.
	 */
	if (r == 1 && (work_begin_key.cookie[0] == '\n' ||
				work_begin_key.cookie[0] == '\0'))
		return -EINVAL;

	/*
	 * The current process should be tracked otherwise we can't link
	 * this event to an origin.
	 */
	switch_key.pid = current->pid;
	switch_key.type = KEY_SWITCH;

	work_begin_key.cookie_size = r;
	work_begin_key.type = KEY_WORK_BEGIN;

	/*
	 * From now on, only a work_done event can complete this branch.
	 */
	s = event_transition(&switch_key, sizeof(switch_key),
			&work_begin_key, sizeof(work_begin_key), 1);
	if (!s)
		return -ENOENT;
	append_delta_ts(s, KEY_WORK_BEGIN, "to work_begin", now, 0, NULL, 0);
	latency_tracker_put_event(s);

	return cnt;
}

static const
struct file_operations work_begin_fops = {
	.open           = latency_open_generic,
	.write          = write_work_begin,
};

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

	file = debugfs_create_u32("switch_out_blocked",
			S_IRUSR|S_IWUSR, filters_dir, &config.switch_out_blocked);
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

	file = debugfs_create_file("work_done", S_IWUSR,
			actions_dir, &config, &work_done_fops);
	if (!file)
		goto error;

	file = debugfs_create_file("work_begin", S_IWUSR,
			actions_dir, &config, &work_begin_fops);
	if (!file)
		goto error;

	ret = latency_tracker_debugfs_setup_wakeup_pipe(tracker);
	if (ret != 0)
		goto error;

	return 0;

error:
	return -1;
}

static
int __init rt_init(void)
{
	int ret;

	tracker = latency_tracker_create("rt");
	if (!tracker)
		goto error;
	latency_tracker_set_startup_events(tracker, 10000);
	latency_tracker_set_max_resize(tracker, 10000);
	/* FIXME: makes us crash after rmmod */
	//latency_tracker_set_timer_period(tracker, 100000000);
	latency_tracker_set_threshold(tracker, usec_threshold * 1000);
	latency_tracker_set_timeout(tracker, usec_timeout * 1000);
	latency_tracker_set_callback(tracker, rt_cb);
	latency_tracker_set_key_size(tracker, MAX_KEY_SIZE);
	latency_tracker_set_priv_data_size(tracker, sizeof(struct event_data));
	ret = setup_debugfs_extras();
	if (ret != 0)
		goto error;

	ret = latency_tracker_enable(tracker);
	if (ret)
		goto error;

	if (!timer_tracing)
		config.timer_tracing = 0;

	ret = lttng_wrapper_tracepoint_probe_register("local_timer_entry",
			probe_local_timer_entry, NULL);
	WARN_ON(ret);
	ret = lttng_wrapper_tracepoint_probe_register("local_timer_exit",
			probe_local_timer_exit, NULL);
	WARN_ON(ret);
	ret = lttng_wrapper_tracepoint_probe_register("hrtimer_expire_entry",
			probe_hrtimer_expire_entry, NULL);
	WARN_ON(ret);
	ret = lttng_wrapper_tracepoint_probe_register("hrtimer_expire_exit",
			probe_hrtimer_expire_exit, NULL);
	WARN_ON(ret);
	ret = lttng_wrapper_tracepoint_probe_register("irq_handler_entry",
			probe_irq_handler_entry, NULL);
	WARN_ON(ret);

	ret = lttng_wrapper_tracepoint_probe_register("irq_handler_exit",
			probe_irq_handler_exit, NULL);
	WARN_ON(ret);

	ret = lttng_wrapper_tracepoint_probe_register("softirq_raise",
			probe_softirq_raise, NULL);
	WARN_ON(ret);

	ret = lttng_wrapper_tracepoint_probe_register("softirq_entry",
			probe_softirq_entry, NULL);
	WARN_ON(ret);

	ret = lttng_wrapper_tracepoint_probe_register("softirq_exit",
			probe_softirq_exit, NULL);
	WARN_ON(ret);

	ret = lttng_wrapper_tracepoint_probe_register("sched_switch",
			probe_sched_switch, NULL);
	WARN_ON(ret);

	ret = lttng_wrapper_tracepoint_probe_register("sched_waking",
			probe_sched_waking, NULL);
	WARN_ON(ret);

	ret = register_kretprobe(&probe_do_irq);
	WARN_ON(ret);

	goto end;

error:
	ret = -1;
end:
	return ret;
}
module_init(rt_init);

static
void __exit rt_exit(void)
{
	uint64_t skipped;

	lttng_wrapper_tracepoint_probe_unregister("local_timer_entry",
			probe_local_timer_entry, NULL);
	lttng_wrapper_tracepoint_probe_unregister("local_timer_exit",
			probe_local_timer_exit, NULL);
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
	unregister_kretprobe(&probe_do_irq);
	tracepoint_synchronize_unregister();
	skipped = latency_tracker_skipped_count(tracker);
	latency_tracker_destroy(tracker);
	printk("Missed events : %llu\n", skipped);
	printk("Failed event in : %d\n", failed_event_in);
	printk("Total rt alerts : %d\n", cnt);
}
module_exit(rt_exit);

MODULE_AUTHOR("Julien Desfossez <jdesfossez@efficios.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
