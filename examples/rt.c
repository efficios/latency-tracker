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
#include <asm/stacktrace.h>
#include "../latency_tracker.h"
#include "../wrapper/tracepoint.h"
#include "../wrapper/trace-clock.h"

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

static struct latency_tracker *tracker;

static int cnt = 0;
static int failed_event_in = 0;

enum rt_key_type {
	KEY_DO_IRQ = 0,
	KEY_HARDIRQ = 1,
	KEY_RAISE_SOFTIRQ = 2,
	KEY_SOFTIRQ = 3,
	KEY_WAKEUP = 4,
	KEY_SWITCH = 5,
	KEY_TIMER_INTERRUPT = 6,
	KEY_HRTIMER = 7,
};

enum event_out_types {
	OUT_IRQHANDLER_NO_CB = 0,
	OUT_SWITCH_BLOCKED = 1,
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
	enum rt_key_type type;
} __attribute__((__packed__));

struct wakeup_key_t {
	int pid;
	enum rt_key_type type;
} __attribute__((__packed__));

struct switch_key_t {
	int pid;
	enum rt_key_type type;
} __attribute__((__packed__));

/* Keep up-to-date with the biggest struct, should use an union actually. */
#undef MAX_KEY_SIZE
#define MAX_KEY_SIZE sizeof(struct raise_softirq_key_t)

#if !defined(MAX_FILTER_STR_VAL)
#define MAX_FILTER_STR_VAL 256
#endif

struct event_data {
	unsigned int pos;
	unsigned int in_use;
	u64 prev_ts;
	char data[MAX_FILTER_STR_VAL];
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
void append_delta_ts(struct latency_tracker_event *s, char *txt, u64 ts)
{
	u64 now;
	struct event_data *data;
	char tmp[48];
	size_t len;

	if (ts)
		now = ts;
	else
		now = trace_clock_monotonic_wrapper();
	data = (struct event_data *) latency_tracker_event_get_priv_data(s);
	if (!data) {
		BUG_ON(1);
		return;
	}

	snprintf(tmp, 48, "%s = %llu, ", txt, now - data->prev_ts);
	len = strlen(tmp);
	if ((data->pos + len) > MAX_FILTER_STR_VAL)
		return;
	memcpy(data->data + data->pos, tmp, len);
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

	if (cb_out_id == OUT_IRQHANDLER_NO_CB)
		return;

	if (!data) {
		BUG_ON(1);
		return;
	}
	end_ts = data->prev_ts;
	trace_latency_tracker_rt(current->comm, current->pid,
			end_ts - start_ts, data->data);
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
	struct latency_tracker_event *s;
	u64 now = trace_clock_monotonic_wrapper();

	key.cpu = smp_processor_id();
	key.type = KEY_DO_IRQ;
	ret = _latency_tracker_event_in(tracker, &key, sizeof(key), 1, now,
			NULL);
	if (ret != LATENCY_TRACKER_OK)
		failed_event_in++;

	s = latency_tracker_get_event(tracker, &key, sizeof(key));
	if (!s) {
		BUG_ON(1);
		return 0;
	}
	append_delta_ts(s, "do_IRQ", now);
	latency_tracker_put_event(s);

#ifdef DEBUG
	printk("%llu do_IRQ (cpu %u)\n", trace_clock_monotonic_wrapper(),
			key.cpu);
#endif

	return 0;
}

static
struct kretprobe probe_do_irq = {
	.entry_handler = entry_do_irq,
	.handler = NULL,
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
	struct latency_tracker_event *event_in, *event_out;
	struct event_data *data_in, *data_out;
	u64 orig_ts;
	int ret;

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
	if (ret != LATENCY_TRACKER_OK)
		failed_event_in++;
	event_out = latency_tracker_get_event(tracker, key_out, key_out_len);
	if (!event_out)
		return NULL;
	data_out = (struct event_data *) latency_tracker_event_get_priv_data(event_out);
	if (!data_out) {
		BUG_ON(1);
		goto end;
	}
	memcpy(data_out, data_in, sizeof(struct event_data));

	latency_tracker_put_event(event_in);
	if (del)
		latency_tracker_event_out(tracker, key_in, key_in_len,
				OUT_IRQHANDLER_NO_CB);

end:
	return event_out;
}

static
void probe_local_timer_entry(void *ignore, int vector)
{
	enum latency_tracker_event_in_ret ret;
	struct local_timer_key_t key;
	struct latency_tracker_event *s;
	u64 now = trace_clock_monotonic_wrapper();

	key.cpu = smp_processor_id();
	key.type = KEY_TIMER_INTERRUPT;
	ret = _latency_tracker_event_in(tracker, &key, sizeof(key), 1, now,
			NULL);
	if (ret != LATENCY_TRACKER_OK)
		failed_event_in++;

	s = latency_tracker_get_event(tracker, &key, sizeof(key));
	if (!s) {
		BUG_ON(1);
		return;
	}
	append_delta_ts(s, "local_timer_entry", now);
	latency_tracker_put_event(s);

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

	local_timer_key.cpu = smp_processor_id();
	local_timer_key.type = KEY_TIMER_INTERRUPT;
	latency_tracker_event_out(tracker, &local_timer_key,
			sizeof(local_timer_key), OUT_IRQHANDLER_NO_CB);
}

static
void probe_irq_handler_entry(void *ignore, int irq, struct irqaction *action)
{
	struct do_irq_key_t do_irq_key;
	struct hardirq_key_t hardirq_key;
	struct latency_tracker_event *s;

	do_irq_key.cpu = smp_processor_id();
	do_irq_key.type = KEY_DO_IRQ;

	hardirq_key.cpu = smp_processor_id();
	hardirq_key.type = KEY_HARDIRQ;

	s = event_transition(&do_irq_key, sizeof(do_irq_key), &hardirq_key,
			sizeof(hardirq_key), 1);
	if (!s)
		return;
	append_delta_ts(s, "to irq_handler_entry", 0);
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

	/*
	 * If there is an IRQ event corresponding to this CPU in the HT,
	 * it means that the IRQ was not related to a RT user-space process.
	 * Otherwise it would have been removed from the softirq handler.
	 */
	hardirq_key.cpu = smp_processor_id();
	hardirq_key.type = KEY_HARDIRQ;
	latency_tracker_event_out(tracker, &hardirq_key, sizeof(hardirq_key),
			OUT_IRQHANDLER_NO_CB);
}

static
void probe_softirq_raise(void *ignore, unsigned int vec_nr)
{
	struct hardirq_key_t hardirq_key;
	struct raise_softirq_key_t raise_softirq_key;
	struct latency_tracker_event *s;

	hardirq_key.cpu = smp_processor_id();
	hardirq_key.type = KEY_HARDIRQ;

	raise_softirq_key.cpu = smp_processor_id();
	raise_softirq_key.vector = vec_nr;
	raise_softirq_key.type = KEY_RAISE_SOFTIRQ;

	s = event_transition(&hardirq_key, sizeof(hardirq_key),
			&raise_softirq_key, sizeof(raise_softirq_key), 0);
	if (!s)
		return;
	append_delta_ts(s, "to softirq_raise", 0);
	latency_tracker_put_event(s);

#ifdef DEBUG
	printk("%llu softirq_raise %u\n", trace_clock_monotonic_wrapper(),
			vec_nr);
#endif
}

static
void probe_softirq_entry(void *ignore, unsigned int vec_nr)
{
	struct raise_softirq_key_t raise_softirq_key;
	struct softirq_key_t softirq_key;
	struct latency_tracker_event *s;

	raise_softirq_key.cpu = smp_processor_id();
	raise_softirq_key.vector = vec_nr;
	raise_softirq_key.type = KEY_RAISE_SOFTIRQ;

	/*
	 * Insert the softirq_entry event.
	 * TODO: Use the CPU as key on non-RT kernel and PID on PREEMPT_RT.
	 */
	softirq_key.cpu = smp_processor_id();
	softirq_key.type = KEY_SOFTIRQ;

	s = event_transition(&raise_softirq_key, sizeof(raise_softirq_key),
			&softirq_key, sizeof(softirq_key), 1);
	if (!s)
		return;
	append_delta_ts(s, "to softirq_entry", 0);
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
	append_delta_ts(s, "to hrtimer_expire_entry", 0);
	latency_tracker_put_event(s);

#ifdef DEBUG
	printk("%llu hrtimer_entry %u\n", trace_clock_monotonic_wrapper(),
			vec_nr);
#endif
}

static
void probe_softirq_exit(void *ignore, unsigned int vec_nr)
{
	struct softirq_key_t softirq_key;
	struct latency_tracker_event *s;
	u64 orig_ts;

	/*
	 * Just cleanup the softirq_entry event
	 */
	softirq_key.cpu = smp_processor_id();
	softirq_key.type = KEY_SOFTIRQ;
	s = latency_tracker_get_event(tracker, &softirq_key, sizeof(softirq_key));
	if (!s)
		return;
	orig_ts = latency_tracker_event_get_start_ts(s);
	latency_tracker_put_event(s);
	latency_tracker_event_out(tracker, &softirq_key, sizeof(softirq_key),
			OUT_IRQHANDLER_NO_CB);
}

static
void softirq_wakeup(struct wakeup_key_t *wakeup_key)
{
	struct softirq_key_t softirq_key;
	struct latency_tracker_event *s;

	/* TODO: PREEMPT_RT */
	softirq_key.cpu = smp_processor_id();
	softirq_key.type = KEY_SOFTIRQ;

	s = event_transition(&softirq_key, sizeof(softirq_key),
			wakeup_key, sizeof(wakeup_key), 0);
	if (!s)
		return;
	append_delta_ts(s, "to sched_wakeup", 0);
	latency_tracker_put_event(s);
#ifdef DEBUG
	printk("%llu wakeup %d (%s)\n", trace_clock_monotonic_wrapper(),
			p->pid, p->comm);
#endif
}

static
void hrtimer_wakeup(struct wakeup_key_t *wakeup_key)
{
	struct hrtimer_key_t hrtimer_key;
	struct latency_tracker_event *s;

	/* TODO: PREEMPT_RT */
	hrtimer_key.cpu = smp_processor_id();
	hrtimer_key.type = KEY_HRTIMER;
	s = event_transition(&hrtimer_key, sizeof(hrtimer_key),
			wakeup_key, sizeof(wakeup_key), 0);
	if (!s)
		return;
	append_delta_ts(s, "to sched_wakeup", 0);
	latency_tracker_put_event(s);
}

static
void probe_sched_wakeup(void *ignore, struct task_struct *p, int success)
{
	/*
	 * On a non-RT kernel, if we are here while handling a softirq, lookup
	 * the softirq currently active on the current CPU to get the origin
	 * timestamp. If we are here in a thread context, we cannot deduce
	 * anything (need sched_waking instead).
	 * On a PREEMPT_RT we match on the PID of the current task instead
	 * of the CPU.
	 */
	struct wakeup_key_t wakeup_key;
	struct latency_tracker_event *s;

	/* FIXME: is it the right RCU magic to make sure p stays alive ? */
	rcu_read_lock_sched_notrace();
	if (!p)
		goto end;

	wakeup_key.pid = p->pid;
	wakeup_key.type = KEY_WAKEUP;

	/*
	 * If the process was already woken up, we cannot link
	 * its wakeup to the current event, so we exit here.
	 */
	s = latency_tracker_get_event(tracker, &wakeup_key,
			sizeof(wakeup_key));
	if (s) {
		latency_tracker_put_event(s);
		goto end;
	}

	/* In order of nesting */
	if (in_nmi()) {
		/* TODO */
		goto end;
	} else if (in_irq()) {
		/* TODO */
		goto end;
	} else if (in_serving_softirq()) {
		softirq_wakeup(&wakeup_key);
	} else {
		/* hrtimer or thread wakeup */
		hrtimer_wakeup(&wakeup_key);
	}

end:
	rcu_read_unlock_sched_notrace();
}

static
void probe_sched_switch(void *ignore, struct task_struct *prev,
		struct task_struct *next)
{
	struct wakeup_key_t wakeup_key;
	struct switch_key_t switch_key;
	struct latency_tracker_event *s;
	int ret;

	/* FIXME: is it the right RCU magic */
	rcu_read_lock_sched_notrace();
	if (!prev || !next)
		goto end;

	/* FIXME: wakeup key is not usable with sched_switch in/out chains */
	/* TODO check RT prio */
	/* sched in */
	wakeup_key.pid = next->pid;
	wakeup_key.type = KEY_WAKEUP;

	switch_key.pid = next->pid;
	switch_key.type = KEY_SWITCH;

	s = event_transition(&wakeup_key, sizeof(wakeup_key), &switch_key,
			sizeof(switch_key), 1);
	if (s) {
		append_delta_ts(s, "to sched_switch_in", 0);
		latency_tracker_put_event(s);

#ifdef DEBUG
		printk("%llu switch_in %d (%s)\n",
				trace_clock_monotonic_wrapper(),
				next->pid, next->comm);
#endif
	}

	/* switch out */
	/*
	 * If the task is still running, but just got preempted, it means that
	 * it is still actively working on an event, so we continue tracking
	 * its state until it blocks.
	 */
	if (prev->state == TASK_RUNNING)
		goto end;

	switch_key.pid = prev->pid;
	switch_key.type = KEY_SWITCH;
	s = latency_tracker_get_event(tracker, &switch_key, sizeof(switch_key));
	if (!s)
		return;
	latency_tracker_put_event(s);
	append_delta_ts(s, "to sched_switch_out", 0);
	ret = latency_tracker_event_out(tracker, &switch_key, sizeof(switch_key),
			OUT_SWITCH_BLOCKED);
#ifdef DEBUG
	if (ret == 0)
		printk("%llu switch_out %d (%s)\n",
				trace_clock_monotonic_wrapper(),
				prev->pid, prev->comm);
#endif

end:
	rcu_read_unlock_sched_notrace();
}

static
int __init rt_init(void)
{
	int ret;

	tracker = latency_tracker_create();
	if (!tracker)
		goto error;
	latency_tracker_set_startup_events(tracker, 2000);
	latency_tracker_set_max_resize(tracker, 10000);
	/* FIXME: makes us crash after rmmod */
	//latency_tracker_set_timer_period(tracker, 100000000);
	latency_tracker_set_threshold(tracker, usec_threshold * 1000);
	latency_tracker_set_timeout(tracker, usec_timeout * 1000);
	latency_tracker_set_callback(tracker, rt_cb);
	latency_tracker_set_key_size(tracker, MAX_KEY_SIZE);
	latency_tracker_set_priv_data_size(tracker, sizeof(struct event_data));
	ret = latency_tracker_enable(tracker);
	if (ret)
		goto error;

	ret = lttng_wrapper_tracepoint_probe_register("local_timer_entry",
			probe_local_timer_entry, NULL);
	WARN_ON(ret);
	ret = lttng_wrapper_tracepoint_probe_register("local_timer_exit",
			probe_local_timer_exit, NULL);
	WARN_ON(ret);
	ret = lttng_wrapper_tracepoint_probe_register("hrtimer_expire_entry",
			probe_hrtimer_expire_entry, NULL);
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

	ret = lttng_wrapper_tracepoint_probe_register("sched_wakeup",
			probe_sched_wakeup, NULL);
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
	//struct rt_tracker *rt_priv;

	lttng_wrapper_tracepoint_probe_unregister("local_timer_entry",
			probe_local_timer_entry, NULL);
	lttng_wrapper_tracepoint_probe_unregister("local_timer_exit",
			probe_local_timer_exit, NULL);
	lttng_wrapper_tracepoint_probe_unregister("hrtimer_expire_entry",
			probe_hrtimer_expire_entry, NULL);
	lttng_wrapper_tracepoint_probe_unregister("sched_switch",
			probe_sched_switch, NULL);
	lttng_wrapper_tracepoint_probe_unregister("sched_wakeup",
			probe_sched_wakeup, NULL);
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
