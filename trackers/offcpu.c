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
#include <linux/jhash.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/stacktrace.h>
#include <asm/stacktrace.h>
#include "offcpu.h"
#include "../latency_tracker.h"
#include "../wrapper/tracepoint.h"
#include "../wrapper/trace-clock.h"
#include "../wrapper/lt_probe.h"

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

static pid_t current_pid[NR_CPUS];

/*
 * microseconds because we can't guarantee the passing of 64-bit
 * arguments to insmod on all architectures.
 */
static unsigned long usec_threshold = DEFAULT_USEC_OFFCPU_THRESH;
module_param(usec_threshold, ulong, 0444);
MODULE_PARM_DESC(usec_threshold, "Threshold in microseconds");

static unsigned long usec_timeout = DEFAULT_USEC_OFFCPU_TIMEOUT;
module_param(usec_timeout, ulong, 0444);
MODULE_PARM_DESC(usec_timeout, "Timeout in microseconds");

struct schedkey {
	pid_t pid;
	unsigned int cpu;
} __attribute__((__packed__));
#undef MAX_KEY_SIZE
#define MAX_KEY_SIZE sizeof(struct schedkey)

enum sched_exitcode {
	SCHED_EXIT_NORMAL = 0,
	SCHED_EXIT_DIED = 1,
};

static struct latency_tracker *tracker;

static int cnt = 0;

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

	save_stack_trace(&trace);

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

static
void offcpu_cb(struct latency_tracker_event_ctx *ctx)
{
	uint64_t end_ts = latency_tracker_event_ctx_get_end_ts(ctx);
	uint64_t start_ts = latency_tracker_event_ctx_get_start_ts(ctx);
	enum latency_tracker_cb_flag cb_flag = latency_tracker_event_ctx_get_cb_flag(ctx);
	unsigned int cb_out_id = latency_tracker_event_ctx_get_cb_out_id(ctx);
	struct schedkey *key = (struct schedkey *) latency_tracker_event_ctx_get_key(ctx)->key;
	struct offcpu_tracker *offcpu_priv =
		(struct offcpu_tracker *) latency_tracker_get_priv(tracker);
	struct task_struct *p;
	char stacktxt[MAX_STACK_TXT];
	u64 delay;

	if (cb_flag != LATENCY_TRACKER_CB_NORMAL)
		return;
	if (cb_out_id == SCHED_EXIT_DIED)
		return;

	delay = end_ts - start_ts;
	do_div(delay, 1000);

#ifdef SCHEDWORST
	usec_threshold = delay;
#endif

	rcu_read_lock();
	p = pid_task(find_vpid(key->pid), PIDTYPE_PID);
	if (!p)
		goto end;
//	printk("offcpu: sched_switch %s (%d) %llu us\n", p->comm, key->pid, delay);
	extract_stack(p, stacktxt, delay, 0);
	trace_latency_tracker_offcpu_sched_switch(p->comm, key->pid, end_ts - start_ts,
			cb_flag, stacktxt);
	cnt++;
	offcpu_handle_proc(offcpu_priv, end_ts);

end:
	rcu_read_unlock();
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0))
LT_PROBE_DEFINE(sched_switch, bool preempt, struct task_struct *prev,
		struct task_struct *next)
#else
LT_PROBE_DEFINE(sched_switch, struct task_struct *prev,
		struct task_struct *next)
#endif
{
	struct schedkey key;
	enum latency_tracker_event_in_ret ret;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	rcu_read_lock();
	if (!next || !prev)
		goto end;
	current_pid[prev->on_cpu] = next->pid;

	key.pid = prev->pid;
	key.cpu = smp_processor_id();
	ret = latency_tracker_event_in(tracker, &key, sizeof(key),
			1, latency_tracker_get_priv(tracker));

	key.pid = next->pid;
	key.cpu = smp_processor_id();
	latency_tracker_event_out(tracker, NULL, &key, sizeof(key),
			SCHED_EXIT_NORMAL, 0);
end:
	rcu_read_unlock();
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0) || \
	LT_RT_KERNEL_RANGE(4,1,10,11, 4,2,0,0))
LT_PROBE_DEFINE(sched_waking, struct task_struct *p)
#else
LT_PROBE_DEFINE(sched_waking, struct task_struct *p, int success)
#endif
{
	struct schedkey key;
	char stacktxt_waker[MAX_STACK_TXT];
	struct latency_tracker_event *s;
	u64 now, delta;
	int i;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	/*
	 * Make sure we are not waking up a process already running on
	 * another CPU.
	 */
	for (i = 0; i < NR_CPUS; i++)
		if (current_pid[i] == p->pid)
			return;

	rcu_read_lock();
	key.pid = p->pid;
	key.cpu = smp_processor_id();
	s = latency_tracker_get_event_by_key(tracker, &key, sizeof(key), NULL);
	if (!s)
		goto end;
	now = trace_clock_read64();
	delta = now - latency_tracker_event_get_start_ts(s);
	if (delta > (usec_threshold * 1000)) {
		/* skip our own stack (3 levels) */
		extract_stack(current, stacktxt_waker, 0, 3);
		trace_latency_tracker_offcpu_sched_wakeup(current, stacktxt_waker, p, delta, 0);
	}
	latency_tracker_unref_event(s);

end:
	rcu_read_unlock();
	return;
}

static
u32 hash_fct(const void *key, u32 length, u32 initval)
{
	struct schedkey *k = (struct schedkey *) key;

	return jhash((void *) &(k->pid), sizeof(k->pid), 0);
}

static
int match_fct(const void *key1, const void *key2, size_t length)
{
	struct schedkey *k1, *k2;

	k1 = (struct schedkey *) key1;
	k2 = (struct schedkey *) key2;

	/*
	 * There is one PID 0 per cpu, so we have to make sure when
	 * dealing with PID 0 that it is for the same CPU.
	 */
	if (k1->pid == 0 && k2->pid == 0) {
		if (k1->cpu == k2->cpu)
			return 0;
	} else if (k1->pid == k2->pid) {
		return 0;
	}
	return 1;
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

	tracker = latency_tracker_create("offcpu");
	if (!tracker)
		goto error;
	latency_tracker_set_startup_events(tracker, 2000);
	latency_tracker_set_max_resize(tracker, 10000);
	latency_tracker_set_timer_period(tracker, 100000000);
	latency_tracker_set_priv(tracker, offcpu_priv);
	latency_tracker_set_threshold(tracker, usec_threshold * 1000);
	latency_tracker_set_timeout(tracker, usec_timeout * 1000);
	latency_tracker_set_callback(tracker, offcpu_cb);
	latency_tracker_set_hash_fct(tracker, hash_fct);
	latency_tracker_set_match_fct(tracker, match_fct);
	latency_tracker_set_key_size(tracker, MAX_KEY_SIZE);

	ret = offcpu_setup_priv(offcpu_priv);
	WARN_ON(ret);

	ret = lttng_wrapper_tracepoint_probe_register("sched_switch",
			probe_sched_switch, NULL);
	WARN_ON(ret);

	ret = lttng_wrapper_tracepoint_probe_register("sched_waking",
			probe_sched_waking, NULL);
	WARN_ON(ret);

	goto end;

error:
	ret = -1;
	offcpu_destroy_priv(offcpu_priv);
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
	lttng_wrapper_tracepoint_probe_unregister("sched_waking",
			probe_sched_waking, NULL);
	tracepoint_synchronize_unregister();
	skipped = latency_tracker_skipped_count(tracker);
	offcpu_priv = latency_tracker_get_priv(tracker);
	offcpu_destroy_priv(offcpu_priv);
	latency_tracker_destroy(tracker);
	printk("Missed events : %llu\n", skipped);
	printk("Total offcpu alerts : %d\n", cnt);
}
module_exit(offcpu_exit);

MODULE_AUTHOR("Julien Desfossez <jdesfossez@efficios.com>");
MODULE_LICENSE("GPL and additional rights");
MODULE_VERSION("1.0");
