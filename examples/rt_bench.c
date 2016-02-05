/*
 * Copyright (C) 2016 Julien Desfossez <jdesfossez@efficios.com>
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

#include <linux/cpumask.h>
#include <linux/slab.h>

#include "../wrapper/trace-clock.h"
#include "../wrapper/tracepoint.h"
#include "rt_bench.h"

//#define BENCHMARK 1

#ifdef BENCHMARK

static u64 *begin_ts;


BENCH_PROBE_DEFINE(local_timer_entry, int vector);
BENCH_PROBE_DEFINE(local_timer_exit, int vector);
BENCH_PROBE_DEFINE(hrtimer_expire_entry, struct hrtimer *hrtimer, ktime_t *now);
BENCH_PROBE_DEFINE(hrtimer_expire_exit, struct timer_list *timer);
BENCH_PROBE_DEFINE(irq_handler_entry, int irq, struct irqaction *action);
BENCH_PROBE_DEFINE(irq_handler_exit, int irq, struct irqaction *action, int ret);
BENCH_PROBE_DEFINE(softirq_raise, unsigned int vec_nr);
BENCH_PROBE_DEFINE(softirq_entry, unsigned int vec_nr);
BENCH_PROBE_DEFINE(softirq_exit, unsigned int vec_nr);
BENCH_PROBE_DEFINE(sched_waking, struct task_struct *p, int success);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0))
BENCH_PROBE_DEFINE(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next);
#else
BENCH_PROBE_DEFINE(sched_switch, struct task_struct *prev, struct task_struct *next);
#endif

static
void init_benchmark(void)
{
	int cpu;
	int nr_cpu = 0;

	for_each_possible_cpu(cpu)
		nr_cpu++;

	begin_ts = kzalloc(nr_cpu * sizeof(u64), GFP_KERNEL);
	if (!begin_ts)
		goto error;

error:
	return;
}

void teardown_benchmark(void)
{
	if (begin_ts)
		kfree(begin_ts);

	BENCH_UNREGISTER_PROBES(local_timer_entry);
	BENCH_UNREGISTER_PROBES(local_timer_exit);
	BENCH_UNREGISTER_PROBES(hrtimer_expire_entry);
	BENCH_UNREGISTER_PROBES(hrtimer_expire_exit);
	BENCH_UNREGISTER_PROBES(irq_handler_entry);
	BENCH_UNREGISTER_PROBES(irq_handler_exit);
	BENCH_UNREGISTER_PROBES(softirq_raise);
	BENCH_UNREGISTER_PROBES(softirq_entry);
	BENCH_UNREGISTER_PROBES(softirq_exit);
	BENCH_UNREGISTER_PROBES(sched_switch);
	BENCH_UNREGISTER_PROBES(sched_waking);
}

void setup_benchmark_pre(void)
{
	int ret;

	init_benchmark();

	BENCH_REGISTER_PRE_PROBE(local_timer_entry);
	BENCH_REGISTER_PRE_PROBE(local_timer_exit);
	BENCH_REGISTER_PRE_PROBE(hrtimer_expire_entry);
	BENCH_REGISTER_PRE_PROBE(hrtimer_expire_exit);
	BENCH_REGISTER_PRE_PROBE(irq_handler_entry);
	BENCH_REGISTER_PRE_PROBE(irq_handler_exit);
	BENCH_REGISTER_PRE_PROBE(softirq_raise);
	BENCH_REGISTER_PRE_PROBE(softirq_entry);
	BENCH_REGISTER_PRE_PROBE(softirq_exit);
	BENCH_REGISTER_PRE_PROBE(sched_switch);
	BENCH_REGISTER_PRE_PROBE(sched_waking);
}

void setup_benchmark_post(void)
{
	int ret;

	BENCH_REGISTER_POST_PROBE(local_timer_entry);
	BENCH_REGISTER_POST_PROBE(local_timer_exit);
	BENCH_REGISTER_POST_PROBE(hrtimer_expire_entry);
	BENCH_REGISTER_POST_PROBE(hrtimer_expire_exit);
	BENCH_REGISTER_POST_PROBE(irq_handler_entry);
	BENCH_REGISTER_POST_PROBE(irq_handler_exit);
	BENCH_REGISTER_POST_PROBE(softirq_raise);
	BENCH_REGISTER_POST_PROBE(softirq_entry);
	BENCH_REGISTER_POST_PROBE(softirq_exit);
	BENCH_REGISTER_POST_PROBE(sched_switch);
	BENCH_REGISTER_POST_PROBE(sched_waking);
}

void report_benchmark(void)
{
	u64 avg;

	BENCH_REPORT(local_timer_entry);
	BENCH_REPORT(local_timer_exit);
	BENCH_REPORT(hrtimer_expire_entry);
	BENCH_REPORT(hrtimer_expire_exit);
	BENCH_REPORT(irq_handler_entry);
	BENCH_REPORT(irq_handler_exit);
	BENCH_REPORT(softirq_raise);
	BENCH_REPORT(softirq_entry);
	BENCH_REPORT(softirq_exit);
	BENCH_REPORT(sched_switch);
	BENCH_REPORT(sched_waking);
}
#else
void setup_benchmark_pre(void) {}
void setup_benchmark_post(void) {}
void report_benchmark(void) {}
void teardown_benchmark(void) {}
#endif /* BENCHMARK */
