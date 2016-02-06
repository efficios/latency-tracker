#ifndef RT_BENCH_H
#define RT_BENCH_H

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

#define BENCH_PROBE_DEFINE(_name, ...) \
	static u64 nr_##_name, total_##_name, min_##_name = ULLONG_MAX, max_##_name; \
	void trace_##_name(__VA_ARGS__); \
	static void pre_##_name(void *ignore, __VA_ARGS__) { \
		local_irq_save(cpu_flags[smp_processor_id()]); \
		begin_ts[smp_processor_id()] = trace_clock_monotonic_wrapper(); \
	} \
	static void post_##_name(void *ignore, __VA_ARGS__) { \
		u64 ts = trace_clock_monotonic_wrapper(); \
		u64 delta = ts - begin_ts[smp_processor_id()]; \
		if (begin_ts[smp_processor_id()] == 0) \
			goto end; \
		if (ts < begin_ts[smp_processor_id()]) { \
			WARN_ON_ONCE(1); \
			goto end; \
		} \
		if (min_##_name > delta) \
			min_##_name = delta; \
		if (max_##_name < delta) \
			max_##_name = delta; \
		nr_##_name++; \
		total_##_name += delta; \
		begin_ts[smp_processor_id()] = 0; \
	end: \
		local_irq_restore(cpu_flags[smp_processor_id()]); \
	} \

#define BENCH_REGISTER_PRE_PROBE(_name) \
	ret = lttng_wrapper_tracepoint_probe_register(#_name, pre_##_name, NULL)

#define BENCH_REGISTER_POST_PROBE(_name) \
	ret = lttng_wrapper_tracepoint_probe_register(#_name, post_##_name, NULL)

#define BENCH_UNREGISTER_PROBES(_name) \
	lttng_wrapper_tracepoint_probe_unregister(#_name, pre_##_name, NULL); \
	lttng_wrapper_tracepoint_probe_unregister(#_name, post_##_name, NULL);

#define BENCH_REPORT(_name) \
	if (nr_##_name == 0) \
		avg = 0; \
	else \
		avg = total_##_name / nr_##_name; \
	printk(#_name":\tnr = %llu\ttotal = %llu\tmin = %llu, average = %llu, max = %llu\n", \
			nr_##_name, total_##_name, min_##_name, avg, max_##_name); \

void setup_benchmark_pre(void);
void setup_benchmark_post(void);
void report_benchmark(void);
void teardown_benchmark(void);

#endif /* RT_BENCH_H */
