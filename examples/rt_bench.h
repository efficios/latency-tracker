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
	void trace_##_name(__VA_ARGS__); \
	static void pre_##_name(void *ignore, __VA_ARGS__) { \
		trace_latency_tracker_measurement(#_name, 1, 0); \
	} \
	static void post_##_name(void *ignore, __VA_ARGS__) { \
		trace_latency_tracker_measurement(#_name, 0, 0); \
	} \

#define BENCH_REGISTER_PRE_PROBE(_name) \
	ret = lttng_wrapper_tracepoint_probe_register(#_name, pre_##_name, NULL)

#define BENCH_REGISTER_POST_PROBE(_name) \
	ret = lttng_wrapper_tracepoint_probe_register(#_name, post_##_name, NULL)

#define BENCH_UNREGISTER_PROBES(_name) \
	lttng_wrapper_tracepoint_probe_unregister(#_name, pre_##_name, NULL); \
	lttng_wrapper_tracepoint_probe_unregister(#_name, post_##_name, NULL);

void setup_benchmark_pre(void);
void setup_benchmark_post(void);
void report_benchmark(void);
void teardown_benchmark(void);

#endif /* RT_BENCH_H */
