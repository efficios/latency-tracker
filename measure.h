#if !defined(MEASURE_H)
#define MEASURE_H

/*
 * Copyright (C) 2016 Julien Desfossez <jdesfossez@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/perf_event.h>

#define irq_stats(x)            (&per_cpu(irq_stat, x))

#define PER_CPU_ALLOC 10000
struct tracker_measurement_entry {
	u64 ts;
	u64 latency;
	u64 pmu1;
	u64 pmu2;
	u64 pmu3;
	u64 pmu4;
	u64 pmu5;
	u64 pmu6;
	u64 pmu7;
	u64 pmu8;
	unsigned int custom;
};

struct tracker_measurement_cpu_perf {
	struct perf_event *event1;
	struct perf_event *event2;
	struct perf_event *event3;
	struct perf_event *event4;
	struct perf_event *event5;
	struct perf_event *event6;
	struct perf_event *event7;
	struct perf_event *event8;
	struct tracker_measurement_entry *entries;
	unsigned int pos;
};

struct perf_event_attr attr1, attr2, attr3, attr4, attr5, attr6, attr7, attr8;

static struct tracker_measurement_cpu_perf __percpu *tracker_cpu_perf;


#define BENCH_PREAMBULE unsigned long _bench_flags; \
	unsigned int _bench_nmi; \
	struct tracker_measurement_cpu_perf *_bench_c; \
	int _bench_cpu = smp_processor_id(); \
	u64 _bench_ts1 = 0, _bench_ts2 = 0; \
	u64 _bench_pmu1_1 = 0, _bench_pmu1_2 = 0; \
	u64 _bench_pmu2_1 = 0, _bench_pmu2_2 = 0; \
	u64 _bench_pmu3_1 = 0, _bench_pmu3_2 = 0; \
	u64 _bench_pmu4_1 = 0, _bench_pmu4_2 = 0; \
	u64 _bench_pmu5_1 = 0, _bench_pmu5_2 = 0; \
	u64 _bench_pmu6_1 = 0, _bench_pmu6_2 = 0; \
	u64 _bench_pmu7_1 = 0, _bench_pmu7_2 = 0; \
	u64 _bench_pmu8_1 = 0, _bench_pmu8_2 = 0; \
	_bench_c = per_cpu_ptr(tracker_cpu_perf, _bench_cpu); \
	local_irq_save(_bench_flags); \
	_bench_nmi = irq_stats(smp_processor_id())->__nmi_count

#define BENCH_GET_TS1 _bench_c->event1->pmu->read(_bench_c->event1); \
		_bench_c->event2->pmu->read(_bench_c->event2); \
		_bench_c->event3->pmu->read(_bench_c->event3); \
		_bench_c->event4->pmu->read(_bench_c->event4); \
		_bench_c->event5->pmu->read(_bench_c->event5); \
		_bench_c->event6->pmu->read(_bench_c->event6); \
		_bench_c->event7->pmu->read(_bench_c->event7); \
		_bench_c->event8->pmu->read(_bench_c->event8); \
		_bench_pmu1_1 = local64_read(&_bench_c->event1->count); \
		_bench_pmu2_1 = local64_read(&_bench_c->event2->count); \
		_bench_pmu3_1 = local64_read(&_bench_c->event3->count); \
		_bench_pmu4_1 = local64_read(&_bench_c->event4->count); \
		_bench_pmu5_1 = local64_read(&_bench_c->event5->count); \
		_bench_pmu6_1 = local64_read(&_bench_c->event6->count); \
		_bench_pmu7_1 = local64_read(&_bench_c->event7->count); \
		_bench_pmu8_1 = local64_read(&_bench_c->event8->count); \
		_bench_ts1 = trace_clock_monotonic_wrapper()

#define BENCH_GET_TS2 _bench_c->event1->pmu->read(_bench_c->event1); \
		_bench_c->event2->pmu->read(_bench_c->event2); \
		_bench_c->event3->pmu->read(_bench_c->event3); \
		_bench_c->event4->pmu->read(_bench_c->event4); \
		_bench_c->event5->pmu->read(_bench_c->event5); \
		_bench_c->event6->pmu->read(_bench_c->event6); \
		_bench_c->event7->pmu->read(_bench_c->event7); \
		_bench_c->event8->pmu->read(_bench_c->event8); \
		_bench_pmu1_2 = local64_read(&_bench_c->event1->count); \
		_bench_pmu2_2 = local64_read(&_bench_c->event2->count); \
		_bench_pmu3_2 = local64_read(&_bench_c->event3->count); \
		_bench_pmu4_2 = local64_read(&_bench_c->event4->count); \
		_bench_pmu5_2 = local64_read(&_bench_c->event5->count); \
		_bench_pmu6_2 = local64_read(&_bench_c->event6->count); \
		_bench_pmu7_2 = local64_read(&_bench_c->event7->count); \
		_bench_pmu8_2 = local64_read(&_bench_c->event8->count); \
		_bench_ts2 = trace_clock_monotonic_wrapper()

#define BENCH_APPEND(c) if (_bench_nmi == irq_stats(smp_processor_id())->__nmi_count) { \
		if (_bench_c->pos < PER_CPU_ALLOC && _bench_ts1 != 0 && _bench_ts2 != 0) { \
			_bench_c->entries[_bench_c->pos].ts = _bench_ts1; \
			_bench_c->entries[_bench_c->pos].latency = _bench_ts2 - _bench_ts1; \
			_bench_c->entries[_bench_c->pos].pmu1 = _bench_pmu1_2 - _bench_pmu1_1; \
			_bench_c->entries[_bench_c->pos].pmu2 = _bench_pmu2_2 - _bench_pmu2_1; \
			_bench_c->entries[_bench_c->pos].pmu3 = _bench_pmu3_2 - _bench_pmu3_1; \
			_bench_c->entries[_bench_c->pos].pmu4 = _bench_pmu4_2 - _bench_pmu4_1; \
			_bench_c->entries[_bench_c->pos].pmu5 = _bench_pmu5_2 - _bench_pmu5_1; \
			_bench_c->entries[_bench_c->pos].pmu6 = _bench_pmu6_2 - _bench_pmu6_1; \
			_bench_c->entries[_bench_c->pos].pmu7 = _bench_pmu7_2 - _bench_pmu7_1; \
			_bench_c->entries[_bench_c->pos].pmu8 = _bench_pmu8_2 - _bench_pmu8_1; \
			_bench_c->entries[_bench_c->pos].custom = c; \
			_bench_c->pos++; \
		} \
	} \
	local_irq_restore(_bench_flags)

static
void overflow_callback(struct perf_event *event,
		struct perf_sample_data *data,
		struct pt_regs *regs)
{
}

static
int alloc_measurements(void)
{
	int cpu, ret;
	struct tracker_measurement_cpu_perf *c;

	tracker_cpu_perf = alloc_percpu(struct tracker_measurement_cpu_perf);

	/* include/uapi/linux/perf_event.h */
	/* attr1 = L1-dcache-load-misses */
	attr1.size = sizeof(struct perf_event_attr);
	attr1.pinned = 1;
	attr1.disabled = 0;
	attr1.type = PERF_TYPE_HW_CACHE;
	attr1.config = PERF_COUNT_HW_CACHE_L1D | \
		       PERF_COUNT_HW_CACHE_OP_READ << 8 | \
		       PERF_COUNT_HW_CACHE_RESULT_MISS << 16;

	/* attr2 = LLC-load-misses */
	attr2.size = sizeof(struct perf_event_attr);
	attr2.pinned = 1;
	attr2.disabled = 0;
	attr2.type = PERF_TYPE_HW_CACHE;
	attr2.config = PERF_COUNT_HW_CACHE_LL | \
		       PERF_COUNT_HW_CACHE_OP_READ << 8 | \
		       PERF_COUNT_HW_CACHE_RESULT_MISS << 16;

	/* attr3 = dTLB-load-misses */
	attr3.size = sizeof(struct perf_event_attr);
	attr3.pinned = 1;
	attr3.disabled = 0;
	attr3.type = PERF_TYPE_HW_CACHE;
	attr3.config = PERF_COUNT_HW_CACHE_DTLB | \
		       PERF_COUNT_HW_CACHE_OP_READ << 8 | \
		       PERF_COUNT_HW_CACHE_RESULT_MISS << 16;

	/* attr4 = node-load-misses */
	/*
	attr4.size = sizeof(struct perf_event_attr);
	attr4.pinned = 1;
	attr4.disabled = 0;
	attr4.type = PERF_TYPE_HW_CACHE;
	attr4.config = PERF_COUNT_HW_CACHE_NODE | \
		       PERF_COUNT_HW_CACHE_OP_READ << 8 | \
		       PERF_COUNT_HW_CACHE_RESULT_MISS << 16;
		       */
	attr4.size = sizeof(struct perf_event_attr);
	attr4.pinned = 1;
	attr4.disabled = 0;
	attr4.type = PERF_TYPE_HARDWARE;
	attr4.config = PERF_COUNT_HW_CACHE_MISSES;

	attr5.size = sizeof(struct perf_event_attr);
	attr5.pinned = 1;
	attr5.disabled = 0;
	attr5.type = PERF_TYPE_HARDWARE;
	attr5.config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;

	attr6.size = sizeof(struct perf_event_attr);
	attr6.pinned = 1;
	attr6.disabled = 0;
	attr6.type = PERF_TYPE_HARDWARE;
	attr6.config = PERF_COUNT_HW_BRANCH_MISSES;

	attr7.size = sizeof(struct perf_event_attr);
	attr7.pinned = 1;
	attr7.disabled = 0;
	attr7.type = PERF_TYPE_HARDWARE;
	attr7.config = PERF_COUNT_HW_CPU_CYCLES;

	attr8.size = sizeof(struct perf_event_attr);
	attr8.pinned = 1;
	attr8.disabled = 0;
	attr8.type = PERF_TYPE_HARDWARE;
	attr8.config = PERF_COUNT_HW_INSTRUCTIONS;


	/*
	attr6.size = sizeof(struct perf_event_attr);
	attr6.pinned = 1;
	attr6.disabled = 0;
	attr6.type = PERF_TYPE_HARDWARE;
	attr6.config = PERF_COUNT_HW_BUS_CYCLES;

	attr7.size = sizeof(struct perf_event_attr);
	attr7.pinned = 1;
	attr7.disabled = 0;
	attr7.type = PERF_TYPE_HARDWARE;
	attr7.config = PERF_COUNT_HW_REF_CPU_CYCLES;

	attr11.size = sizeof(struct perf_event_attr);
	attr11.pinned = 1;
	attr11.disabled = 0;
	attr11.type = PERF_TYPE_HARDWARE;
	attr11.config = PERF_COUNT_HW_BRANCH_MISSES;

	   attr2.type = PERF_TYPE_HARDWARE;
	   attr2.config = PERF_COUNT_HW_BRANCH_MISSES;
	   */


	for_each_online_cpu(cpu) {
		c = per_cpu_ptr(tracker_cpu_perf, cpu);
		c->pos = 0;
		c->entries = vzalloc(PER_CPU_ALLOC * sizeof(struct tracker_measurement_entry));
		if (!c->entries) {
			ret = -ENOMEM;
			goto end;
		}

		c->event1 = perf_event_create_kernel_counter(&attr1,
				cpu, NULL, overflow_callback, NULL);
		if (!c->event1) {
			printk("failed to create perf counter\n");
			ret = -1;
			goto end;
		}

		c->event2 = perf_event_create_kernel_counter(&attr2,
				cpu, NULL, overflow_callback, NULL);
		if (!c->event2) {
			printk("failed to create perf counter\n");
			ret = -1;
			goto end;
		}
		c->event3 = perf_event_create_kernel_counter(&attr3,
				cpu, NULL, overflow_callback, NULL);
		if (!c->event3) {
			printk("failed to create perf counter\n");
			ret = -1;
			goto end;
		}
		c->event4 = perf_event_create_kernel_counter(&attr4,
				cpu, NULL, overflow_callback, NULL);
		if (!c->event4) {
			printk("failed to create perf counter\n");
			ret = -1;
			goto end;
		}

		c->event5 = perf_event_create_kernel_counter(&attr5,
				cpu, NULL, overflow_callback, NULL);
		if (!c->event5) {
			printk("failed to create perf counter\n");
			ret = -1;
			goto end;
		}
		c->event6 = perf_event_create_kernel_counter(&attr6,
				cpu, NULL, overflow_callback, NULL);
		if (!c->event6) {
			printk("failed to create perf counter\n");
			ret = -1;
			goto end;
		}
		c->event7 = perf_event_create_kernel_counter(&attr7,
				cpu, NULL, overflow_callback, NULL);
		if (!c->event7) {
			printk("failed to create perf counter\n");
			ret = -1;
			goto end;
		}
		c->event8 = perf_event_create_kernel_counter(&attr8,
				cpu, NULL, overflow_callback, NULL);
		if (!c->event8) {
			printk("failed to create perf counter\n");
			ret = -1;
			goto end;
		}
	}
	ret = 0;

end:
	wrapper_vmalloc_sync_all();
	return ret;
}

static
void output_measurements(void)
{
	int cpu;
	loff_t pos = 0;
	struct file *file;
	mm_segment_t old_fs;
	char buf[256];

	old_fs = get_fs();
	set_fs(get_ds());

	file = filp_open("/tmp/out.csv", O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (!file) {
		printk("Failed to open the output file\n");
		goto end;
	}

	snprintf(buf, 256, "timestamp,cpu,latency,L1_miss,LLC_miss,dTLB_miss,cache_misses,branches,branch_miss,cpu_cycles,instructions,custom\n");
	vfs_write(file, buf, strlen(buf), &pos);
	for_each_online_cpu(cpu) {
		int i;
		struct tracker_measurement_cpu_perf *_bench_c;
		_bench_c = per_cpu_ptr(tracker_cpu_perf, cpu);
		for (i = 0; i < _bench_c->pos; i++) {
			/*
			snprintf(buf, 64, "%llu [%03d] %llu %llu\n",
					 _bench_c->entries[i].ts,
					 cpu, _bench_c->entries[i].latency,
					 _bench_c->entries[i].pmu1);
					 */
			snprintf(buf, 256, "%llu,%03d,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%u\n",
					 _bench_c->entries[i].ts,
					 cpu, _bench_c->entries[i].latency,
					 _bench_c->entries[i].pmu1,
					 _bench_c->entries[i].pmu2,
					 _bench_c->entries[i].pmu3,
					 _bench_c->entries[i].pmu4,
					 _bench_c->entries[i].pmu5,
					 _bench_c->entries[i].pmu6,
					 _bench_c->entries[i].pmu7,
					 _bench_c->entries[i].pmu8,
					 _bench_c->entries[i].custom);
			vfs_write(file, buf, strlen(buf), &pos);
		}
	}
	filp_close(file, NULL);

end:
	set_fs(old_fs); //Reset to save FS
	return;
}

static
void free_measurements(void)
{
	int cpu;
	struct tracker_measurement_cpu_perf *c;

	for_each_online_cpu(cpu) {
		c = per_cpu_ptr(tracker_cpu_perf, cpu);
		perf_event_release_kernel(c->event1);
		perf_event_release_kernel(c->event2);
		perf_event_release_kernel(c->event3);
		perf_event_release_kernel(c->event4);
		perf_event_release_kernel(c->event5);
		perf_event_release_kernel(c->event6);
		perf_event_release_kernel(c->event7);
		perf_event_release_kernel(c->event8);
		vfree(c->entries);
	}
	free_percpu(tracker_cpu_perf);
}


#endif /* MEASURE_H */
