#ifndef _TP_BLOCK_HIST_H
#define _TP_BLOCK_HIST_H

/*
 * block_hist.h
 *
 * Copyright (C) 2015 Julien Desfossez <jdesfossez@efficios.com>
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

#include <linux/blkdev.h>
#include "../latency_tracker.h"

/*
 * Threshold to execute the callback (microseconds).
 */
#define DEFAULT_USEC_BLK_LATENCY_THRESHOLD 5 * 1000
#define DEFAULT_USEC_BLK_LATENCY_TIMEOUT 0
/*
 * Garbage collector parameters (microseconds).
 */
#define DEFAULT_USEC_BLK_LATENCY_GC_THRESHOLD 0
#define DEFAULT_USEC_BLK_LATENCY_GC_PERIOD 0

/*
 * log2 scale, so:
 * 0-9:   1ns, 2, 4, 8, 16, 32, 64, 128, 256, 512
 * 10-19: 1us, 2, 4...
 * 20-29: 1ms, ... 512ms
 * 30-39: 1s, ... 512s
 * 40: > 512s
 * = 41 intervals
 */
#define LATENCY_BUCKETS 41

extern unsigned long usec_threshold;
extern unsigned long usec_timeout;
extern unsigned long usec_gc_threshold;
extern unsigned long usec_gc_period;

enum wake_reason {
	BLOCK_TRACKER_WAKE_DATA = 0,
	BLOCK_TRACKER_WAIT = 1,
	BLOCK_TRACKER_HUP = 2,
};

enum io_type {
	IO_SYSCALL_READ = 0,
	IO_SYSCALL_WRITE = 1,
	IO_SYSCALL_RW = 2,
	IO_SYSCALL_SYNC = 3,
	IO_SYSCALL_OPEN = 4,
	IO_SYSCALL_CLOSE = 5,

	IO_FS_READ = 6,
	IO_FS_WRITE = 7,

	IO_BLOCK_READ = 8,
	IO_BLOCK_WRITE = 9,
	/* must always be the last value in this enum */
	IO_TYPE_NR = 10,
};

enum tracker_key_type {
	KEY_SYSCALL = 0,
	KEY_FS = 1,
	KEY_BLOCK = 2,
};

/* Different keys must not have exactly the same fields. */
struct blk_key_t {
	dev_t dev;
	sector_t sector;
	enum tracker_key_type type;
} __attribute__((__packed__));

struct syscall_key_t {
	pid_t pid;
	enum tracker_key_type type;
} __attribute__((__packed__));

struct kprobe_key_t {
	pid_t pid;
	enum tracker_key_type type;
} __attribute__((__packed__));

struct iohist {
	uint64_t min;
	uint64_t max;
	uint64_t ts_begin;
	uint64_t ts_end;
	unsigned int values[IO_TYPE_NR][LATENCY_BUCKETS];
	int nb_values;
        spinlock_t lock;
};

#define AGGREGATES 15

struct block_hist_tracker {
	u64 last_alert_ts;
	u64 ns_rate_limit;
	wait_queue_head_t read_wait;
	enum wake_reason reason;
	bool got_alert;
	int readers;
        struct timer_list timer;
	/* array of 1 minute aggregates */
	struct iohist latency_history[AGGREGATES];
	/* index in latency_history % AGGREGATES */
	int current_min;
	struct iohist tmp_display;
};

extern struct latency_tracker *tracker;

DECLARE_PER_CPU(struct iohist, live_hist);
DECLARE_PER_CPU(struct iohist, current_hist);

extern int skip_cnt;

void blk_cb(unsigned long ptr);
void update_hist(struct latency_tracker_event *s, enum io_type t,
		struct iohist *h);

#endif /* _TP_BLOCK_HIST_H */
