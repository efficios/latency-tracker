/*
 * userspace.c
 *
 * Copyright (C) 2017 Julien Desfossez <jdesfossez@efficios.com>
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
#include <asm/syscall.h>
#include "../latency_tracker.h"
#include "../tracker_debugfs.h"
#include "../wrapper/tracepoint.h"
#include "../wrapper/trace-clock.h"
#include "../wrapper/lt_probe.h"

#include <trace/events/latency_tracker.h>

/*
 * Limited to MAX_FILTER_STR_VAL (256) for ftrace compatibility.
 */
#define LT_MAX_COOKIE_SIZE MAX_FILTER_STR_VAL

struct userspace_key {
	char cookie[LT_MAX_COOKIE_SIZE];
	int cookie_size;
} __attribute__((__packed__));

#undef MAX_KEY_SIZE
#define MAX_KEY_SIZE sizeof(struct userspace_key)

static struct latency_tracker *tracker;

static int cnt = 0;

static
void userspace_cb(struct latency_tracker_event_ctx *ctx)
{
	uint64_t end_ts = latency_tracker_event_ctx_get_end_ts(ctx);
	uint64_t start_ts = latency_tracker_event_ctx_get_start_ts(ctx);
	enum latency_tracker_cb_flag cb_flag =
		latency_tracker_event_ctx_get_cb_flag(ctx);
	u64 delay;
	/*
	 * TODO: output an event in ftrace
	struct userspace_key *key = (struct userspace_key *)
		latency_tracker_event_ctx_get_key(ctx)->key;
		*/

	if (cb_flag != LATENCY_TRACKER_CB_NORMAL)
		return;

	delay = end_ts - start_ts;


	cnt++;

	latency_tracker_debugfs_wakeup_pipe(tracker);
}

LT_PROBE_DEFINE(tracker_begin, char *tp_data, size_t len)
{
	struct userspace_key key;
	enum latency_tracker_event_in_ret ret;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	if (!tp_data)
		return;

	/*
	 * Cookies must be strings, just a "echo > work_begin" is not
	 * accepted.
	 */
	if (len == 1 && (tp_data[0] == '\n' || tp_data[0] == '\0'))
		return;

	memset(&key.cookie, 0, sizeof(key.cookie));
	memcpy(&key.cookie, tp_data, len);

	ret = latency_tracker_event_in(tracker, &key, sizeof(key), 0, NULL);
	WARN_ON_ONCE(ret);
}

LT_PROBE_DEFINE(tracker_end, char *tp_data, size_t len)
{
	struct userspace_key key;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	if (!tp_data)
		return;

	/*
	 * Cookies must be strings, just a "echo > work_begin" is not
	 * accepted.
	 */
	if (len == 1 && (tp_data[0] == '\n' || tp_data[0] == '\0'))
		return;

	memset(&key.cookie, 0, sizeof(key.cookie));
	memcpy(&key.cookie, tp_data, len);

	latency_tracker_event_out(tracker, NULL, &key, sizeof(key), 0, 0);
}

static
int __init userspace_init(void)
{
	int ret;

	tracker = latency_tracker_create("userspace");
	if (!tracker)
		goto error;
	latency_tracker_set_callback(tracker, userspace_cb);
	latency_tracker_set_key_size(tracker, MAX_KEY_SIZE);

	ret = latency_tracker_debugfs_setup_wakeup_pipe(tracker);
	if (ret != 0)
		goto error;

	ret = lttng_wrapper_tracepoint_probe_register("latency_tracker_begin",
			probe_tracker_begin, NULL);
	WARN_ON(ret);

	ret = lttng_wrapper_tracepoint_probe_register("latency_tracker_end",
			probe_tracker_end, NULL);
	WARN_ON(ret);

	goto end;

error:
	ret = -1;
end:
	return ret;
}
module_init(userspace_init);

static
void __exit userspace_exit(void)
{
	uint64_t skipped;

	lttng_wrapper_tracepoint_probe_unregister("latency_tracker_begin",
			probe_tracker_begin, NULL);
	lttng_wrapper_tracepoint_probe_unregister("latency_tracker_end",
			probe_tracker_end, NULL);
	tracepoint_synchronize_unregister();
	skipped = latency_tracker_skipped_count(tracker);
	latency_tracker_destroy(tracker);
	printk("Missed events : %llu\n", skipped);
	printk("Total userspace alerts : %d\n", cnt);
}
module_exit(userspace_exit);

MODULE_AUTHOR("Julien Desfossez <jdesfossez@efficios.com>");
MODULE_LICENSE("GPL and additional rights");
MODULE_VERSION("1.0");
