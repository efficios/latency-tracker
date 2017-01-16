/*
 * self_test.c
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
#include <linux/jhash.h>
#include "../latency_tracker.h"
#include "../tracker_debugfs.h"

#include <trace/events/latency_tracker.h>

static
int __init self_test_init(void)
{
	char *k1 = "blablabla1";
	char *k2 = "bliblibli1";
	int ret, i;
	struct latency_tracker *tracker;

	tracker = latency_tracker_create("test");
	if (!tracker)
		goto error;

	ret = latency_tracker_set_startup_events(tracker, 300);
	if (ret)
		goto error;

	ret = latency_tracker_set_timer_period(tracker, 100*1000*1000);
	if (ret)
		goto error;

	ret = latency_tracker_set_key_size(tracker, strlen(k1) + 1);
	if (ret)
		goto error;

	ret = latency_tracker_allocate(tracker);
	if (ret)
		goto error;

	for (i = 0; i < 10; i++) {
		printk("insert k1\n");
		ret = latency_tracker_event_in(tracker, k1, strlen(k1) + 1,
				0, NULL);
		if (ret)
			printk("failed\n");
	}

	printk("insert k2\n");
	rcu_read_lock_sched_notrace();
	ret = _latency_tracker_event_in(tracker, k2, strlen(k2) + 1, 0,
			0, NULL);
	rcu_read_unlock_sched_notrace();
	if (ret)
		printk("failed\n");

	printk("lookup k1\n");
	latency_tracker_event_out(tracker, NULL, k1, strlen(k1) + 1, 0, 0);
	printk("lookup k2\n");
	latency_tracker_event_out(tracker, NULL, k2, strlen(k2) + 1, 0, 0);
	printk("lookup k1\n");
	rcu_read_lock_sched_notrace();
	_latency_tracker_event_out(tracker, NULL, k1, strlen(k1) + 1, 0, 0);
	rcu_read_unlock_sched_notrace();

	printk("done\n");
	latency_tracker_destroy(tracker);

	ret = 0;
	goto end;

error:
	ret = -1;
end:
	return ret;
}
module_init(self_test_init);

static
void __exit self_test_exit(void)
{
	return;
}
module_exit(self_test_exit);

MODULE_AUTHOR("Julien Desfossez <jdesfossez@efficios.com>");
MODULE_LICENSE("GPL and additional rights");
MODULE_VERSION("1.0");
