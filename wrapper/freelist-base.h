#ifndef _LTTNG_WRAPPER_FREELIST_BASE_H
#define _LTTNG_WRAPPER_FREELIST_BASE_H

/*
 * wrapper/ht-base.h
 *
 * Default Linux kernel list
 *
 * Copyright (C) 2014-2015 Julien Desfossez <jdesfossez@efficios.com>
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

/*
 * Returns the number of event still active at destruction time.
 */
static inline
int wrapper_freelist_init(struct latency_tracker *tracker, int max_events)
{
	int i;
	struct latency_tracker_event *e;

	INIT_LIST_HEAD(&tracker->events_free_list);
	for (i = 0; i < max_events; i++) {
		e = kzalloc(sizeof(struct latency_tracker_event), GFP_KERNEL);
//		printk("- alloc'd %p\n", e);
		if (!e)
			goto error;
		if (i == max_events/2) {
			printk("setting the flag at %d\n", i);
			e->resize_flag = 1;
		}
		list_add(&e->list, &tracker->events_free_list);
	}

	tracker->free_list_nelems = max_events;
	wrapper_vmalloc_sync_all();

	return 0;

error:
	return -1;
}

static
void wrapper_resize_work(struct work_struct *work)
{
	struct latency_tracker *tracker;
	int i, max_events;
	struct latency_tracker_event *e, *n;
	struct list_head tmp_list;
	unsigned long flags;

	return;
	INIT_LIST_HEAD(&tmp_list);
	tracker = container_of(work, struct latency_tracker, resize_w);

	max_events = tracker->free_list_nelems * 2;
	printk("increasing to %d\n", max_events);

	for (i = 0; i < max_events; i++) {
		e = kzalloc(sizeof(struct latency_tracker_event), GFP_KERNEL);
//		printk("- realloc'd %p\n", e);
		if (!e)
			goto error;
		if (i == max_events/2) {
			printk("setting the flag at %d\n", i);
			e->resize_flag = 1;
		}
		list_add(&e->list, &tmp_list);
	}

	spin_lock_irqsave(&tracker->lock, flags);
	list_for_each_entry_safe(e, n, &tmp_list, list) {
		list_del(&e->list);
		list_add(&e->list, &tracker->events_free_list);
	}
	tracker->free_list_nelems = max_events;
	spin_unlock_irqrestore(&tracker->lock, flags);

	printk("resize done\n");
	goto end;

error:
	printk("resize error\n");
	return;

end:
	return;
}

static inline
void wrapper_freelist_destroy(struct latency_tracker *tracker)
{
	struct latency_tracker_event *e, *n;

	list_for_each_entry_safe(e, n, &tracker->events_free_list, list) {
		list_del(&e->list);
		kfree(e);
	}
}

static inline
struct latency_tracker_event *wrapper_freelist_get_event(
		struct latency_tracker *tracker)
{
	struct latency_tracker_event *e;
	int ret;

	if (list_empty(&tracker->events_free_list)) {
		goto error;
	}
	e = list_last_entry(&tracker->events_free_list,
			struct latency_tracker_event, list);
	if (e->resize_flag) {
		printk("starting the resize\n");
		ret = queue_work(tracker->resize_q, &tracker->resize_w);
		if (!ret) {
			printk("error queueing\n");
			goto error;
		}
	}
	list_del(&e->list);
	goto end;

error:
	e = NULL;
end:
//	printk("- using %p\n", e);
	return e;
}

/*
 * Must be called with appropriate locking.
 */
static
void __wrapper_freelist_put_event(struct latency_tracker *tracker,
		struct latency_tracker_event *e)
{
	memset(e, 0, sizeof(struct latency_tracker_event));
	list_add(&e->list, &tracker->events_free_list);
}

static
void wrapper_freelist_put_event(struct latency_tracker *tracker,
		struct latency_tracker_event *e)
{
	unsigned long flags;

	spin_lock_irqsave(&tracker->lock, flags);
	__wrapper_freelist_put_event(tracker, e);
	spin_unlock_irqrestore(&tracker->lock, flags);
}

#endif /* _LTTNG_WRAPPER_FREELIST_BASE_H */
