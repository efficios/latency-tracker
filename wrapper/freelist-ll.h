#ifndef _LTTNG_WRAPPER_FREELIST_BASE_H
#define _LTTNG_WRAPPER_FREELIST_BASE_H

/*
 * wrapper/ht-base.h
 *
 * Lockless list
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

#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/smp.h>
#include "percpu-defs.h"

/* TODO: CPU hotplug */
static
int init_per_cpu_llist(struct latency_tracker *tracker)
{
	struct llist_head *l;
	int cpu;

	tracker->per_cpu_ll = alloc_percpu(struct per_cpu_ll);
	if (!tracker->per_cpu_ll)
		goto error;

	for_each_possible_cpu(cpu) {
		printk("LA %d\n", cpu);
		l = per_cpu_ptr(&tracker->per_cpu_ll->llist, cpu);
		init_llist_head(l);
		tracker->nr_cpus++;
	}

	return 0;

error:
	return -ENOMEM;
}

/*
 * Returns the number of event still active at destruction time.
 */
static inline
int wrapper_freelist_init(struct latency_tracker *tracker, int max_events)
{
	int i;
	struct latency_tracker_event *e;

	if (init_per_cpu_llist(tracker) < 0)
		goto error;

	init_llist_head(&tracker->ll_events_free_list);
	for (i = 0; i < max_events; i++) {
		e = kzalloc(sizeof(struct latency_tracker_event), GFP_KERNEL);
		if (!e)
			goto error;
		e->tkey.key = kzalloc(tracker->key_size, GFP_KERNEL);
		if (!e->tkey.key)
			goto error;
		if (tracker->priv_data_size) {
			e->priv_data = kzalloc(tracker->priv_data_size,
					GFP_KERNEL);
			if (!e->priv_data)
				goto error;
		}
		if (tracker->max_resize && (i == max_events/2)) {
			tracker->resize_event = e;
		}
		llist_add(&e->llist, &tracker->ll_events_free_list);
	}
	tracker->free_list_nelems = max_events;
	tracker->per_cpu_alloc = max_events / tracker->nr_cpus;
	wrapper_vmalloc_sync_all();

	return 0;

error:
	return -1;
}

static
void wrapper_resize_work(struct latency_tracker *tracker)
{
	int i, max_events;
	struct latency_tracker_event *e;

	max_events = min(tracker->free_list_nelems * 2,
			tracker->max_resize - tracker->free_list_nelems);
	printk("latency_tracker: increasing to %d (adding %d)\n",
			tracker->free_list_nelems + max_events, max_events);

	for (i = 0; i < max_events; i++) {
		e = kzalloc(sizeof(struct latency_tracker_event), GFP_KERNEL);
		if (!e)
			goto error;
		e->tkey.key = kzalloc(tracker->key_size, GFP_KERNEL);
		if (!e->tkey.key)
			goto error;
		if (tracker->priv_data_size) {
			e->priv_data = kzalloc(tracker->priv_data_size,
					GFP_KERNEL);
			if (!e->priv_data)
				goto error;
		}
		if (i == max_events / 2)
			tracker->resize_event = e;
		/*
		 * FIXME: add should be at the tail, we will resize too
		 * much.
		 */
		llist_add(&e->llist, &tracker->ll_events_free_list);
	}
	tracker->free_list_nelems += max_events;
	wrapper_vmalloc_sync_all();
	goto end;

error:
	printk("latency_tracker: resize error\n");
	return;

end:
	printk("latency_tracker: resize success\n");
	return;
}

static
int free_event_list(struct llist_node *list)
{
	struct latency_tracker_event *e, *n;
	int cnt = 0;

	llist_for_each_entry_safe(e, n, list, llist) {
		kfree(e->tkey.key);
		if (e->priv_data)
			kfree(e->priv_data);
		kfree(e);
		cnt++;
	}

	return cnt;
}

static
int free_per_cpu_llist(struct latency_tracker *tracker)
{
	struct llist_head *list_head;
	struct llist_node *list;
	struct per_cpu_ll *ll;

	int total_cnt = 0;
	int cpu;

	for_each_possible_cpu(cpu) {
		int cnt = 0;

		ll = per_cpu_ptr(tracker->per_cpu_ll, cpu);
		list_head = &ll->llist;
		list = llist_del_all(list_head);
		if (!list)
			continue;
		cnt = free_event_list(list);
		printk("freed %d on cpu %d (%d)\n", cnt, cpu,
				ll->current_count);
		total_cnt += cnt;
	}

	free_percpu(tracker->per_cpu_ll);
	return total_cnt;
}

static inline
void wrapper_freelist_destroy(struct latency_tracker *tracker)
{
	struct llist_node *list;
	int cnt = 0;

	list = llist_del_all(&tracker->ll_events_free_list);
	if (list) {
		cnt = free_event_list(list);
	}
	cnt += free_per_cpu_llist(tracker);
	printk("latency_tracker: LL freed %d events (%lu bytes)\n", cnt,
			cnt * (sizeof(struct latency_tracker_event) +
				tracker->key_size + tracker->priv_data_size));
}

/*
 * Try to get an entry from the local CPU pool, if empty, use
 * the global pool.
 */
struct llist_node *per_cpu_get(struct latency_tracker *tracker)
{
	struct llist_node *node;
	struct per_cpu_ll *ll;

	ll = lttng_this_cpu_ptr(tracker->per_cpu_ll);
	node = llist_del_first(&ll->llist);
	if (node) {
		ll->current_count--;
		return node;
	}
	return llist_del_first(&tracker->ll_events_free_list);
}

static inline
struct latency_tracker_event *wrapper_freelist_get_event(
		struct latency_tracker *tracker)
{
	struct latency_tracker_event *e;
	struct llist_node *node;
	
	rcu_read_lock_sched_notrace();
	node = per_cpu_get(tracker);
	rcu_read_unlock_sched_notrace();
	if (!node)
		goto error;
	e = llist_entry(node, struct latency_tracker_event, llist);
	goto end;

error:
	e = NULL;
end:
	return e;
}

static
void __wrapper_freelist_put_event(struct latency_tracker *tracker,
		struct latency_tracker_event *e)
{
	struct per_cpu_ll *ll;

	/*
	 * memset the event before putting it back inside the
	 * list. Make sure not to override the allocated pointer
	 * for the key.
	 */
	memset(e, 0, offsetof(struct latency_tracker_event, priv_data));
	memset(e->tkey.key, 0, tracker->key_size);
	if (e->priv_data)
		memset(e->priv_data, 0, tracker->priv_data_size);
	ll = lttng_this_cpu_ptr(tracker->per_cpu_ll);
	llist_add(&e->llist, &ll->llist);
	ll->current_count++;
	/* put back events in the global list if we have too much */
	if (ll->current_count > 2*tracker->per_cpu_alloc) {
		struct llist_node *node;
		int i;

		for (i = 0; i < tracker->per_cpu_alloc; i++) {
			node = llist_del_first(&ll->llist);
			if (!node) {
				BUG_ON(1);
				return;
			}
			llist_add(node, &tracker->ll_events_free_list);
			ll->current_count--;
		}
	}
}

static
void wrapper_freelist_put_event(struct latency_tracker *tracker,
		struct latency_tracker_event *e)
{
	__wrapper_freelist_put_event(tracker, e);
}

#endif /* _LTTNG_WRAPPER_FREELIST_BASE_H */
