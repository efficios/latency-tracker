#ifndef _LTTNG_WRAPPER_HT_BASEHT_H
#define _LTTNG_WRAPPER_HT_BASEHT_H

/*
 * wrapper/ht-base.h
 *
 * URCU HT
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

#include <linux/hashtable.h>
#include "../urcu/compiler.h"

/*
 * return 1 on match.
 */
static inline
int urcu_match(struct cds_lfht_node *node, const void *key)
{
	struct latency_tracker_event *s;
	struct latency_tracker_key *tkey1, *tkey2;

	s = caa_container_of(node, struct latency_tracker_event, urcunode);
	tkey1 = &s->tkey;
	tkey2 = (struct latency_tracker_key *) key;
	if (tkey1->key_len != tkey2->key_len)
		return 0;
	return !s->tracker->match_fct(tkey1->key, tkey2->key, tkey1->key_len);
}


static inline
void wrapper_ht_init(struct latency_tracker *tracker)
{
	unsigned long size = 2048;

	tracker->urcu_ht = cds_lfht_new(size, size, size, 0, NULL);
}

/* TODO: we assume unique key feature enabled. */
static inline
struct latency_tracker_event *wrapper_ht_add(struct latency_tracker *tracker,
		struct latency_tracker_event *s)
{
	struct cds_lfht_node *node_ptr;

	rcu_read_lock_sched_notrace();
	node_ptr = cds_lfht_add_replace(tracker->urcu_ht,
			s->hkey, urcu_match, (void *) &s->tkey, &s->urcunode);
	rcu_read_unlock_sched_notrace();

	if (node_ptr != NULL) {
		/* Return replaced event. */
		return container_of(node_ptr, struct latency_tracker_event,
				urcunode);
	}
	return NULL;
}

static inline
int wrapper_ht_del(struct latency_tracker *tracker,
		struct latency_tracker_event *s)
{
	int ret;

	rcu_read_lock_sched_notrace();
	ret = cds_lfht_del(tracker->urcu_ht, &s->urcunode);
	rcu_read_unlock_sched_notrace();
	return ret;
}

/*
 * Returns the number of event still active at destruction time.
 */
static inline
int wrapper_ht_clear(struct latency_tracker *tracker)
{
	int nb = 0;
	struct latency_tracker_event *s;
	struct cds_lfht_iter iter;

	rcu_read_lock_sched_notrace();
	cds_lfht_for_each_entry(tracker->urcu_ht, &iter, s, urcunode) {
		kref_put(&s->refcount, __latency_tracker_event_destroy);
		nb++;
	}
	rcu_read_unlock_sched_notrace();

	return nb;
}

static inline
void wrapper_ht_gc(struct latency_tracker *tracker, u64 now)
{
	struct latency_tracker_event *s;
	struct cds_lfht_iter iter;

	rcu_read_lock_sched_notrace();
	cds_lfht_for_each_entry(tracker->urcu_ht, &iter, s, urcunode) {
		if ((now - s->start_ts) > tracker->gc_thresh) {
			s->end_ts = now;
			s->cb_flag = LATENCY_TRACKER_CB_GC;
			if (s->cb)
				s->cb((unsigned long) s);
		}
		kref_put(&s->refcount, __latency_tracker_event_destroy);
	}
	rcu_read_unlock_sched_notrace();
}

static inline
int wrapper_ht_check_event(struct latency_tracker *tracker,
		struct latency_tracker_key *tkey, unsigned int id, u64 now)
{
	struct latency_tracker_event *s;
	u32 k;
	int found = 0;
	struct cds_lfht_iter iter;

	k = tracker->hash_fct(tkey->key, tkey->key_len, 0);

	rcu_read_lock_sched_notrace();
	cds_lfht_for_each_entry_duplicate(tracker->urcu_ht, k,
			urcu_match, tkey, &iter, s, urcunode) {
		if ((now - s->start_ts) > s->thresh) {
			s->end_ts = now;
			s->cb_flag = LATENCY_TRACKER_CB_NORMAL;
			s->cb_out_id = id;
			if (s->cb)
				s->cb((unsigned long) s);
		}
		wrapper_ht_del(tracker, s);
		kref_put(&s->refcount, __latency_tracker_event_destroy);
		found = 1;
	}
	rcu_read_unlock_sched_notrace();

	return found;
}

static inline
void wrapper_ht_unique_check(struct latency_tracker *tracker,
		struct latency_tracker_key *tkey)
{
}

#endif /* _LTTNG_WRAPPER_HT_BASEHT_H */
