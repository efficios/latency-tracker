#ifndef _LTTNG_WRAPPER_HT_RHT_H
#define _LTTNG_WRAPPER_HT_RHT_H

/*
 * wrapper/ht-base.h
 *
 * Linux kernel rhashtable
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

#include <linux/rhashtable.h>

bool rht_check_above_75(const struct rhashtable *ht, size_t new_size)
{
	/* Expand table when exceeding 75% load */
	if (ht->nelems > (new_size / 4 * 3)) {
		printk("would grow, old: %lu, new: %lu\n", ht->nelems,
				new_size);
	}
	return 0;
}

static inline u32 already_hashed(const void *data, u32 len, u32 seed)
{
	const u32 *k = data;
	return *k;
}

static inline
void wrapper_ht_init(struct latency_tracker *tracker)
{
	struct rhashtable_params ht_params = {
		.head_offset = offsetof(struct latency_tracker_event, node),
		.key_offset = offsetof(struct latency_tracker_event, hkey),
		.key_len = sizeof(u32),
		.hashfn = already_hashed,
		.max_shift = DEFAULT_LATENCY_TABLE_SIZE,
//		.grow_decision = rht_check_above_75,
//		.shrink_decision = rht_shrink_below_30_2,
//		.mutex_is_held = lockdep_nl_sk_hash_is_held,
	};

	rhashtable_init(&tracker->rht, &ht_params);
}

static inline
struct latency_tracker_event *wrapper_ht_add(struct latency_tracker *tracker,
		struct latency_tracker_event *s)
{
#if defined(LLFREELIST)
	unsigned long flags;

	spin_lock_irqsave(&tracker->lock, flags);
#endif

	rhashtable_insert(&tracker->rht, &s->node, GFP_KERNEL);

#if defined(LLFREELIST)
	spin_unlock_irqrestore(&tracker->lock, flags);
#endif
	return NULL;
}

/* Always called with spin_lock held. */
static inline
int wrapper_ht_del(struct latency_tracker *tracker,
		struct latency_tracker_event *s)
{
	rhashtable_remove(&tracker->rht, &s->node, GFP_KERNEL);
	return 0;
}

/*
 * Returns the number of event still active at destruction time.
 */
static inline
int wrapper_ht_clear(struct latency_tracker *tracker)
{
	int nb = 0, i;
	struct latency_tracker_event *s, *next;
	struct bucket_table *tbl;

	rcu_read_lock_sched_notrace();
	tbl = rht_dereference_rcu(tracker->rht.tbl, &tracker->rht);
	for (i = 0; i < tbl->size; i++) {
		rht_for_each_entry_safe(s, next, tbl->buckets[i],
				&tracker->rht, node) {
			latency_tracker_event_destroy(tracker, s);
			nb++;
		}
	}
	rcu_read_unlock_sched_notrace();

	return nb;
}

static inline
void wrapper_ht_gc(struct latency_tracker *tracker, u64 now)
{
	struct latency_tracker_event *s, *next;
	struct bucket_table *tbl;
	int i;

	rcu_read_lock_sched_notrace();
	tbl = rht_dereference_rcu(tracker->rht.tbl, &tracker->rht);
	for (i = 0; i < tbl->size; i++) {
		rht_for_each_entry_safe(s, next, tbl->buckets[i],
				&tracker->rht, node) {
			if ((now - s->start_ts) > tracker->gc_thresh) {
				s->end_ts = now;
				s->cb_flag = LATENCY_TRACKER_CB_GC;
				if (s->cb)
					s->cb((unsigned long) s);
			}
			latency_tracker_event_destroy(tracker, s);
		}
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

	k = tracker->hash_fct(tkey->key, tkey->key_len, 0);
	rcu_read_lock_sched_notrace();
	do {
		s = rhashtable_lookup(&tracker->rht, &k);
		if (!s)
			break;
		if (s->tkey.key_len != tkey->key_len)
			continue;
		if (tracker->match_fct(tkey->key, s->tkey.key, tkey->key_len))
			continue;
		if ((now - s->start_ts) > s->thresh) {
			s->end_ts = now;
			s->cb_flag = LATENCY_TRACKER_CB_NORMAL;
			s->cb_out_id = id;
			if (s->cb)
				s->cb((unsigned long) s);
		}
		latency_tracker_event_destroy(tracker, s);
		found = 1;
	} while (s);
	rcu_read_unlock_sched_notrace();

	return found;
}

static inline
void wrapper_ht_unique_check(struct latency_tracker *tracker,
		struct latency_tracker_key *tkey)
{
	u32 k;
	struct latency_tracker_event *s;

	k = tracker->hash_fct(tkey->key, tkey->key_len, 0);
	rcu_read_lock_sched_notrace();
	do {
		s = rhashtable_lookup(&tracker->rht, &k);
		if (!s)
			break;
		if (s->tkey.key_len != tkey->key_len)
			continue;
		if (tracker->match_fct(tkey->key, s->tkey.key, tkey->key_len))
			continue;
		s->cb_flag = LATENCY_TRACKER_CB_UNIQUE;
		if (s->cb)
			s->cb((unsigned long) s);
		latency_tracker_event_destroy(tracker, s);
		break;
	} while (s);
	rcu_read_unlock_sched_notrace();
}

#endif /* _LTTNG_WRAPPER_HT_RHT_H */
