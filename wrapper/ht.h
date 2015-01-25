#ifndef _LTTNG_WRAPPER_HT_H
#define _LTTNG_WRAPPER_HT_H

/*
 * wrapper/ht.h
 *
 * wrapper around hash table implementation to use.
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

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0))
#define RHASHTABLE
#include <linux/rhashtable.h>
#endif
#include <linux/hashtable.h>
#include <linux/jhash.h>

#include "../latency_tracker.h"
#include "../tracker_private.h"

#ifdef RHASHTABLE
static int lockdep_nl_sk_hash_is_held(void)
{
/*
#ifdef CONFIG_LOCKDEP
        if (debug_locks)
                return lockdep_is_held(&nl_sk_hash_lock) || lockdep_is_held(&nl_table_lock);
#endif
*/
        return 1;
}

static inline
void wrapper_ht_init(struct latency_tracker *tracker)
{
	struct rhashtable_params ht_params = {
		.head_offset = offsetof(struct latency_tracker_event, node),
		.key_offset = offsetof(struct latency_tracker_event, hkey),
		.key_len = sizeof(u32), /* portid */
		.hashfn = jhash,
		.max_shift = 16, /* 64K */
		.grow_decision = rht_grow_above_75,
		.shrink_decision = rht_shrink_below_30,
		.mutex_is_held = lockdep_nl_sk_hash_is_held,
	};

	rhashtable_init(&tracker->rht, &ht_params);
}

static inline
void wrapper_ht_add(struct latency_tracker *tracker,
		struct latency_tracker_event *s)
{
	rhashtable_insert(&tracker->rht, &s->node, GFP_KERNEL);
}

static inline
void wrapper_ht_del(struct latency_tracker *tracker,
		struct latency_tracker_event *s)
{
	rhashtable_remove(&tracker->rht, &s->node, GFP_KERNEL);
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

	tbl = rht_dereference_rcu(tracker->rht.tbl, &tracker->rht);
	for (i = 0; i < tbl->size; i++) {
		rht_for_each_entry_safe(s, next, tbl->buckets[i],
				&tracker->rht, node) {
			latency_tracker_event_destroy(tracker, s);
			nb++;
		}
	}

	return nb;
}

static inline
void wrapper_ht_gc(struct latency_tracker *tracker, u64 now)
{
	struct latency_tracker_event *s, *next;
	struct bucket_table *tbl;
	int i;

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
}

static inline
int wrapper_ht_check_event(struct latency_tracker *tracker, void *key,
		unsigned int key_len, unsigned int id, u64 now)
{
	struct latency_tracker_event *s;
	u32 k;
	int found = 0;

	k = tracker->hash_fct(key, key_len, 0);
	while ((s = rhashtable_lookup(&tracker->rht, &k))) {
		if (tracker->match_fct(key, s->key, key_len))
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
	}

	return found;
}

static inline
void wrapper_ht_unique_check(struct latency_tracker *tracker,
		struct latency_tracker_event *s, void *key, size_t key_len)
{
	u32 k;
	k = tracker->hash_fct(key, key_len, 0);
	while ((s = rhashtable_lookup(&tracker->rht, &k))) {
		if (tracker->match_fct(key, s->key, key_len))
			continue;
		s->cb_flag = LATENCY_TRACKER_CB_UNIQUE;
		if (s->cb)
			s->cb((unsigned long) s);
		latency_tracker_event_destroy(tracker, s);
		break;
	}
}

/*
#define hash_for_each_safe(tracker, xxbkt, xxtmp, obj, n, tbl) \
	rht_for_each_entry_safe(obj, n, xxhead, tracker->rht, node)
	*/

#else /* RHASHTABLE */

#define wrapper_ht_init(tracker) hash_init(tracker->ht)
#define wrapper_ht_add(tracker, s) hash_add(tracker->ht, &s->hlist, s->hkey)
#define wrapper_ht_del(tracker, s) hash_del(&s->hlist)


/*
 * Returns the number of event still active at destruction time.
 */
static inline
int wrapper_ht_clear(struct latency_tracker *tracker)
{
	int nb = 0;
	int bkt;
	struct latency_tracker_event *s;
	struct hlist_node *tmp;

	hash_for_each_safe(tracker->ht, bkt, tmp, s, hlist){
		latency_tracker_event_destroy(tracker, s);
		nb++;
	}

	return nb;
}

static inline
void wrapper_ht_gc(struct latency_tracker *tracker, u64 now)
{
	struct latency_tracker_event *s;
	struct hlist_node *tmp;
	int bkt;

	hash_for_each_safe(tracker->ht, bkt, tmp, s, hlist){
		if ((now - s->start_ts) > tracker->gc_thresh) {
			s->end_ts = now;
			s->cb_flag = LATENCY_TRACKER_CB_GC;
			if (s->cb)
				s->cb((unsigned long) s);
		}
		latency_tracker_event_destroy(tracker, s);
	}
}

static inline
int wrapper_ht_check_event(struct latency_tracker *tracker, void *key,
    unsigned int key_len, unsigned int id, u64 now)
{
	struct latency_tracker_event *s;
	struct hlist_node *next;
	u32 k;
	int found = 0;

	k = tracker->hash_fct(key, key_len, 0);
	hash_for_each_possible_safe(tracker->ht, s, next, hlist, k){
		if (tracker->match_fct(key, s->key, key_len))
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
	}

	return found;
}

static inline
void wrapper_ht_unique_check(struct latency_tracker *tracker,
		struct latency_tracker_event *s, void *key, size_t key_len)
{
	struct hlist_node *next;
	u32 k;
	k = tracker->hash_fct(key, key_len, 0);
	hash_for_each_possible_safe(tracker->ht, s, next, hlist, k){
		if (tracker->match_fct(key, s->key, key_len))
			continue;
		s->cb_flag = LATENCY_TRACKER_CB_UNIQUE;
		if (s->cb)
			s->cb((unsigned long) s);
		latency_tracker_event_destroy(tracker, s);
		break;
	}
}
#endif /* RHASHTABLE */

#endif /* _LTTNG_WRAPPER_HT_H */
