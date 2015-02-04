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
#include "../urcu-compiler.h"

//#define wrapper_ht_add(tracker, s) hash_add(tracker->ht, &s->hlist, s->hkey)
#define wrapper_ht_del(tracker, s) hash_del(&s->hlist)

static inline
u32 already_hashed(const void *data, unsigned long seed)
{
	const u32 *k = data;
	return *k;
}

static inline
int urcu_match(struct cds_lfht_node *node, const void *key)
{
	struct latency_tracker_event *s;

	s = caa_container_of(node, struct latency_tracker_event, urcunode);
	return 0;
}


static inline
void wrapper_ht_init(struct latency_tracker *tracker)
{
	tracker->urcu_ht = cds_lfht_new(0, DEFAULT_LATENCY_TABLE_SIZE,
			DEFAULT_LATENCY_TABLE_SIZE, 0, NULL);
}

static inline
void wrapper_ht_add(struct latency_tracker *tracker,
		struct latency_tracker_event *s)
{
	struct cds_lfht_node *node_ptr;

	node_ptr = cds_lfht_add_unique(tracker->urcu_ht,
			s->hkey, 
			urcu_match, (void *) &s->hkey, &s->urcunode);

	/*
	if (node_ptr != s->urcunode)
		printk("ERR HT ADD\n");
		*/

	rhashtable_insert(&tracker->rht, &s->node, GFP_KERNEL);
}

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
	unsigned long flags;

	spin_lock_irqsave(&tracker->lock, flags);
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
		spin_unlock_irqrestore(&tracker->lock, flags);
		latency_tracker_event_destroy(tracker, s);
		found = 1;
		spin_lock_irqsave(&tracker->lock, flags);
	}
	spin_unlock_irqrestore(&tracker->lock, flags);

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

#endif /* _LTTNG_WRAPPER_HT_BASEHT_H */
