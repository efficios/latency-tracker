#ifndef _LTTNG_WRAPPER_HT_BASEHT_H
#define _LTTNG_WRAPPER_HT_BASEHT_H

/*
 * wrapper/ht-base.h
 *
 * Default Linux kernel HT
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

static inline
void wrapper_ht_init(struct latency_tracker *tracker)
{
	hash_init(tracker->ht);
}

static inline
struct latency_tracker_event *wrapper_ht_add(struct latency_tracker *tracker,
		struct latency_tracker_event *s)
{
	unsigned long flags;

	spin_lock_irqsave(&tracker->lock, flags);
	hash_add(tracker->ht, &s->hlist, s->hkey);
	spin_unlock_irqrestore(&tracker->lock, flags);
	return NULL;
}

/* Always called with spin_lock held. */
static inline
int wrapper_ht_del(struct latency_tracker *tracker,
		struct latency_tracker_event *s)
{
	hash_del(&s->hlist);
	return 0;
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
	unsigned long flags;

	spin_lock_irqsave(&tracker->lock, flags);
	hash_for_each_safe(tracker->ht, bkt, tmp, s, hlist){
		__latency_tracker_event_destroy(tracker, s);
		nb++;
	}
	spin_unlock_irqrestore(&tracker->lock, flags);

	return nb;
}

static inline
void wrapper_ht_gc(struct latency_tracker *tracker, u64 now)
{
	struct latency_tracker_event *s;
	struct hlist_node *tmp;
	unsigned long flags;
	int bkt;

	spin_lock_irqsave(&tracker->lock, flags);
	hash_for_each_safe(tracker->ht, bkt, tmp, s, hlist){
		if ((now - s->start_ts) > tracker->gc_thresh) {
			s->end_ts = now;
			s->cb_flag = LATENCY_TRACKER_CB_GC;
			if (s->cb)
				s->cb((unsigned long) s);
		}
		__latency_tracker_event_destroy(tracker, s);
	}
	spin_unlock_irqrestore(&tracker->lock, flags);
}

static inline
int wrapper_ht_check_event(struct latency_tracker *tracker,
    struct latency_tracker_key *tkey, unsigned int id, u64 now)
{
	struct latency_tracker_event *s;
	struct hlist_node *next;
	u32 k;
	int found = 0;
	unsigned long flags;

	spin_lock_irqsave(&tracker->lock, flags);
	k = tracker->hash_fct(tkey->key, tkey->key_len, 0);
	hash_for_each_possible_safe(tracker->ht, s, next, hlist, k){
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
		__latency_tracker_event_destroy(tracker, s);
		found = 1;
	}
	spin_unlock_irqrestore(&tracker->lock, flags);

	return found;
}

static inline
void wrapper_ht_unique_check(struct latency_tracker *tracker,
		struct latency_tracker_key *tkey)
{
	struct hlist_node *next;
	unsigned long flags;
	struct latency_tracker_event *s;
	u32 k;

	spin_lock_irqsave(&tracker->lock, flags);
	k = tracker->hash_fct(tkey->key, tkey->key_len, 0);
	hash_for_each_possible_safe(tracker->ht, s, next, hlist, k){
		if (s->tkey.key_len != tkey->key_len)
			continue;
		if (tracker->match_fct(tkey->key, s->tkey.key, tkey->key_len))
			continue;
		s->cb_flag = LATENCY_TRACKER_CB_UNIQUE;
		if (s->cb)
			s->cb((unsigned long) s);
		__latency_tracker_event_destroy(tracker, s);
		break;
	}
	spin_unlock_irqrestore(&tracker->lock, flags);
}

#endif /* _LTTNG_WRAPPER_HT_BASEHT_H */
