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
	unsigned long size = 1 << DEFAULT_LATENCY_TABLE_SIZE;

	tracker->urcu_ht = cds_lfht_new(size, size, size, 0, NULL);
}

static inline
void wrapper_ht_add(struct latency_tracker *tracker,
		struct latency_tracker_event *s)
{
	struct cds_lfht_node *node_ptr;

	rcu_read_lock();
	node_ptr = cds_lfht_add_unique(tracker->urcu_ht,
			s->hkey, urcu_match, (void *) &s->tkey, &s->urcunode);
	rcu_read_unlock();

	if (node_ptr != &s->urcunode)
		printk("ERR HT ADD\n");
}

static inline
void wrapper_ht_del(struct latency_tracker *tracker,
		struct latency_tracker_event *s)
{
	/*
	 * TODO: check return value to make sure we can kfree.
	 * Not required now because we should not have concurrent del of
	 * the same node, but it might happen in the future.
	 */
	rcu_read_lock();
	cds_lfht_del(tracker->urcu_ht, &s->urcunode);
	rcu_read_unlock();
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

	cds_lfht_for_each_entry(tracker->urcu_ht, &iter, s, urcunode) {
		latency_tracker_event_destroy(tracker, s);
		nb++;
	}

	return nb;
}

static inline
void wrapper_ht_gc(struct latency_tracker *tracker, u64 now)
{
	struct latency_tracker_event *s;
	struct cds_lfht_iter iter;

	cds_lfht_for_each_entry(tracker->urcu_ht, &iter, s, urcunode) {
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
int wrapper_ht_check_event(struct latency_tracker *tracker,
		struct latency_tracker_key *tkey, unsigned int id, u64 now)
{
	struct latency_tracker_event *s;
	u32 k;
	int found = 0;
	struct cds_lfht_iter iter;

	k = tracker->hash_fct(tkey->key, tkey->key_len, 0);

	cds_lfht_for_each_entry_duplicate(tracker->urcu_ht, k,
			urcu_match, tkey, &iter, s, urcunode) {
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
		struct latency_tracker_key *tkey)
{
	u32 k;
	struct cds_lfht_iter iter;
	struct latency_tracker_event *s;

	k = tracker->hash_fct(tkey->key, tkey->key_len, 0);
	cds_lfht_for_each_entry_duplicate(tracker->urcu_ht, k,
			urcu_match, tkey, &iter, s, urcunode) {
		s->cb_flag = LATENCY_TRACKER_CB_UNIQUE;
		if (s->cb)
			s->cb((unsigned long) s);
		latency_tracker_event_destroy(tracker, s);
		break;
	}
}

#endif /* _LTTNG_WRAPPER_HT_BASEHT_H */
