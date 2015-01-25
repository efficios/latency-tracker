#ifndef _TRACKER_PRIVATE_H
#define _TRACKER_PRIVATE_H

#define DEFAULT_LATENCY_HASH_BITS 3
#define DEFAULT_LATENCY_TABLE_SIZE (1 << DEFAULT_LATENCY_HASH_BITS)

#include "wrapper/ht.h"

struct latency_tracker {
        struct hlist_head ht[DEFAULT_LATENCY_TABLE_SIZE];
	struct rhashtable rht;
        int (*match_fct) (const void *key1, const void *key2, size_t length);
        u32 (*hash_fct) (const void *key, u32 length, u32 initval);
        struct list_head events_free_list;
        uint64_t gc_period;
        uint64_t gc_thresh;
        struct timer_list timer;
        /*
         * Protects the access to the HT, the free_list and the timer.
         */
        spinlock_t lock;
        void *priv;
};

struct latency_tracker_event;
static
void latency_tracker_event_destroy(struct latency_tracker *tracker,
		struct latency_tracker_event *s);

#endif /* _TRACKER_PRIVATE_H */
