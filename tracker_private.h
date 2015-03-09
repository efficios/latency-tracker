#ifndef _TRACKER_PRIVATE_H
#define _TRACKER_PRIVATE_H

//#define DEFAULT_LATENCY_HASH_BITS 3
//#define DEFAULT_LATENCY_TABLE_SIZE (1 << DEFAULT_LATENCY_HASH_BITS)
#define DEFAULT_LATENCY_TABLE_SIZE 2048

#include <linux/workqueue.h>

#include "wrapper/ht.h"
#include "rculfhash-internal.h"
#include "urcu/wfcqueue.h"

struct latency_tracker {
	/*  basic kernel HT */
        struct hlist_head ht[DEFAULT_LATENCY_TABLE_SIZE];
	/* rhashtable */
	struct rhashtable rht;
	/* urcu ht */
	struct cds_lfht *urcu_ht;
	/* Returns 0 on match. */
        int (*match_fct) (const void *key1, const void *key2, size_t length);
        u32 (*hash_fct) (const void *key, u32 length, u32 initval);
	int free_list_nelems;
	int max_resize;
	/* Flag to trigger the freelist resize work. */
	int need_to_resize;
	/* How much event could not be tracked due to an empty free list. */
	uint64_t skipped_count;
#ifdef LLFREELIST
	struct llist_head ll_events_free_list;
#else
	struct list_head events_free_list;
#endif
        uint64_t timer_period;
        uint64_t gc_thresh;
	/* GC and resize work */
        struct timer_list timer;
	struct workqueue_struct *resize_q;
	struct work_struct resize_w;
	/* For timeout on events (on timer_period) */
	struct cds_wfcq_head timeout_head;
	struct cds_wfcq_tail timeout_tail;
        /*
         * Protects the access to the HT, the free_list and the timer.
         */
        spinlock_t lock;
        void *priv;
};

struct latency_tracker_event;
static
void latency_tracker_event_destroy(struct kref *kref);
static
void __latency_tracker_event_destroy(struct kref *kref);

#endif /* _TRACKER_PRIVATE_H */
