/*
 * block_latency_tp.c
 *
 * Example of usage of latency_tracker with kernel tracepoints.
 * In this example, we call the callback function blk_cb when the delay
 * between a block request (block_rq_issue) and its completion
 * (block_rq_complete) takes more than BLK_LATENCY_THRESH nanoseconds.
 *
 * Copyright (C) 2014 Julien Desfossez <jdesfossez@efficios.com>
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

#include <linux/module.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include "block_latency_tp.h"
#include "../latency_tracker.h"

/*
 * Threshold to execute the callback (nanoseconds).
 */
#define BLK_LATENCY_THRESH 5 * 1000000

struct blkkey {
	dev_t dev;
	sector_t sector;
} __attribute__((__packed__));

struct latency_tracker *tracker;

void blk_cb(unsigned long ptr, unsigned int timeout)
{
	char b[BDEVNAME_SIZE];
	struct latency_tracker_event *data =
		(struct latency_tracker_event *) ptr;
	struct blkkey *key = data->key;

	__bdevname(key->dev, b);
	printk("CB called, dev = %d,%d, sector = %lu, delay = %llu\n",
			MAJOR(key->dev), MINOR(key->dev),
			key->sector, data->end_ts - data->start_ts);
}

static
void rq_to_key(struct blkkey *key, struct request *rq)
{
	if (!key || !rq)
		return;

	key->sector = blk_rq_pos(rq);
	key->dev = rq->rq_disk ? disk_devt(rq->rq_disk) : 0;
}

static
void probe_block_rq_issue(void *ignore, struct request_queue *q,
		struct request *rq)
{
	struct blkkey key;
	int ret;

	if (rq->cmd_type == REQ_TYPE_BLOCK_PC)
		return;

	rq_to_key(&key, rq);
	ret = latency_tracker_event_in(tracker, &key, sizeof(key),
			BLK_LATENCY_THRESH, blk_cb, 0, NULL);
	WARN_ON(ret);
}

static
void probe_block_rq_complete(void *ignore, struct request_queue *q,
		struct request *rq, unsigned int nr_bytes)
{
	struct blkkey key;

	if (rq->cmd_type == REQ_TYPE_BLOCK_PC)
		return;

	rq_to_key(&key, rq);
	latency_tracker_event_out(tracker, &key, sizeof(key));
}

static
int __init block_latency_tp_init(void)
{
	int ret;

	tracker = latency_tracker_create(NULL, NULL);
	if (!tracker)
		goto error;

	ret = tracepoint_probe_register("block_rq_issue",
			probe_block_rq_issue, NULL);
	WARN_ON(ret);

	ret = tracepoint_probe_register("block_rq_complete",
			probe_block_rq_complete, NULL);
	WARN_ON(ret);

	ret = 0;
	goto end;

error:
	ret = -1;
end:
	return ret;
}
module_init(block_latency_tp_init);

static
void __exit block_latency_tp_exit(void)
{
	tracepoint_probe_unregister("block_rq_issue",
			probe_block_rq_issue, NULL);
	tracepoint_probe_unregister("block_rq_complete",
			probe_block_rq_complete, NULL);
	tracepoint_synchronize_unregister();
	latency_tracker_destroy(tracker);
}
module_exit(block_latency_tp_exit);

MODULE_AUTHOR("Julien Desfossez <jdesfossez@efficios.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
