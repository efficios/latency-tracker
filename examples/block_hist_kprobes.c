#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/poll.h>
#include <linux/cpu.h>
#include "../latency_tracker.h"
#include "block_hist.h"
#include "../wrapper/percpu-defs.h"

static
int entry_new_sync_write(struct kretprobe_instance *p, struct pt_regs *regs)
{
	struct task_struct* task = current;
	struct kprobe_key_t kprobe_key;
	enum latency_tracker_event_in_ret ret;
	u64 thresh, timeout;

	kprobe_key.pid = task->pid;
	kprobe_key.type = KEY_FS;
	thresh = usec_threshold * 1000;
	timeout = usec_timeout * 1000;

	ret = latency_tracker_event_in(tracker, &kprobe_key, sizeof(kprobe_key),
			thresh, blk_cb, timeout, 0, NULL);
	if (ret == LATENCY_TRACKER_FULL) {
		skip_cnt++;
		//printk("latency_tracker block: no more free events, consider "
		//		"increasing the max_events parameter\n");
	} else if (ret) {
		printk("latency_tracker block: error adding event\n");
	}

	return 0;
}

static
int exit_new_sync_write(struct kretprobe_instance *p, struct pt_regs *regs)
{
	struct kprobe_key_t key;
	struct latency_tracker_event *s;

	key.pid = current->pid;
	key.type = KEY_FS;
	s = latency_tracker_get_event(tracker, &key, sizeof(key));
	if (!s)
		goto end;
	update_hist(s, IO_FS_WRITE,
			lttng_this_cpu_ptr(&live_hist));
	update_hist(s, IO_FS_WRITE,
			lttng_this_cpu_ptr(&current_hist));
	latency_tracker_put_event(s);

end:
	latency_tracker_event_out(tracker, &key, sizeof(key), 0);
	return 0;
}

static
struct kretprobe probe_new_sync_write = {
	.entry_handler = entry_new_sync_write,
	.handler = exit_new_sync_write,
	.kp.symbol_name = "new_sync_write",
};

static
int entry_new_sync_read(struct kretprobe_instance *p, struct pt_regs *regs)
{
	struct task_struct* task = current;
	struct kprobe_key_t kprobe_key;
	enum latency_tracker_event_in_ret ret;
	u64 thresh, timeout;

	kprobe_key.pid = task->pid;
	kprobe_key.type = KEY_FS;
	thresh = usec_threshold * 1000;
	timeout = usec_timeout * 1000;

	ret = latency_tracker_event_in(tracker, &kprobe_key, sizeof(kprobe_key),
			thresh, blk_cb, timeout, 0, NULL);
	if (ret == LATENCY_TRACKER_FULL) {
		skip_cnt++;
		//printk("latency_tracker block: no more free events, consider "
		//		"increasing the max_events parameter\n");
	} else if (ret) {
		printk("latency_tracker block: error adding event\n");
	}

	return 0;
}

static
int exit_new_sync_read(struct kretprobe_instance *p, struct pt_regs *regs)
{
	struct kprobe_key_t key;
	struct latency_tracker_event *s;

	key.pid = current->pid;
	key.type = KEY_FS;
	s = latency_tracker_get_event(tracker, &key, sizeof(key));
	if (!s)
		goto end;
	update_hist(s, IO_FS_READ,
			lttng_this_cpu_ptr(&live_hist));
	update_hist(s, IO_FS_READ,
			lttng_this_cpu_ptr(&current_hist));
	latency_tracker_put_event(s);

end:
	latency_tracker_event_out(tracker, &key, sizeof(key), 0);
	return 0;
}

static
struct kretprobe probe_new_sync_read = {
	.entry_handler = entry_new_sync_read,
	.handler = exit_new_sync_read,
	.kp.symbol_name = "new_sync_read",
};

int setup_kprobes(void)
{
	register_kretprobe(&probe_new_sync_write);
	register_kretprobe(&probe_new_sync_read);

	return 0;
}

void remove_kprobes(void)
{
	unregister_kretprobe(&probe_new_sync_write);
	unregister_kretprobe(&probe_new_sync_read);
}
