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

	if (!latency_tracker_get_tracking_on(tracker))
		return 0;

	kprobe_key.pid = task->pid;
	kprobe_key.type = KEY_FS;

	ret = latency_tracker_event_in(tracker, &kprobe_key, sizeof(kprobe_key),
			0, NULL);
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

	if (!latency_tracker_get_tracking_on(tracker))
		return 0;

	key.pid = current->pid;
	key.type = KEY_FS;
	s = latency_tracker_get_event_by_key(tracker, &key, sizeof(key), NULL);
	if (!s)
		goto end;
	update_hist(s, IO_FS_WRITE,
			lttng_this_cpu_ptr(&live_hist));
	update_hist(s, IO_FS_WRITE,
			lttng_this_cpu_ptr(&current_hist));
	latency_tracker_unref_event(s);

end:
	latency_tracker_event_out(tracker, NULL, &key, sizeof(key), 0, 0);
	return 0;
}

static
struct kretprobe probe_new_sync_write = {
	.entry_handler = entry_new_sync_write,
	.handler = exit_new_sync_write,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0))
	.kp.symbol_name = "do_sync_write",
#else
	.kp.symbol_name = "new_sync_write",
#endif
};

static
int entry_new_sync_read(struct kretprobe_instance *p, struct pt_regs *regs)
{
	struct task_struct* task = current;
	struct kprobe_key_t kprobe_key;
	enum latency_tracker_event_in_ret ret;

	if (!latency_tracker_get_tracking_on(tracker))
		return 0;

	kprobe_key.pid = task->pid;
	kprobe_key.type = KEY_FS;

	ret = latency_tracker_event_in(tracker, &kprobe_key, sizeof(kprobe_key),
			0, NULL);
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

	if (!latency_tracker_get_tracking_on(tracker))
		return 0;

	key.pid = current->pid;
	key.type = KEY_FS;
	s = latency_tracker_get_event_by_key(tracker, &key, sizeof(key), NULL);
	if (!s)
		goto end;
	update_hist(s, IO_FS_READ,
			lttng_this_cpu_ptr(&live_hist));
	update_hist(s, IO_FS_READ,
			lttng_this_cpu_ptr(&current_hist));
	latency_tracker_unref_event(s);

end:
	latency_tracker_event_out(tracker, NULL, &key, sizeof(key), 0, 0);
	return 0;
}

static
struct kretprobe probe_new_sync_read = {
	.entry_handler = entry_new_sync_read,
	.handler = exit_new_sync_read,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0))
	.kp.symbol_name = "do_sync_read",
#else
	.kp.symbol_name = "new_sync_read",
#endif
};

int setup_kprobes(void)
{
	int ret;

	ret = register_kretprobe(&probe_new_sync_write);
	WARN_ON(ret);
	ret = register_kretprobe(&probe_new_sync_read);
	WARN_ON(ret);

	return 0;
}

void remove_kprobes(void)
{
	unregister_kretprobe(&probe_new_sync_write);
	unregister_kretprobe(&probe_new_sync_read);
}
