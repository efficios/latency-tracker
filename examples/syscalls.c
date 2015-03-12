/*
 * syscalls.c
 *
 * Example of usage of latency_tracker with kernel tracepoints.
 *
 * In this example, we call the callback function syscalls_cb when the
 * duration of a system call is more than DEFAULT_USEC_SYSCALL_THRESH
 * microseconds.
 *
 * The parameter can be controlled at run-time by writing the value in
 * micro-seconds in:
 * /sys/module/syscalls/parameters/usec_threshold
 *
 * It is possible to use nanoseconds, but you have to write manually the value
 * in this source code.
 *
 * Copyright (C) 2015 Francois Doray <francois.pierre-doray@polymtl.ca>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; only version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/stacktrace.h>
#include <asm/stacktrace.h>
#include "syscalls.h"
#include "../latency_tracker.h"
#include "../wrapper/tracepoint.h"
#include "../wrapper/vmalloc.h"
#include "../wrapper/syscall_name.h"
#include "../wrapper/trace-clock.h"

#include <trace/events/latency_tracker.h>

/*
 * Threshold to execute the callback (microseconds).
 */
#define DEFAULT_USEC_SYSCALL_THRESH 1 * 1000 * 1000
/*
 * Timeout to execute the callback (microseconds).
 */
#define DEFAULT_USEC_SYSCALL_TIMEOUT 500 * 1000
/*
 * Select whether we track latencies for all processes or only
 * for register ones (through the /proc file).
 */
#define DEFAULT_WATCH_ALL_PROCESSES 0

#define MAX_STACK_TXT 256

/*
 * microseconds because we can't guarantee the passing of 64-bit
 * arguments to insmod on all architectures.
 */
static unsigned long usec_threshold = DEFAULT_USEC_SYSCALL_THRESH;
module_param(usec_threshold, ulong, 0644);
MODULE_PARM_DESC(usec_threshold, "Threshold in microseconds");

static unsigned long usec_timeout = DEFAULT_USEC_SYSCALL_TIMEOUT;
module_param(usec_timeout, ulong, 0644);
MODULE_PARM_DESC(usec_timeout, "Timeout in microseconds");

static unsigned long watch_all = DEFAULT_WATCH_ALL_PROCESSES;
module_param(watch_all, ulong, 0644);
MODULE_PARM_DESC(watch_all, "Watch all processes or just registered one");

static int cnt = 0;

static struct latency_tracker *tracker;

struct sched_key_t {
  pid_t pid;
} __attribute__((__packed__));

struct process_key_t {
  pid_t tgid;
} __attribute__((__packed__));

struct process_val_t {
  u64 syscall_start_ts;
  pid_t tgid;
  int take_stack_dump;
  struct hlist_node hlist;
  struct rcu_head rcu;
};

static DEFINE_HASHTABLE(process_map, 3);

static int print_trace_stack(void *data, char *name)
{
        return 0;
}

static void
__save_stack_address(void *data, unsigned long addr, bool reliable, bool nosched)
{
        struct stack_trace *trace = data;
#ifdef CONFIG_FRAME_POINTER
        if (!reliable)
                return;
#endif
        if (nosched && in_sched_functions(addr))
                return;
        if (trace->skip > 0) {
                trace->skip--;
                return;
        }
        if (trace->nr_entries < trace->max_entries)
                trace->entries[trace->nr_entries++] = addr;
}

static void save_stack_address(void *data, unsigned long addr, int reliable)
{
        return __save_stack_address(data, addr, reliable, false);
}

static const struct stacktrace_ops backtrace_ops = {
        .stack                  = print_trace_stack,
        .address                = save_stack_address,
        .walk_stack             = print_context_stack,
};

static void free_process_val_rcu(struct rcu_head *rcu)
{
  kfree(container_of(rcu, struct process_val_t, rcu));
}

static 
struct process_val_t* find_process(struct process_key_t *key, u32 hash)
{
  struct process_val_t *val;

  hash_for_each_possible_rcu(process_map, val, hlist, hash) {
    if (key->tgid == val->tgid) {
      return val;
    }
  }
  return NULL;
}

void process_register(pid_t tgid)
{
  u32 hash;
  struct process_key_t key;
  struct process_val_t *val;

  key.tgid = tgid;
  hash = jhash(&key, sizeof(key), 0);

  rcu_read_lock();
  val = find_process(&key, hash);
  if (val) {
    rcu_read_unlock();
    return;
  }
  rcu_read_unlock();

  val = kzalloc(sizeof(struct process_val_t), GFP_KERNEL);
  val->tgid = tgid;
  hash_add_rcu(process_map, &val->hlist, hash);
  printk("syscall tracker register process %d\n", tgid);
}

void process_unregister(pid_t tgid)
{
  u32 hash;
  struct process_key_t key;
  struct process_val_t *val;

  key.tgid = tgid;
  hash = jhash(&key, sizeof(key), 0);

  rcu_read_lock();
  val = find_process(&key, hash);
  if (val) {
    hash_del_rcu(&val->hlist);
    call_rcu(&val->rcu, free_process_val_rcu);
    printk("syscall tracker unregister process %d\n", tgid);
  }
  rcu_read_unlock();
}

static
void get_stack_txt(char *stacktxt, struct task_struct *p)
{
	struct stack_trace trace;
	unsigned long entries[32];
	char tmp[48];
	int i, j;
	size_t frame_len;

	trace.nr_entries = 0;
	trace.max_entries = ARRAY_SIZE(entries);
	trace.entries = entries;
	trace.skip = 0;
	dump_trace(p, NULL, NULL, 0, &backtrace_ops, &trace);

	j = 0;
	for (i = 0; i < trace.nr_entries; i++) {
		snprintf(tmp, 48, "%pS\n", (void *) trace.entries[i]);
		frame_len = strlen(tmp);
		snprintf(stacktxt + j, MAX_STACK_TXT - j, tmp);
		j += frame_len;
	}
}

static
void syscall_cb(unsigned long ptr)
{
	struct latency_tracker_event *data =
		(struct latency_tracker_event *) ptr;
	struct process_key_t process_key;
	struct sched_key_t *key = (struct sched_key_t *) data->tkey.key;
	struct process_val_t *val;
	struct task_struct* task;
	int send_sig = 0;
	u32 hash;

	rcu_read_lock();
	if (data->cb_flag == LATENCY_TRACKER_CB_TIMEOUT) {
		task = pid_task(find_vpid(key->pid), PIDTYPE_PID);
		if (!task)
			goto end_unlock;
	} else if (data->cb_flag == LATENCY_TRACKER_CB_NORMAL) {
		task = current;
	} else {
		goto end_unlock;
	}

	process_key.tgid = task->tgid;
	hash = jhash(&process_key, sizeof(process_key), 0);

	val = find_process(&process_key, hash);
	if (val)
		send_sig = 1;

	/* On timeout take the stack, on normal cb just the basic event. */
	if (data->cb_flag == LATENCY_TRACKER_CB_TIMEOUT) {
		if (val) {
			val->syscall_start_ts = data->start_ts;
			val->take_stack_dump = 1;
		}
	} else {
		trace_syscall_latency(task->comm, task->pid,
				data->end_ts - data->start_ts);
    if (send_sig)
      send_sig_info(SIGPROF, SEND_SIG_NOINFO, task);
    else
      syscall_tracker_handle_proc(latency_tracker_get_priv(tracker));
	}
	rcu_read_unlock();

	++cnt;
	goto end;

end_unlock:
	rcu_read_unlock();

end:
	return;
}

static
void probe_syscall_enter(void *__data, struct pt_regs *regs, long id)
{
  struct task_struct* task = current;
  struct process_key_t process_key;
  u32 hash;
  struct sched_key_t sched_key;
  u64 thresh, timeout;

  if (!watch_all)
  {
    process_key.tgid = task->tgid;
    hash = jhash(&process_key, sizeof(process_key), 0);

    rcu_read_lock();
    if (find_process(&process_key, hash) == NULL) {
      rcu_read_unlock();
      return;
    }
    rcu_read_unlock();
  }

  sched_key.pid = task->pid;
  thresh = usec_threshold * 1000;
  timeout = usec_timeout * 1000;

  latency_tracker_event_in(tracker, &sched_key, sizeof(sched_key),
        thresh, syscall_cb, timeout, 1, (void *) id);
}

static
void probe_syscall_exit(void *__data, struct pt_regs *regs, long ret)
{
  struct sched_key_t key;
  key.pid = current->pid;
  latency_tracker_event_out(tracker, &key, sizeof(key), 0);
}

static
void probe_sched_process_exit(void *__data, struct task_struct *p)
{
  // If this is the main thread of a process, unregister the process.
  if (p->pid == p->tgid) {
    process_unregister(p->tgid);
  }
}

static
void probe_sched_switch(void *ignore, struct task_struct *prev,
		struct task_struct *next)
{
  struct task_struct* task = next;
  struct process_key_t process_key;
  struct process_val_t *val;
  char stacktxt[MAX_STACK_TXT];
  u64 now;
  u32 hash;

  rcu_read_lock();
  process_key.tgid = task->tgid;
  hash = jhash(&process_key, sizeof(process_key), 0);

  val = find_process(&process_key, hash);
  if (!val)
    goto end_unlock;
  if (!val->take_stack_dump)
    goto end_unlock;

  now = trace_clock_read64();
  get_stack_txt(stacktxt, task);
  trace_syscall_latency_stack(
		  task->comm, task->pid,
		  now - val->syscall_start_ts, 0, stacktxt);
  val->take_stack_dump = 0;
  val->syscall_start_ts = 0;

end_unlock:
  rcu_read_unlock();
  return;
}

static
int __init syscalls_init(void)
{
  int ret;
  struct syscall_tracker *tracker_priv;

  wrapper_vmalloc_sync_all();

  tracker_priv = syscall_tracker_alloc_priv();
  if (!tracker_priv) {
    ret = -ENOMEM;
    goto end;
  }

  tracker = latency_tracker_create(NULL, NULL, 200000, 500000, 100000000, 0,
      tracker_priv);
  if (!tracker)
    goto error;

  ret = lttng_wrapper_tracepoint_probe_register(
      "sys_enter", probe_syscall_enter, NULL);
  WARN_ON(ret);
  ret = lttng_wrapper_tracepoint_probe_register(
      "sys_exit", probe_syscall_exit, NULL);
  WARN_ON(ret);
  ret = lttng_wrapper_tracepoint_probe_register(
      "sched_process_exit", probe_sched_process_exit, NULL);
  WARN_ON(ret);
  ret = lttng_wrapper_tracepoint_probe_register(
      "sched_switch", probe_sched_switch, NULL);
  WARN_ON(ret);

  ret = syscall_tracker_setup_proc_priv(tracker_priv);

  goto end;

error:
  ret = -1;
end:
  return ret;
}
module_init(syscalls_init);

static
void __exit syscalls_exit(void)
{
  struct process_val_t *process_val;
  int bkt;
  uint64_t skipped;
  struct syscall_tracker *tracker_priv;

  lttng_wrapper_tracepoint_probe_unregister(
      "sys_enter", probe_syscall_enter, NULL);
  lttng_wrapper_tracepoint_probe_unregister(
      "sys_exit", probe_syscall_exit, NULL);
  lttng_wrapper_tracepoint_probe_unregister(
      "sched_process_exit", probe_sched_process_exit, NULL);
  lttng_wrapper_tracepoint_probe_unregister(
      "sched_switch", probe_sched_switch, NULL);
  tracepoint_synchronize_unregister();

  rcu_read_lock();
  hash_for_each_rcu(process_map, bkt, process_val, hlist) {
    hash_del_rcu(&process_val->hlist);
    call_rcu(&process_val->rcu, free_process_val_rcu);
  }
  rcu_read_unlock();
  synchronize_rcu();

  skipped = latency_tracker_skipped_count(tracker);

  tracker_priv = latency_tracker_get_priv(tracker);
  syscall_tracker_destroy_proc_priv(tracker_priv);
  latency_tracker_destroy(tracker);

  printk("Missed events : %llu\n", skipped);
  printk("Total syscall alerts : %d\n", cnt);
}
module_exit(syscalls_exit);

MODULE_AUTHOR("Francois Doray <francois.pierre-doray@polymtl.ca>");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
