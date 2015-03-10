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
#include "syscalls.h"
#include "../latency_tracker.h"
#include "../wrapper/tracepoint.h"
#include "../wrapper/vmalloc.h"

#include <trace/events/latency_tracker.h>

/*
 * Threshold to execute the callback (microseconds).
 */
#define DEFAULT_USEC_SYSCALL_THRESH 1 * 1000 * 1000

/*
 * microseconds because we can't guarantee the passing of 64-bit
 * arguments to insmod on all architectures.
 */
static unsigned long usec_threshold = DEFAULT_USEC_SYSCALL_THRESH;
module_param(usec_threshold, ulong, 0644);
MODULE_PARM_DESC(usec_threshold, "Threshold in microseconds");

static int cnt = 0;

static struct latency_tracker *tracker;

struct sched_key_t {
  pid_t pid;
} __attribute__((__packed__));

struct process_key_t {
  pid_t tgid;
} __attribute__((__packed__));

struct process_val_t {
  pid_t tgid;
  struct hlist_node hlist;
  struct rcu_head rcu;
};

static DEFINE_HASHTABLE(process_map, 3);

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
void syscall_cb(unsigned long ptr)
{
  struct latency_tracker_event *data =
    (struct latency_tracker_event *) ptr;
  u32 hash;
  struct process_key_t process_key;
  struct task_struct* task = current;

  process_key.tgid = task->tgid;
  hash = jhash(&process_key, sizeof(process_key), 0);

  if (find_process(&process_key, hash) == NULL)
  {
    trace_syscall_latency(task->comm, task->pid, data->end_ts - data->start_ts);
  }
  else
  {
    send_sig_info(SIGPROF, SEND_SIG_NOINFO, task);
  }

  ++cnt;
}

static
void probe_syscall_enter(void *__data, struct pt_regs *regs, long id)
{
  struct sched_key_t sched_key;
  u64 thresh, timeout;

  sched_key.pid = current->pid;
  thresh = usec_threshold * 1000;
  timeout = 0;

  latency_tracker_event_in(tracker, &sched_key, sizeof(sched_key),
        thresh, syscall_cb, timeout, 1, NULL);
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
int __init syscalls_init(void)
{
  int ret;

  wrapper_vmalloc_sync_all();

  tracker = latency_tracker_create(NULL, NULL, 200, 5000, 100000000, 0,
      NULL);
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

  ret = syscall_tracker_setup_proc_priv();

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

  syscall_tracker_destroy_proc_priv();

  lttng_wrapper_tracepoint_probe_unregister(
      "sys_enter", probe_syscall_enter, NULL);
  lttng_wrapper_tracepoint_probe_unregister(
      "sys_exit", probe_syscall_exit, NULL);
  lttng_wrapper_tracepoint_probe_unregister(
      "sched_process_exit", probe_sched_process_exit, NULL);
  tracepoint_synchronize_unregister();

  rcu_read_lock();
  hash_for_each_rcu(process_map, bkt, process_val, hlist) {
    hash_del_rcu(&process_val->hlist);
    call_rcu(&process_val->rcu, free_process_val_rcu);
  }
  rcu_read_unlock();
  synchronize_rcu();

  skipped = latency_tracker_skipped_count(tracker);
  latency_tracker_destroy(tracker);
  printk("Missed events : %llu\n", skipped);
  printk("Total syscall alerts : %d\n", cnt);
}
module_exit(syscalls_exit);

MODULE_AUTHOR("Francois Doray <francois.pierre-doray@polymtl.ca>");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
