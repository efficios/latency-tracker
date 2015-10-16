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
 * /sys/module/latency_tracker_syscalls/parameters/usec_threshold
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
#include <linux/fdtable.h>
#include <linux/tcp.h>
#include <asm/syscall.h>
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
 * At threshold/2 start taking the kernel stack at every
 * sched_switch of the process until the syscall is completed.
 */
#define DEFAULT_TAKE_KERNEL_STACK 1
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

static unsigned long take_kernel_stack = DEFAULT_TAKE_KERNEL_STACK;
module_param(take_kernel_stack, ulong, 0644);
MODULE_PARM_DESC(take_kernel_stack, "Extract kernel stack at timeout/2");

static unsigned long watch_all = DEFAULT_WATCH_ALL_PROCESSES;
module_param(watch_all, ulong, 0644);
MODULE_PARM_DESC(watch_all, "Watch all processes or just registered ones");

static int cnt = 0;

static struct latency_tracker *tracker;

enum tracker_key_type {
	KEY_SYSCALL = 0,
	KEY_POLLFD = 1,
};

enum tracker_out_reason {
	OUT_SYSCALL,
	OUT_POLLFD,
	OUT_POLLFD_NOCB,
};

struct pollfd_key_t {
	pid_t pid;
	int fd;
	enum tracker_key_type type;
} __attribute__((__packed__));

struct sched_key_t {
	pid_t pid;
	enum tracker_key_type type;
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
		if (MAX_STACK_TXT - j < 0)
			return;
	}
}

static
void syscall_cb(struct latency_tracker_event_ctx *ctx)
{
	uint64_t end_ts = latency_tracker_event_ctx_get_end_ts(ctx);
	uint64_t start_ts = latency_tracker_event_ctx_get_start_ts(ctx);
	enum latency_tracker_cb_flag cb_flag = latency_tracker_event_ctx_get_cb_flag(ctx);
	int out_id = latency_tracker_event_ctx_get_cb_out_id(ctx);
	struct process_key_t process_key;
	struct process_val_t *val;
	struct task_struct* task;
	int send_sig = 0;
	u32 hash;

	if (out_id == OUT_POLLFD_NOCB) {
		return;
	}

	rcu_read_lock();
	if (cb_flag == LATENCY_TRACKER_CB_TIMEOUT) {
		goto end_unlock;
	} else if (cb_flag == LATENCY_TRACKER_CB_NORMAL) {
		task = current;
	} else {
		goto end_unlock;
	}

	process_key.tgid = task->tgid;
	hash = jhash(&process_key, sizeof(process_key), 0);

	val = find_process(&process_key, hash);
	if (val)
		send_sig = 1;

	trace_latency_tracker_syscall(task->comm, task->pid,
			start_ts, end_ts - start_ts);
	if (send_sig)
		send_sig_info(SIGPROF, SEND_SIG_NOINFO, task);
	else
		syscall_tracker_handle_proc(latency_tracker_get_priv(tracker));
	rcu_read_unlock();

	++cnt;
	goto end;

end_unlock:
	rcu_read_unlock();

end:
	return;
}

static
void ipv4_str(unsigned long ip, char *str)
{
	snprintf(str, 16, "%lu.%lu.%lu.%lu",
			ip >> 24,
			ip >> 16 & 0xFF,
			ip >> 8 & 0xFF,
			ip & 0xFF);
}

#if 0
static
int io_syscall(long id)
{
	switch(id) {
		case __NR_read:
		case __NR_pread64:
		case __NR_readv:
		case __NR_preadv:
		case __NR_recvfrom:
		case __NR_recvmsg:
		case __NR_getdents:
		case __NR_getdents64:
		case __NR_statfs:
		case __NR_fstatfs:
			return IO_SYSCALL_READ;

		case __NR_write:
		case __NR_pwrite64:
		case __NR_writev:
		case __NR_pwritev:
		case __NR_sendto:
		case __NR_sendmsg:
		case __NR_mkdir:
		case __NR_mkdirat:
		case __NR_rmdir:
		case __NR_creat:
		case __NR_mknod:
		case __NR_mknodat:
		case __NR_vmsplice:
		case __NR_sendmmsg:
			return IO_SYSCALL_WRITE;

		case __NR_sendfile:
		case __NR_splice:
			return IO_SYSCALL_RW;

		case __NR_fsync:
		case __NR_fdatasync:
		case __NR_sync:
		case __NR_sync_file_range:
		case __NR_syncfs:
			return IO_SYSCALL_SYNC;

		case __NR_open:
		case __NR_pipe:
		case __NR_pipe2:
		case __NR_dup2:
		case __NR_dup3:
		case __NR_socket:
		case __NR_connect:
//		case __NR_accept:
//		case __NR_accept4:
		case __NR_execve:
		case __NR_chdir:
		case __NR_fchdir:
		case __NR_mount:
		case __NR_umount2:
		case __NR_swapon:
		case __NR_openat:
			return IO_SYSCALL_OPEN;

		case __NR_close:
		case __NR_swapoff:
		case __NR_shutdown:
			return IO_SYSCALL_CLOSE;

		default:
			break;
	}
	return -1;
}

static
void test_read(struct pt_regs *regs)
{
	unsigned long args[1];
	struct files_struct *files = current->files;
	int fd;
	struct path *path = NULL;
	struct socket *sock;
	int err = NULL;
	struct fd f;

	if (current->comm[0] != 's' ||
		current->comm[1] != 's' ||
		current->comm[2] != 'h' ||
		current->comm[3] != 'd')
		return;
	if (nb_print++ > 10)
		return;

	syscall_get_arguments(current, regs, 0, 1, args);
	fd = args[0];

	spin_lock(&files->file_lock);
	//printk("test: %s\n", current->files->fd_array[fd]->f_path.dentry->d_name.name);
	f = fdget(fd);
	if (f.file) {
		sock = sock_from_file(f.file, &err);
		if (sock) {
			struct inet_sock *inet = inet_sk(sock->sk);
			char s_ipv4[16], d_ipv4[16];

			ipv4_str(ntohl(inet->inet_saddr), s_ipv4);
			ipv4_str(ntohl(inet->inet_daddr), d_ipv4);
			printk("found %s:%u -> %s:%u\n",
					s_ipv4, ntohs(inet->inet_sport),
					d_ipv4, ntohs(inet->inet_dport));
		}
		fdput(f);
	}
	spin_unlock(&files->file_lock);

	printk("%d (%s) read on fd %d, path %p\n", current->pid, current->comm, fd, path);
}
#endif

static int nb_print = 0;

static
void poll_fds(struct pt_regs *regs)
{
	/* struct pollfd *fds, nfds_t nfds, int timeout */
	unsigned long args[3];
	struct pollfd *fds;
	int ret, i;

	if (nb_print++ > 10)
		return;

	syscall_get_arguments(current, regs, 0, 3, args);
	fds = kmalloc(args[1] * sizeof(struct pollfd), GFP_KERNEL);
	if (!fds)
		goto end;

	ret = copy_from_user(fds, (void *) args[0], args[1] * sizeof(struct pollfd));
	if (ret)
		goto end_free;

	printk("%s (%d) polling on %lu fds:\n", current->comm, current->pid,
			args[1]);
	for (i = 0; i < args[1]; i++) {
		int fd = fds[i].fd;
		struct fd f;
		struct files_struct *files = current->files;
		struct socket *sock;
		int err = NULL;
		struct pollfd_key_t key;

		spin_lock(&files->file_lock);
		f = fdget(fd);
		if (!f.file) {
			printk("LA %d\n", fd);
			fdput(f);
			spin_unlock(&files->file_lock);
			continue;
		}
		/*
		 * Keep track of each individual FD passed to poll, only
		 * extract them when they have activity (so they stay in the
		 * HT as long as they are inactive even if poll returns because
		 * of a timeout or another FD.
		 * They can also be removed if they get closed.
		 */
		key.pid = current->pid;
		key.fd = fd;
		key.type = KEY_POLLFD;
		latency_tracker_event_in(tracker, &key, sizeof(key), 1, NULL);

		sock = sock_from_file(f.file, &err);
		if (sock) {
			switch (sock->type) {
			case SOCK_STREAM:
				printk("- FD %d (%d, %d) (SOCK_STREAM)\n", fd,
						fds[i].events, fds[i].revents);
				break;
			case SOCK_DGRAM:
			{
				struct inet_sock *inet = inet_sk(sock->sk);
				char s_ipv4[16], d_ipv4[16];

				ipv4_str(ntohl(inet->inet_saddr), s_ipv4);
				ipv4_str(ntohl(inet->inet_daddr), d_ipv4);
				printk("- FD (%d, %d) %d = %s:%u -> %s:%u\n",
						fds[i].events, fds[i].revents, fd,
						s_ipv4, ntohs(inet->inet_sport),
						d_ipv4, ntohs(inet->inet_dport));
				break;
			}
			case SOCK_RAW:
				printk("- FD (%d, %d) %d (SOCK_RAW)\n", fds[i].events,
						fds[i].revents, fd);
				break;
			default:
				printk("- FD (%d, %d) %d (SOCK other)\n", fds[i].events,
						fds[i].revents, fd);
				break;
			}
		} else {
			printk("- FD %d (%d, %d) (FILE)\n", fd, fds[i].events,
					fds[i].revents);
		}
		fdput(f);
		spin_unlock(&files->file_lock);
	}

end_free:
	kfree(fds);
end:
	return;
}

/*
 * on syscall entry, look if we are working on a FD that we have been polling
 * before, if it is the case, remove it from our internal state and don't
 * execute the callback because we were not polling on it anymore.
 * example use case:
 * - poll on 2 FDs (1 and 2)
 * - FD 1 returns with activity
 * - the program reads on FD 1 and writes on FD 2
 * in this case we cannot consider that FD 2 is still blocked in poll
 *
 * different than:
 * - poll on 2 FDs (1 and 2)
 * - FD 1 returns with activity (or poll times out)
 * - the program handles it and goes back to polling on the 2 FDs
 * in this case, we consider FD 2 blocked as long as there is no
 * activity on it even if poll returns.
 *
 * TODO: cleanup when the process dies.
 */
static
void fd_out(int fd)
{
	struct pollfd_key_t key;

	key.pid = current->pid;
	key.fd = fd;
	key.type = KEY_POLLFD;
	latency_tracker_event_out(tracker, &key, sizeof(key),
			OUT_POLLFD_NOCB);
}

static
void syscall_fd_out(unsigned long id, struct pt_regs *regs)
{
	unsigned long fd;

	switch (id) {
		/* FD is the first argument */
		case __NR_read:
		case __NR_pread64:
		case __NR_readv:
		case __NR_preadv:
		case __NR_recvfrom:
		case __NR_recvmsg:
		case __NR_getdents:
		case __NR_getdents64:
		case __NR_fstatfs:
		case __NR_write:
		case __NR_pwrite64:
		case __NR_writev:
		case __NR_pwritev:
		case __NR_sendto:
		case __NR_sendmsg:
		case __NR_mkdirat:
		case __NR_mknodat:
		case __NR_vmsplice:
		case __NR_sendmmsg:
		case __NR_fsync:
		case __NR_fdatasync:
		case __NR_sync_file_range:
		case __NR_syncfs:
		case __NR_open:
		case __NR_connect:
		case __NR_accept:
		case __NR_accept4:
		case __NR_openat:
		case __NR_close:
		case __NR_shutdown:
			syscall_get_arguments(current, regs, 0, 1, &fd);
			fd_out(fd);
			break;
		/* 0 in, 1 out */
		case __NR_sendfile:
			syscall_get_arguments(current, regs, 0, 1, &fd);
			fd_out(fd);
			syscall_get_arguments(current, regs, 1, 1, &fd);
			fd_out(fd);
			break;
		/* 0 in, 2 out */
		case __NR_splice:
			syscall_get_arguments(current, regs, 0, 1, &fd);
			fd_out(fd);
			syscall_get_arguments(current, regs, 2, 1, &fd);
			fd_out(fd);
			break;
		default:
			break;
	}
	return;
}

static
void probe_syscall_enter(void *__data, struct pt_regs *regs, long id)
{
	struct task_struct* task = current;
	struct process_key_t process_key;
	u32 hash;
	struct sched_key_t sched_key;

	if (!watch_all) {
		process_key.tgid = task->tgid;
		hash = jhash(&process_key, sizeof(process_key), 0);

		rcu_read_lock();
		if (find_process(&process_key, hash) == NULL) {
			rcu_read_unlock();
			return;
		}
		rcu_read_unlock();
	}

	switch (id) {
	case __NR_poll:
		poll_fds(regs);
		break;
	default:
		syscall_fd_out(id, regs);
		break;
	}
	sched_key.pid = task->pid;
	sched_key.type = KEY_SYSCALL;
	latency_tracker_event_in(tracker, &sched_key, sizeof(sched_key),
			1, (void *) id);
}

static
void poll_out(struct pt_regs *regs, long sys_ret)
{
	/* struct pollfd *fds, nfds_t nfds, int timeout */
	unsigned long args[3];
	struct pollfd *fds;
	int ret, i;

	if (nb_print++ > 10)
		return;

	printk("OUT %ld\n", sys_ret);
	syscall_get_arguments(current, regs, 0, 3, args);
	fds = kmalloc(args[1] * sizeof(struct pollfd), GFP_KERNEL);
	if (!fds) {
		printk("malloc failed\n");
		goto end;
	}

	ret = copy_from_user(fds, (void *) args[0], args[1] * sizeof(struct pollfd));
	if (ret) {
		printk("copy failed\n");
		goto end_free;
	}

	for (i = 0; i < args[1]; i++) {
		printk("- FD OUT: %d (%d, %d)\n", fds[i].fd,
				fds[i].events, fds[i].revents);
		if (fds[i].events & fds[i].revents) {
			struct pollfd_key_t key;

			key.pid = current->pid;
			key.fd = fds[i].fd;
			key.type = KEY_POLLFD;
			latency_tracker_event_out(tracker, &key, sizeof(key),
					OUT_POLLFD);
		}
	}
end_free:
	kfree(fds);
end:
	return;
}

static
void probe_syscall_exit(void *__data, struct pt_regs *regs, long ret)
{
	struct sched_key_t key;
	struct latency_tracker_event *s;

	key.pid = current->pid;
	key.type = KEY_SYSCALL;

	s = latency_tracker_get_event(tracker, &key, sizeof(key));
	if (s) {
		unsigned long id;

		id = (unsigned long) latency_tracker_event_get_priv(s);
		if (id == __NR_poll) {
			poll_out(regs, ret);
		}
		latency_tracker_put_event(s);
	}

	latency_tracker_event_out(tracker, &key, sizeof(key), OUT_SYSCALL);
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
	struct sched_key_t sched_key;
	struct latency_tracker_event *s;
	char stacktxt[MAX_STACK_TXT];
	u64 now, delta;

	if (!task)
		goto end;
	if (!take_kernel_stack)
		goto end;
	sched_key.pid = task->pid;
	sched_key.type = KEY_SYSCALL;
	s = latency_tracker_get_event(tracker, &sched_key, sizeof(sched_key));
	if (!s)
		goto end;
	now = trace_clock_read64();
	delta = now - latency_tracker_event_get_start_ts(s);
	if (delta > ((usec_threshold * 1000)/2)) {
		get_stack_txt(stacktxt, task);
		trace_latency_tracker_syscall_stack(
				task->comm, task->pid, latency_tracker_event_get_start_ts(s),
				delta, 0, stacktxt);
	}
	latency_tracker_put_event(s);

end:
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

	tracker = latency_tracker_create();
	if (!tracker)
		goto error;
	latency_tracker_set_timer_period(tracker, 100000000);
	latency_tracker_set_startup_events(tracker, 1000);
	latency_tracker_set_max_resize(tracker, 20000);
	latency_tracker_set_priv(tracker, tracker_priv);
	latency_tracker_set_threshold(tracker, usec_threshold * 1000);
	latency_tracker_set_callback(tracker, syscall_cb);
	ret = latency_tracker_enable(tracker);
	if (ret)
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
