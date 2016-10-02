/*
 * ttfc.c
 *
 * Copyright (C) 2016 Julien Desfossez <jdesfossez@efficios.com>
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

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/jhash.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/stacktrace.h>
#include <linux/fdtable.h>
#include <linux/tcp.h>
#include <linux/ipv6.h>
#include <asm/syscall.h>
#include <asm/stacktrace.h>
#include "../latency_tracker.h"
#include "../wrapper/tracepoint.h"
#include "../wrapper/trace-clock.h"
#include "../wrapper/lt_probe.h"

#include <trace/events/latency_tracker.h>

/*
 * Threshold to execute the callback (microseconds).
 */
#define DEFAULT_USEC_OFFCPU_THRESH 5 * 1000 * 1000
/*
 * Timeout to execute the callback (microseconds).
 */
#define DEFAULT_USEC_OFFCPU_TIMEOUT 0

/*
 * microseconds because we can't guarantee the passing of 64-bit
 * arguments to insmod on all architectures.
 */
static unsigned long usec_threshold = DEFAULT_USEC_OFFCPU_THRESH;
module_param(usec_threshold, ulong, 0444);
MODULE_PARM_DESC(usec_threshold, "Threshold in microseconds");

static unsigned long usec_timeout = DEFAULT_USEC_OFFCPU_TIMEOUT;
module_param(usec_timeout, ulong, 0444);
MODULE_PARM_DESC(usec_timeout, "Timeout in microseconds");

struct ttfbkey {
	struct inode *f_inode;
} __attribute__((__packed__));
#undef MAX_KEY_SIZE
#define MAX_KEY_SIZE sizeof(struct ttfbkey)

static struct latency_tracker *tracker;

static int cnt = 0;

static
void ipv4_str(unsigned long ip, char *str, uint16_t port)
{
	snprintf(str, 22, "%lu.%lu.%lu.%lu:%u",
			ip >> 24,
			ip >> 16 & 0xFF,
			ip >> 8 & 0xFF,
			ip & 0xFF,
			port);
}

static
void ipv6_str(const u8 *ip, char *str, uint16_t port)
{
	snprintf(str, 47,
		"[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
		"%02x%02x:%02x%02x]:%u",
			ip[0], ip[1],
			ip[2], ip[3],
			ip[4], ip[5],
			ip[6], ip[7],
			ip[8], ip[9],
			ip[10], ip[11],
			ip[12], ip[13],
			ip[14], ip[15],
			port);
}

static
int get_peer_str(int fd, char *s_str, char *d_str)
{
	struct files_struct *files = current->files;
	struct socket *sock;
	int *err = NULL;
	struct fd f;
	int ret = -1;
	struct inet_sock *inet;
	struct ipv6_pinfo *inet6;

	spin_lock(&files->file_lock);
	f = fdget(fd);
	if (!f.file)
		goto end;

	sock = sock_from_file(f.file, err);
	if (!sock)
		goto end_put;

	inet6 = inet6_sk(sock->sk);
	inet = inet_sk(sock->sk);
	if (sock->sk->sk_family == AF_INET6) {
		ipv6_str(sock->sk->sk_v6_daddr.s6_addr, s_str,
				ntohs(inet->inet_sport));
		ipv6_str(sock->sk->sk_v6_rcv_saddr.s6_addr, d_str,
				ntohs(inet->inet_dport));
	} else if (sock->sk->sk_family == AF_INET) {
		ipv4_str(ntohl(inet->inet_saddr), s_str,
				ntohs(inet->inet_sport));
		ipv4_str(ntohl(inet->inet_daddr), d_str,
				ntohs(inet->inet_dport));
	} else {
		ret = -1;
		goto end_put;
	}
	ret = 0;

end_put:
	fdput(f);

end:
	spin_unlock(&files->file_lock);

	return ret;
}

static
void ttfb_cb(struct latency_tracker_event_ctx *ctx)
{
	uint64_t end_ts = latency_tracker_event_ctx_get_end_ts(ctx);
	uint64_t start_ts = latency_tracker_event_ctx_get_start_ts(ctx);
	unsigned int fd = latency_tracker_event_ctx_get_cb_out_id(ctx);
	enum latency_tracker_cb_flag cb_flag =
		latency_tracker_event_ctx_get_cb_flag(ctx);
	char s_str[47], d_str[47];
	u64 delay;
	int ret;

	if (cb_flag != LATENCY_TRACKER_CB_NORMAL)
		return;

	if (fd == -1U)
		return;

	delay = (end_ts - start_ts) / 1000;
#ifdef SCHEDWORST
	usec_threshold = delay;
#endif

	ret = get_peer_str(fd, s_str, d_str);
	if (ret)
		return;

	rcu_read_lock();
	printk("ttfb: %s (%d), delay = %llu us, %s -> %s\n",
			current->comm,
			current->pid, delay,
			s_str, d_str);
//	trace_latency_tracker_ttfb_sched_switch(p->comm, key->pid, end_ts - start_ts,
//			cb_flag, stacktxt);
	cnt++;

	rcu_read_unlock();
}

int fd_from_regs(struct pt_regs *regs)
{
#ifdef __i386__
	return regs->ax;
#else /* __i386__ */
        return regs->di;
#endif /* __i386__ */
}

LT_PROBE_DEFINE(syscall_enter, struct pt_regs *regs, long id)
{
	struct ttfbkey key;
	struct file *file;
	int fd;
	unsigned int cb_id;
	unsigned long x;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	switch(id) {
	case __NR_write:
	case __NR_writev:
		fd = fd_from_regs(regs);
		file = fcheck_files(current->files, fd);
		if (!file)
			return;
		key.f_inode = file->f_inode;
		cb_id = fd;
		break;
	case __NR_close:
	case __NR_shutdown:
		fd = fd_from_regs(regs);
		file = fcheck_files(current->files, fd);
		if (!file)
			return;
		x = atomic_long_read(&file->f_count);
		if (x > 1)
			return;
		key.f_inode = file->f_inode;
		cb_id = -1U;
		break;
	default:
		return;
	}

	/* Pass the FD as cb_out_id so that it is easy to get in the cb */
	latency_tracker_event_out(tracker, NULL, &key, sizeof(key), cb_id, 0);
}

LT_PROBE_DEFINE(syscall_exit, struct pt_regs *regs, long ret)
{
	struct ttfbkey key;
	long id;
	struct file *file;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	id = syscall_get_nr(current, regs);

	switch(id) {
	case __NR_accept:
	case __NR_accept4:
		file = fcheck_files(current->files, ret);
		if (!file)
			return;
		key.f_inode = file->f_inode;
		break;
	default:
		return;
	}

	/*
	printk("IN: %p, %d %s\n", key.f_inode, key.pid,
			file->f_path.dentry->d_name.name);
			*/

	ret = latency_tracker_event_in(tracker, &key, sizeof(key),
		1, NULL);
	if (ret == LATENCY_TRACKER_FULL) {
		printk("latency_tracker net: no more free events, consider "
				"increasing the max_events parameter\n");
	} else if (ret) {
		printk("latency_tracker net: error adding event\n");
	}
}

static
int __init ttfb_init(void)
{
	int ret;

	tracker = latency_tracker_create("ttfb");
	if (!tracker)
		goto error;
	latency_tracker_set_startup_events(tracker, 2000);
	latency_tracker_set_max_resize(tracker, 10000);
	latency_tracker_set_timer_period(tracker, 100000000);
	latency_tracker_set_threshold(tracker, usec_threshold * 1000);
	latency_tracker_set_timeout(tracker, usec_timeout * 1000);
	latency_tracker_set_callback(tracker, ttfb_cb);
	latency_tracker_set_key_size(tracker, MAX_KEY_SIZE);
	ret = latency_tracker_enable(tracker);
	if (ret)
		goto error;

	ret = lttng_wrapper_tracepoint_probe_register(
			"sys_enter", probe_syscall_enter, NULL);
	WARN_ON(ret);
	ret = lttng_wrapper_tracepoint_probe_register(
			"sys_exit", probe_syscall_exit, NULL);
	WARN_ON(ret);

	goto end;

error:
	ret = -1;
end:
	return ret;
}
module_init(ttfb_init);

static
void __exit ttfb_exit(void)
{
	uint64_t skipped;

	lttng_wrapper_tracepoint_probe_unregister(
			"sys_enter", probe_syscall_enter, NULL);
	lttng_wrapper_tracepoint_probe_unregister(
			"sys_exit", probe_syscall_exit, NULL);
	tracepoint_synchronize_unregister();
	skipped = latency_tracker_skipped_count(tracker);
	latency_tracker_destroy(tracker);
	printk("Missed events : %llu\n", skipped);
	printk("Total ttfb alerts : %d\n", cnt);
}
module_exit(ttfb_exit);

MODULE_AUTHOR("Julien Desfossez <jdesfossez@efficios.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
