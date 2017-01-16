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
#include "../tracker_debugfs.h"
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
void ipv4_str(unsigned long ip, char *str)
{
	snprintf(str, 16, "%lu.%lu.%lu.%lu",
			ip >> 24,
			ip >> 16 & 0xFF,
			ip >> 8 & 0xFF,
			ip & 0xFF);
}

static
void ipv6_str(const u8 *ip, char *str)
{
	snprintf(str, 40,
		"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
		"%02x%02x:%02x%02x",
			ip[0], ip[1],
			ip[2], ip[3],
			ip[4], ip[5],
			ip[6], ip[7],
			ip[8], ip[9],
			ip[10], ip[11],
			ip[12], ip[13],
			ip[14], ip[15]);
}

static
int get_peers_data(int fd, int *family, char *saddr4, char *saddr6,
		unsigned int *sport, char *daddr4, char *daddr6,
		unsigned int *dport)
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
	if (sock->sk->sk_family == AF_INET) {
		ipv4_str(ntohl(inet->inet_saddr), saddr4);
		ipv4_str(ntohl(inet->inet_daddr), daddr4);
		saddr6[0] = '\0';
		daddr6[0] = '\0';
		*family = AF_INET;
	} else if (sock->sk->sk_family == AF_INET6) {
		ipv6_str(sock->sk->sk_v6_daddr.s6_addr, saddr6);
		ipv6_str(sock->sk->sk_v6_rcv_saddr.s6_addr, daddr6);
		saddr4[0] = '\0';
		daddr4[0] = '\0';
		*family = AF_INET6;
	} else {
		ret = -1;
		goto end_put;
	}
	*sport = ntohs(inet->inet_sport);
	*dport = ntohs(inet->inet_dport);
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
	char saddr4[16], daddr4[16];
	char saddr6[40], daddr6[40];
	unsigned int sport = 0, dport = 0;
	u64 delay;
	int family = -1, ret;

	if (cb_flag != LATENCY_TRACKER_CB_NORMAL)
		return;

	if (fd == -1U)
		return;

	delay = end_ts - start_ts;
#ifdef SCHEDWORST
	usec_threshold = delay;
#endif

	ret = get_peers_data(fd, &family, saddr4, saddr6, &sport,
			daddr4, daddr6, &dport);
	if (ret)
		return;

	rcu_read_lock();
	/*
	printk("ttfb: %s (%d), delay = %llu us, %s -> %s\n",
			current->comm,
			current->pid, delay,
			s_str, d_str);
			*/
	trace_latency_tracker_ttfb(current->comm, current->pid, delay,
			family, saddr4, saddr6, sport, daddr4, daddr6, dport);
//			cb_flag, stacktxt);
	cnt++;

	rcu_read_unlock();

	/*
	 * Test: only wakeup if delay > 10ms.
	 * FIXME: should be configurable.
	 */
	if (delay > (10 * 1000 * 1000))
		latency_tracker_debugfs_wakeup_pipe(tracker);
}
#if defined(__x86_64__)
#define PT_REGS_PARM1(x) ((x)->di)
#elif defined(__i386__)
#define PT_REGS_PARM1(x) ((x)->di)
#elif defined(__aarch64__)
#define PT_REGS_PARM1(x) ((x)->regs[0])
#elif defined(__arm__)
#define PT_REGS_PARM1(x) ((x)->ARM_ORIG_r0)
#else
#error "Unsupported Architecture, unable to parse pt_reg"
#endif

int fd_from_regs(struct pt_regs *regs)
{
	return PT_REGS_PARM1(regs);
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
#ifndef __i386__
	case __NR_accept:
#endif
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

	ret = latency_tracker_debugfs_setup_wakeup_pipe(tracker);
	if (ret != 0)
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
MODULE_LICENSE("GPL and additional rights");
MODULE_VERSION("1.0");
