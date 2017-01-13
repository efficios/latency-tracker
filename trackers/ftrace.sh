#!/bin/sh
#
# Copyright (C) 2015 Julien Desfossez <jdesfossez@efficios.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; only
# version 2.1 of the License.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
#

destroy()
{
	echo 0 >/sys/kernel/debug/tracing/tracing_on
	echo 0  >/sys/kernel/debug/tracing/events/latency_tracker/latency_tracker_syscall_stack/enable
	echo 0  >/sys/kernel/debug/tracing/events/latency_tracker/latency_tracker_syscall/enable
	echo > /sys/kernel/debug/tracing/trace
	exit 0
}

trap "destroy" SIGINT SIGTERM SIGPIPE SIGHUP

echo 1  >/sys/kernel/debug/tracing/events/latency_tracker/latency_tracker_syscall_stack/enable
echo 1  >/sys/kernel/debug/tracing/events/latency_tracker/latency_tracker_syscall/enable
echo 1  >/sys/kernel/debug/tracing/tracing_on

cat /sys/kernel/debug/tracing/trace_pipe
