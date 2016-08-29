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

#echo 1 > /sys/kernel/debug/tracing/events/irq/irq_handler_entry/enable
#echo 1 > /sys/kernel/debug/tracing/events/irq/irq_handler_exit/enable
#echo 1 > /sys/kernel/debug/tracing/events/irq/softirq_entry/enable
#echo 1 > /sys/kernel/debug/tracing/events/irq/softirq_exit/enable
#echo 1 > /sys/kernel/debug/tracing/events/sched/sched_waking/enable
#echo 1 > /sys/kernel/debug/tracing/events/sched/sched_switch/enable
#echo 1 > /sys/kernel/debug/tracing/events/timer/hrtimer_expire_entry/enable
#echo 1 > /sys/kernel/debug/tracing/events/timer/hrtimer_expire_exit/enable

destroy()
{
	echo 0 >/sys/kernel/debug/tracing/tracing_on
	echo > /sys/kernel/debug/tracing/trace
	exit 0
}

trap "destroy" SIGINT SIGTERM SIGPIPE SIGHUP

echo 1 >/sys/kernel/debug/tracing/events/latency_tracker/latency_tracker_rt/enable
echo 1 > /sys/kernel/debug/tracing/tracing_on 

while true; do
	cat /sys/kernel/debug/tracing/trace_pipe
done

