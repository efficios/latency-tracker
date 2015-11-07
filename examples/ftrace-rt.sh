#!/bin/bash

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

