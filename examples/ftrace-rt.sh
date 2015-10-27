#!/bin/bash

#echo 1 > /sys/kernel/debug/tracing/events/irq/irq_handler_entry/enable
#echo 1 > /sys/kernel/debug/tracing/events/irq/irq_handler_exit/enable
#echo 1 > /sys/kernel/debug/tracing/events/irq/softirq_entry/enable
#echo 1 > /sys/kernel/debug/tracing/events/irq/softirq_exit/enable
#echo 1 > /sys/kernel/debug/tracing/events/sched/sched_waking/enable
#echo 1 > /sys/kernel/debug/tracing/events/sched/sched_switch/enable
#echo 1 > /sys/kernel/debug/tracing/events/timer/hrtimer_expire_entry/enable
#echo 1 > /sys/kernel/debug/tracing/events/timer/hrtimer_expire_exit/enable

echo 1 >/sys/kernel/debug/tracing/events/latency_tracker/latency_tracker_rt/enable
echo 1 > /sys/kernel/debug/tracing/tracing_on 
cat /sys/kernel/debug/tracing/trace_pipe 

