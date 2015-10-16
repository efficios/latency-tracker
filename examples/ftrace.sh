#!/bin/bash
destroy()
{
	echo 0 >/sys/kernel/debug/tracing/tracing_on
	echo 0  >/sys/kernel/debug/tracing/events/latency_tracker/latency_tracker_syscall_stack/enable
	echo 0  >/sys/kernel/debug/tracing/events/latency_tracker/latency_tracker_syscall_fd/enable
	echo 0  >/sys/kernel/debug/tracing/events/latency_tracker/latency_tracker_syscall/enable
	cat /sys/kernel/debug/tracing/trace_pipe >/dev/null
	exit 0
}

trap "destroy" SIGINT SIGTERM SIGPIPE SIGHUP

#echo 1  >/sys/kernel/debug/tracing/events/latency_tracker/latency_tracker_syscall_stack/enable
echo 1  >/sys/kernel/debug/tracing/events/latency_tracker/latency_tracker_syscall_fd/enable
#echo 1  >/sys/kernel/debug/tracing/events/latency_tracker/latency_tracker_syscall/enable
echo 1  >/sys/kernel/debug/tracing/tracing_on
cat /sys/kernel/debug/tracing/trace_pipe
