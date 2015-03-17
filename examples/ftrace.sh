#!/bin/bash
destroy()
{
	echo 0 >/sys/kernel/debug/tracing/tracing_on
	echo 0  >/sys/kernel/debug/tracing/events/latency_tracker/syscall_latency_stack/enable
	echo 0  >/sys/kernel/debug/tracing/events/latency_tracker/syscall_latency/enable
	cat /sys/kernel/debug/tracing/trace_pipe >/dev/null
	exit 0
}

trap "destroy" SIGINT SIGTERM

echo 1  >/sys/kernel/debug/tracing/events/latency_tracker/syscall_latency_stack/enable
echo 1  >/sys/kernel/debug/tracing/events/latency_tracker/syscall_latency/enable 
echo 1  >/sys/kernel/debug/tracing/tracing_on 
cat /sys/kernel/debug/tracing/trace_pipe
