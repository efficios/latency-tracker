#!/bin/bash

echo 1  >/sys/kernel/debug/tracing/events/latency_tracker/syscall_latency_stack/enable
echo 1  >/sys/kernel/debug/tracing/events/latency_tracker/syscall_latency/enable 
echo 1  >/sys/kernel/debug/tracing/tracing_on 
cat /sys/kernel/debug/tracing/trace_pipe
