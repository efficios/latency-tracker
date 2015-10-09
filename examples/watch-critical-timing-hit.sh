#!/bin/bash

destroy()
{
	lttng stop >/dev/null
	lttng destroy >/dev/null
	echo 0 >/sys/kernel/debug/tracing/tracing_on
	echo nop > /sys/kernel/debug/tracing/current_tracer
	exit 0
}

trap "destroy" SIGINT SIGTERM SIGPIPE SIGHUP

echo 0 > /sys/kernel/debug/tracing/options/function-trace  # don't need function tracing
echo 0 > /sys/kernel/debug/tracing/options/ftrace-buffer
echo preemptirqsoff > /sys/kernel/debug/tracing/current_tracer
echo 100 > /sys/kernel/debug/tracing/tracing_thresh      # set threshold (e.g. 2 µs)
echo 1 > /sys/kernel/debug/tracing/tracing_on

insmod latency_tracker.ko 2>/dev/null
insmod latency_tracker_critical_timing.ko 2>/dev/null

pgrep lttng-sessiond >/dev/null || lttng-sessiond -d
modprobe lttng_probe_core 2>/dev/null
modprobe lttng_probe_latency_tracker 2>/dev/null

lttng create --snapshot >/dev/null
lttng enable-channel -k chan1 --subbuf-size 2M >/dev/null
lttng enable-event -k -a -c chan1 >/dev/null
#lttng disable-event -k -c chan1 core_critical_timing_start,core_critical_timing_stop >/dev/null
lttng enable-event -u -a >/dev/null
lttng start >/dev/null

while true; do
	cat /proc/critical_timing_latency
	lttng stop >/dev/null
	lttng snapshot record
	lttng start >/dev/null
done
