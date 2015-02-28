#!/bin/bash

#lttng-sessiond --extra-kmod-probes=latency_tracker -d
lttng create --snapshot
lttng enable-channel -k chan1 --subbuf-size 2M
lttng enable-event -k -a -c chan1
lttng start

while true; do
	cat /proc/wake_latency
	lttng snapshot record
done

lttng stop
lttng destroy
