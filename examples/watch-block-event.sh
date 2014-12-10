#!/bin/bash

#lttng-sessiond --extra-kmod-probes=latency_tracker -d
lttng create --snapshot -U net://192.168.122.1
lttng enable-channel -k chan1 --subbuf-size 2M
lttng add-context -k -t procname -c chan1
lttng enable-event -k -a -c chan1
lttng start

while true; do
	cat /proc/block_tracker
	lttng snapshot record
done

lttng stop
lttng destroy
