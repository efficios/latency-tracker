#!/bin/bash

destroy()
{
	lttng stop
	lttng destroy
	echo "You can now launch the analyses scripts on /$TRACEPATH"
	exit 0
}

#lttng-sessiond --extra-kmod-probes=latency_tracker -d
lttng create --snapshot >/tmp/lttngout
[[ $? != 0 ]] && exit 2
export TRACEPATH=$(grep Default /tmp/lttngout | cut -d'/' -f2-)
#rm /tmp/lttngout

trap "destroy" SIGINT SIGTERM

lttng enable-channel k -k
lttng enable-event -c k -k syscall_latency
lttng enable-event -c k -k syscall_latency_stack

lttng enable-channel u -u
lttng enable-event -c u -u lttng_profile:off_cpu_sample
lttng add-context -c u -u -t vtid

lttng start

while true; do
    cat /proc/syscalls
    echo 'Recording snapshot...'
    lttng snapshot record
done
