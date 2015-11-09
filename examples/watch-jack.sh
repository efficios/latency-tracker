#!/bin/bash

CONF="/sys/kernel/debug/latency/rt"

destroy()
{
	lttng destroy
	exit 0
}

if test $UID != 0; then
	echo "Need to be root"
	exit -1
fi

trap "destroy" SIGINT SIGTERM SIGPIPE SIGHUP

chrt -r -p 99 $$
chrt -r -p 99 $(pgrep lttng-sessiond)
chrt -r -p 99 $(pgrep lttng-consumerd)

rm -rf /tmp/debugrt
pgrep -u root lttng-sessiond || lttng-sessiond -d
lttng create --snapshot -o /tmp/debugrt
lttng enable-channel -k bla --subbuf-size 2M
lttng enable-event -k -a -c bla
lttng enable-event -u -a
lttng start

echo 25000000 > $CONF/threshold
echo 0 > $CONF/filters/timer_tracing
echo 1 > $CONF/filters/irq_tracing
echo -1 > $CONF/filters/irq_filter
echo -1 > $CONF/filters/softirq_filter
echo 1 > $CONF/filters/enter_userspace
echo 0 > $CONF/filters/switch_out_blocked
echo jackd > $CONF/filters/procname

while true; do
	cat $CONF/wakeup_pipe
	lttng stop
	lttng snapshot record
	if test "$SUDO_USER" != ""; then
		chown -R $SUDO_USER /tmp/debugrt
	fi
	lttng start
done
