#!/bin/sh
#
# Copyright (C) 2015 Julien Desfossez <jdesfossez@efficios.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; only
# version 2.1 of the License.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
#

CONF="/sys/kernel/debug/latency/rt"

destroy()
{
	lttng destroy
	exit 0
}

if [ "$(id -u)" != "0" ]; then
	echo "Need to be root"
	exit 1
fi

trap "destroy" SIGINT SIGTERM SIGPIPE SIGHUP

chrt -r -p 99 $$
chrt -r -p 99 "$(pgrep lttng-sessiond)"
chrt -r -p 99 "$(pgrep lttng-consumerd)"

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
		chown -R "$SUDO_USER" /tmp/debugrt
	fi
	lttng start
done
