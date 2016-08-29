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
    lttng stop
    lttng snapshot record
    lttng start
done
