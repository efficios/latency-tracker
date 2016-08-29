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

set -e

dmesg -c >/dev/null
make clean

run() {
	name=$1
	flags=$2
	echo "$name"
	make EXTCFLAGS="$flags"
	insmod latency_tracker.ko
	insmod latency_tracker_wakeup.ko
	insmod latency_tracker_offcpu.ko
	printf "testing"
	for i in $(seq 1 10); do
		printf "."
		sleep 1
	done
	echo ""
	rmmod latency_tracker_wakeup
	rmmod latency_tracker_offcpu
	rmmod latency_tracker
	dmesg -c
}

run default ""
run oldfreelist "-DOLDFREELIST"
run baseht "-DBASEHT"
run urcuht "-DURCUHT"
run "baseht + oldlist" "-DBASEHT -DOLDFREELIST"
run "urcuht + oldlist" "-DURCUHT -DOLDFREELIST"
run "baseht + ll" "-DBASEHT -DLLFREELIST"
run "urcuht + ll" "-DURCUHT -DLLFREELIST"

