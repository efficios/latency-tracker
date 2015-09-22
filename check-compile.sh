#!/bin/bash

set -e

dmesg -c >/dev/null
make clean

run() {
	name=$1
	flags=$2
	echo $name
	make EXTCFLAGS="$flags"
	insmod latency_tracker.ko
	insmod latency_tracker_wakeup.ko
	insmod latency_tracker_offcpu.ko
	echo -n "testing"
	for i in $(seq 1 10); do
		echo -n "."
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

