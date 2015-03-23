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
run baseht "-DBASEHT"
run rhashtable "-DRHASHTABLE"
run rhashtable "-DURCUHT"
run "baseht + ll" "-DBASEHT -DLLFREELIST"
run "rhashtable + ll" "-DRHASHTABLE -DLLFREELIST"
run "urcuht + ll" "-DURCUHT -DLLFREELIST"

