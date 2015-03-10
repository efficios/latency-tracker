#!/bin/bash

set -e

dmesg -c >/dev/null
make clean

run() {
	name=$1
	flags=$2
	echo $name
	make EXTCFLAGS="$flags"
	insmod tracker.ko
	insmod wakeup_latency.ko
	insmod offcpu.ko
	echo -n "testing"
	for i in $(seq 1 10); do
		echo -n "."
		sleep 1
	done
	echo ""
	rmmod wakeup_latency
	rmmod offcpu
	rmmod tracker
	dmesg -c
}

run default ""
run baseht "-DBASEHT"
run rhashtable "-DRHASHTABLE"
run rhashtable "-DURCUHT"
run "baseht + ll" "-DBASEHT -DLLFREELIST"
run "rhashtable + ll" "-DRHASHTABLE -DLLFREELIST"
run "urcuht + ll" "-DURCUHT -DLLFREELIST"

