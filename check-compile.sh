#!/bin/bash

set -e

dmesg -c >/dev/null
make clean

echo "default"
make
insmod tracker.ko
insmod sched_latency.ko
echo -n "testing"
for i in $(seq 1 10); do
	echo -n "."
	sleep 1
done
echo ""
rmmod sched_latency
rmmod tracker
dmesg -c

echo ""
echo "baseht"
make EXTCFLAGS=-DBASEHT
insmod tracker.ko
insmod sched_latency.ko
echo -n "testing"
for i in $(seq 1 10); do
	echo -n "."
	sleep 1
done
echo ""
rmmod sched_latency
rmmod tracker
dmesg -c

echo ""
echo "rhashtable"
make EXTCFLAGS=-DRHASHTABLE
insmod tracker.ko
insmod sched_latency.ko
echo -n "testing"
for i in $(seq 1 10); do
	echo -n "."
	sleep 1
done
echo ""
rmmod sched_latency
rmmod tracker
dmesg -c

echo ""
echo "urcuht"
make EXTCFLAGS=-DURCUHT
insmod tracker.ko
insmod sched_latency.ko
echo -n "testing"
for i in $(seq 1 10); do
	echo -n "."
	sleep 1
done
echo ""
rmmod sched_latency
rmmod tracker
dmesg -c

echo ""
echo "baseht + ll"
make EXTCFLAGS="-DBASEHT -DLLFREELIST"
insmod tracker.ko
insmod sched_latency.ko
echo -n "testing"
for i in $(seq 1 10); do
	echo -n "."
	sleep 1
done
echo ""
rmmod sched_latency
rmmod tracker
dmesg -c

echo ""
echo "rhashtable + ll"
make EXTCFLAGS="-DRHASHTABLE -DLLFREELIST"
insmod tracker.ko
insmod sched_latency.ko
echo -n "testing"
for i in $(seq 1 10); do
	echo -n "."
	sleep 1
done
echo ""
rmmod sched_latency
rmmod tracker
dmesg -c

echo ""
echo "urcuht + ll"
make EXTCFLAGS="-DURCUHT -DLLFREELIST"
insmod tracker.ko
insmod sched_latency.ko
echo -n "testing"
for i in $(seq 1 10); do
	echo -n "."
	sleep 1
done
echo ""
rmmod sched_latency
rmmod tracker
dmesg -c
