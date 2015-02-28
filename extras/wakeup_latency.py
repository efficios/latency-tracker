#!/usr/bin/env python3
#
# The MIT License (MIT)
#
# Copyright (C) 2015 - Julien Desfossez <jdesfossez@efficios.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys
import time
import argparse
import operator

NSEC_PER_SEC = 1000000000

try:
    from babeltrace import TraceCollection
except ImportError:
    # quick fix for debian-based distros
    sys.path.append("/usr/local/lib/python%d.%d/site-packages" %
                    (sys.version_info.major, sys.version_info.minor))
    from babeltrace import TraceCollection


class TraceParser:
    def __init__(self, trace):
        self.trace = trace
        self.event_count = {}
        self.target_pid = None
        self.target_cpu = None
        self.target_comm = None
        self.target_delay = None
        self.target_ts = None
        self.current_target_cpu = None
        self.real_wake_up_ts = None
        self.per_cpu_current = {}

    def ns_to_hour_nsec(self, ns):
        d = time.localtime(ns/NSEC_PER_SEC)
        return "%02d:%02d:%02d.%09d" % (d.tm_hour, d.tm_min, d.tm_sec,
                                        ns % NSEC_PER_SEC)

    def first_pass(self):
        # iterate over all the events to find the last wakeup_latency event
        for event in self.trace.events:
            if event.name == "wakeup_latency":
                self.target_cpu = event["cpu_id"]
                self.target_comm = event["comm"]
                self.target_pid = event["pid"]
                self.target_delay = event["delay"]
                self.target_ts = event.timestamp
        print("Processing wakeup_latency: %s (%d) on CPU %d for %d us" %
              (self.target_comm, self.target_pid, self.target_cpu,
               self.target_delay / 1000))
        print("Reading the trace between %s and %s" %
              (self.ns_to_hour_nsec(
                  self.target_ts - self.target_delay - 1000000),
               self.ns_to_hour_nsec(self.target_ts + 1000000)))

    def parse(self):
        # iterate over all the events
        for event in self.trace.events_timestamps(
                self.target_ts - self.target_delay - 1000000,
                self.target_ts + 1000000):
            if not event.name in self.event_count.keys():
                self.event_count[event.name] = 0
            method_name = "handle_%s" % \
                event.name.replace(":", "_").replace("+", "_")
            self.event_count[event.name] += 1
            # call the function to handle each event individually
            if hasattr(TraceParser, method_name):
                func = getattr(TraceParser, method_name)
                ret = func(self, event)
                if ret:
                    break

    def print_events(self):
        # print statistics after parsing the trace
        sorted_e = sorted(self.event_count.items(),
                          key=operator.itemgetter(1),
                          reverse=True)
        for e in sorted_e:
            name = e[0]
            if name.startswith("syscall_exit_"):
                continue
            elif name.startswith("syscall_entry_"):
                name = name.replace("syscall_entry_", "sys_")

            print(" "*20, "- %s: %d" % (name, e[1]))
        self.event_count = {}

    def handle_sched_switch(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        prev_comm = event["prev_comm"]
        prev_tid = event["prev_tid"]
        #prev_prio = event["prev_prio"]
        #prev_state = event["prev_state"]
        next_comm = event["next_comm"]
        next_tid = event["next_tid"]
        #next_prio = event["next_prio"]
        if self.real_wake_up_ts is not None and \
                cpu_id == self.current_target_cpu:
            if cpu_id in self.per_cpu_current.keys():
                delta = (timestamp - self.per_cpu_current[cpu_id][2]) / 1000
            else:
                delta = "?"
            print("[%s] sched_switch on cpu %d from %s (%d) to %s (%d), ran "
                  "for %s us, events:" %
                  (self.ns_to_hour_nsec(timestamp), cpu_id, prev_comm,
                   prev_tid, next_comm, next_tid, delta))
            self.print_events()
            if next_tid == self.target_pid:
                return True
        self.per_cpu_current[cpu_id] = (next_comm, next_tid, timestamp)

    def handle_sched_wakeup(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        comm = event["comm"]
        tid = event["tid"]
        #prio = event["prio"]
        #success = event["success"]
        target_cpu = event["target_cpu"]
        if tid == self.target_pid:
            if cpu_id in self.per_cpu_current.keys():
                current_comm = self.per_cpu_current[cpu_id][0]
                current_tid = self.per_cpu_current[cpu_id][1]
                delta = (timestamp - self.per_cpu_current[cpu_id][2]) / 1000
            else:
                current_comm = "?"
                current_tid = "?"
                delta = "?"
            print("[%s] Woke up %s (%d) on target CPU %d, currently "
                  "running %s (%d) since %s us" %
                  (self.ns_to_hour_nsec(timestamp), comm, tid, target_cpu,
                   current_comm, current_tid, delta))
            self.real_wake_up_ts = timestamp
            self.current_target_cpu = cpu_id

    def handle_sched_migrate_task(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        #comm = event["comm"]
        tid = event["tid"]
        #prio = event["prio"]
        #orig_cpu = event["orig_cpu"]
        dest_cpu = event["dest_cpu"]
        if tid == self.target_pid and self.real_wake_up_ts is not None:
            if cpu_id in self.per_cpu_current.keys():
                current_comm = self.per_cpu_current[cpu_id][0]
                current_tid = self.per_cpu_current[cpu_id][1]
                delta = (timestamp - self.per_cpu_current[cpu_id][2]) / 1000
            else:
                current_comm = "?"
                current_tid = "?"
                delta = "?"
            print("[%s] Migrated to CPU %d, currently running %s (%d) "
                  "since %s us" %
                  (self.ns_to_hour_nsec(timestamp), dest_cpu, current_comm,
                   current_tid, delta))
            self.current_target_cpu = cpu_id


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Trace parser')
    parser.add_argument('path', metavar="<path/to/trace>", help='Trace path')
    args = parser.parse_args()

    traces = TraceCollection()
    handle = traces.add_traces_recursive(args.path, "ctf")
    if handle is None:
        sys.exit(1)

    t = TraceParser(traces)
    t.first_pass()
    t.parse()

    for h in handle.values():
        traces.remove_trace(h)
