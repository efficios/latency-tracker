/* subsystem name is "latency_tracker" */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM latency_tracker

#if !defined(_TRACE_LATENCY_TRACKER_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_LATENCY_TRACKER_H

#include <linux/tracepoint.h>

TRACE_EVENT(
	sched_latency,
	/* tracepoint function prototype */
	TP_PROTO(pid_t pid, u64 delay),
	/* arguments for this tracepoint */
	TP_ARGS(pid, delay),
	/* LTTng doesn't need those */
	TP_STRUCT__entry(
		__field(int, pid)
		__field(u64, delay)
	),
	TP_fast_assign(
		entry->pid = pid;
		entry->delay = delay;
	),
	TP_printk("pid=%d, delay=%llu", __entry->pid, __entry->delay)
   );

#endif /* _TRACE_LATENCY_TRACKER_H */

/* this part must be outside protection */
#include <trace/define_trace.h>
