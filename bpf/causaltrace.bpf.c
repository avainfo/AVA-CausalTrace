/*
 * Ava Info Conseils
 *
 * Author: Antonin Do Souto
 * Contact: antonindosouto@gmail.com
 *
 * Copyright (c) 2026 Antonin Do Souto
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "events.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, EVENT_THREAD + 1);
	__type(key, __u32);
	__type(value, __u64);
} ringbuf_drops SEC(".maps");

static __always_inline void count_drop(__u32 type) {
	__u64* count = bpf_map_lookup_elem(&ringbuf_drops, &type);

	if (count)
		(*count)++;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(obs_execs, struct task_struct* p, pid_t old_pid, struct linux_binprm* bprm) {
	(void)old_pid;
	(void)bprm;

	struct event* e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop(EVENT_EXEC);
		return 0;
	}

	e->pid = BPF_CORE_READ(p, tgid);
	e->tid = BPF_CORE_READ(p, pid);
	e->ppid = BPF_CORE_READ(p, real_parent, tgid);
	e->ptid = BPF_CORE_READ(p, real_parent, pid);
	e->start_time_ns = BPF_CORE_READ(p, start_time);
	e->p_start_time_ns = BPF_CORE_READ(p, real_parent, start_time);
	e->timestamp_ns = bpf_ktime_get_ns();
	e->type = EVENT_EXEC;

	bpf_core_read_str(e->comm, sizeof(e->comm), &p->comm);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(obs_forks, struct task_struct* p, struct task_struct* c) {
	struct event* e;

	__u32 pid = BPF_CORE_READ(c, tgid);
	__u32 tid = BPF_CORE_READ(c, pid);

	__u32 type = pid == tid ? EVENT_FORK : EVENT_THREAD;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop(type);
		return 0;
	}
	e->pid = pid;
	e->tid = tid;
	e->ppid = BPF_CORE_READ(p, tgid);
	e->ptid = BPF_CORE_READ(p, pid);
	e->start_time_ns = BPF_CORE_READ(c, start_time);
	e->p_start_time_ns = BPF_CORE_READ(p, start_time);
	e->timestamp_ns = bpf_ktime_get_ns();
	e->type = type;

	bpf_core_read_str(e->comm, sizeof(e->comm), &p->comm);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(obs_exits, struct task_struct* p) {
	struct event* e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop(EVENT_EXIT);
		return 0;
	}

	e->pid = BPF_CORE_READ(p, tgid);
	e->tid = BPF_CORE_READ(p, pid);
	e->ppid = BPF_CORE_READ(p, real_parent, tgid);
	e->ptid = BPF_CORE_READ(p, real_parent, pid);
	e->start_time_ns = BPF_CORE_READ(p, start_time);
	e->p_start_time_ns = BPF_CORE_READ(p, real_parent, start_time);
	e->timestamp_ns = bpf_ktime_get_ns();
	e->type = EVENT_EXIT;

	bpf_core_read_str(e->comm, sizeof(e->comm), &p->comm);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
