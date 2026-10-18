/*
 * Ava Info Conseils
 *
 * Author: Antonin Do Souto
 * Contact: antonindosouto@gmail.com
 *
 * Copyright (c) 2026 Antonin Do Souto
 *
 * SPDX-License-Identifier: MIT
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct event {
	__u32 pid;
	__u32 tid;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int obs_procs() {
	struct event* e;
	__u64 pid_tgid;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

	if (!e)
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();

	e->pid = pid_tgid >> 32;
	e->tid = (__u32)pid_tgid;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_printk("pid[%u], tid[%u], com: %s", e->pid, e->tid, e->comm);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int obs_forks(struct trace_event_raw_sched_process_fork* ctx) {
	bpf_printk("FORK parent=%d child=%d", ctx->parent_pid, ctx->child_pid);
	__u64 pid_tgid;

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
