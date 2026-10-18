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

struct sched_process_fork_ctx {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;

	char parent_comm[16];
	__s32 parent_pid;

	char child_comm[16];
	__s32 child_pid;
};

enum event_type {
	EVENT_EXEC = 1,
	EVENT_FORK = 2,
};

struct event {
	__u32 type;
	__u32 pid;
	__u32 tid;
	__u32 ppid;
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
	e->type = EVENT_EXEC;
	e->ppid = 0;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_printk("pid[%u], tid[%u], com: %s", e->pid, e->tid, e->comm);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int obs_forks(struct sched_process_fork_ctx* ctx) {
	struct event* e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_FORK;
	e->pid = ctx->child_pid;
	e->tid = ctx->child_pid;
	e->ppid = ctx->parent_pid;

	bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), ctx->child_comm);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
