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
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

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

SEC("tp_btf/sched_process_exec")
int BPF_PROG(obs_procs, struct task_struct* p, pid_t old_pid, struct linux_binprm* bprm) {
	struct event* e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_EXEC;
	e->pid = BPF_CORE_READ(p, tgid);
	e->tid = BPF_CORE_READ(p, pid);
	e->ppid = BPF_CORE_READ(p, real_parent, tgid);

	bpf_core_read_str(e->comm, sizeof(e->comm), &p->comm);

	bpf_printk("EXEC pid=%u old_tid=%d comm=%s", e->pid, old_pid, e->comm);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(obs_forks, struct task_struct* p, struct task_struct* c) {
	struct event* e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_FORK;
	e->pid = BPF_CORE_READ(c, tgid);
	e->tid = BPF_CORE_READ(c, pid);
	e->ppid = BPF_CORE_READ(p, tgid);

	bpf_core_read_str(e->comm, sizeof(e->comm), &c->comm);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
