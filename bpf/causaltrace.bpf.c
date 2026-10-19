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

#include "events.h"

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

	e->pid = BPF_CORE_READ(p, tgid);
	e->tid = BPF_CORE_READ(p, pid);
	e->ppid = BPF_CORE_READ(p, real_parent, tgid);
	e->ptid = BPF_CORE_READ(p, real_parent, pid);
	e->type = EVENT_EXEC;

	bpf_core_read_str(e->comm, sizeof(e->comm), &p->comm);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(obs_forks, struct task_struct* p, struct task_struct* c) {
	struct event* e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = BPF_CORE_READ(c, tgid);
	e->tid = BPF_CORE_READ(c, pid);
	e->ppid = BPF_CORE_READ(p, tgid);
	e->ptid = BPF_CORE_READ(p, pid);
	e->type = e->tid == e->pid ? EVENT_FORK : EVENT_THREAD;

	bpf_core_read_str(e->comm, sizeof(e->comm), &c->comm);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
