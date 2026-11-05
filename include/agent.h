/*
 * Ava Info Conseils
 *
 * Author: Antonin Do Souto
 * Contact: antonindosouto@gmail.com
 *
 * Copyright (c) 2026 Antonin Do Souto
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AGENT_H
#define AGENT_H

#include "events.h"
#include <stddef.h>
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define HISTORIC_SIZE 512
#define EXEC_RECORD_SIZE 64

enum status_type {
	STATUS_RUNNING = 1,
	STATUS_EXITED = 2,
};

typedef struct ExecRecord {
	char comm[16];

	__u64 timestamp_ns;

	struct ExecRecord* previous;
} ExecRecord;

typedef struct Process {
	char comm[16];

	__u32 pid;
	__u32 tid;
	__u32 ppid;
	__u32 ptid;

	__u64 start_time_ns;
	__u64 parent_start_time_ns;

	__u64 timestamp_ns;

	__u64 exit_time_ns;

	__u32 status;

	struct Process* parent;
	struct ExecRecord* exec_history;

	__u32 popped_er;
	__u32 failed_add;
} Process;

enum {
	PROGRAM_EXEC,
	PROGRAM_FORK,
	PROGRAM_EXIT,
	PROGRAM_COUNT,
};

typedef struct {
	struct bpf_object* obj;
	struct bpf_link* links[PROGRAM_COUNT];
	struct ring_buffer* rb;
	Process* processes;
} Agent;

void agent_destroy(Agent* agent);
int agent_attach(Agent* agent);
int agent_init(Agent* agent);
int agent_run(Agent* agent);

int is_referenced(Process* processes, Process* p);
int add_process(Process* processes, Process p);
Process* search_process(Process* processes, Process p);
int ensure_parent(Process* processes, struct event* e);
int exit_process(Process* processes, Process p);
int evict_process(Process* processes);
void free_processes(Process* processes);

#endif // AGENT_H
