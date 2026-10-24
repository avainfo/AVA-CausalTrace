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

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define HISTORIC_SIZE 512

enum status_type {
	STATUS_RUNNING = 1,
	STATUS_EXITED = 2,
};

typedef struct Process {
	__u32 pid;
	__u32 tid;
	__u32 ppid;
	__u32 ptid;

	__u32 status;

	struct Process* parent;
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

#endif // AGENT_H
