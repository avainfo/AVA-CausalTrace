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

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "agent.h"
#include "events.h"

int add_process(Process* processes, Process p) {
	if (!processes || p.pid == 0)
		return 0;

	Process* free_slot = NULL;
	for (size_t i = 0; i < HISTORIC_SIZE; i++) {
		if (processes[i].pid == p.pid && processes[i].tid == p.tid) {
			ExecRecord* eh = malloc(sizeof(*eh));
			if (!eh)
				return 0;

			eh->previous = processes[i].exec_history;

			memcpy(eh->comm, processes[i].comm, sizeof(eh->comm));

			p.exec_history = eh;

			processes[i] = p;
			return 1;
		}
		if (!free_slot && processes[i].pid == 0)
			free_slot = &processes[i];
	}

	if (!free_slot)
		return 0;

	*free_slot = p;
	return 1;
}

Process* search_process(Process* processes, __u32 target_pid, __u32 target_tid) {
	if (!processes || target_pid == 0 || target_tid == 0)
		return NULL;

	for (size_t i = 0; i < HISTORIC_SIZE; i++) {
		if (processes[i].pid == target_pid && processes[i].tid == target_tid) {
			return &processes[i];
		}
	}
	return NULL;
}

void show_processes(Process* processes) {
	if (!processes)
		return;
	for (int i = 0; i < HISTORIC_SIZE; i++) {
		if (processes[i].pid != 0) {
			printf("Process: %s [%d][%d]\n", processes[i].comm, processes[i].pid, processes[i].tid);
			ExecRecord* eh = processes[i].exec_history;
			int j = 0;
			while (eh && j < 10) {
				printf("  - %s | current=%p | previous=%p\n", eh->comm, (void*)eh, (void*)eh->previous);

				eh = eh->previous;
				j++;
			}
			printf("\n");
		}
	}
}

int ensure_parent(Process* processes, struct event* e) {
	if (!processes || !e || e->ppid == 0 || e->ptid == 0)
		return 0;

	for (size_t i = 0; i < HISTORIC_SIZE; i++) {
		if (processes[i].pid == e->ppid && processes[i].tid == e->ptid)
			return 1;
	}

	Process parent = {
	    .pid = e->ppid,
	    .tid = e->ptid,
	    .ppid = 0,
	    .ptid = 0,
	    .exec_history = NULL,
	};

	memcpy(parent.comm, e->comm, sizeof(parent.comm));

	return add_process(processes, parent);
}

// TODO: Make the kill process and free all the exec_history
