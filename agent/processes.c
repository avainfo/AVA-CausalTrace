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

Process* search_process(Process* processes, Process p) {
	if (!processes || p.pid == 0 || p.tid == 0 || p.ppid == 0 || p.ptid == 0)
		return NULL;

	for (size_t i = 0; i < HISTORIC_SIZE; i++) {
		if (processes[i].pid == p.pid && processes[i].tid == p.tid && processes[i].tid == p.ppid &&
		    processes[i].tid == p.ptid) {
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

int kill_process(Process* processes, Process p) {
	if (!processes || p.pid == 0 || p.tid == 0 || p.ppid == 0 || p.ptid == 0)
		return 0;

	Process* target = search_process(processes, p);
	if (!target)
		return 0;

	return 1;
}

void free_processes(Process* processes) {
	for (int i = 0; i < HISTORIC_SIZE; i++) {
		if (processes[i].pid == 0)
			continue;
		ExecRecord* eh = processes[i].exec_history;
		free_exec_history(eh);
	}
}

void free_exec_history(ExecRecord* eh) {
	if (!eh)
		return;

	free_exec_history(eh->previous);
	free(eh);
}
