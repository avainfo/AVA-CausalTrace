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
#include "formating.h"

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
			p.parent = processes[i].parent;

			processes[i] = p;
			return 1;
		}
		if (processes[i].pid == p.ppid && processes[i].tid == p.ptid) {
			Process* parent = malloc(sizeof(*parent));
			if (!parent)
				return 0;
			*parent = processes[i];
			p.parent = parent;
			processes[i] = p;
			return 1;
		}
		if (!free_slot && processes[i].pid == 0)
			free_slot = &processes[i];
	}

	if (!free_slot)
		return 0;

	Process parent_target = {
	    .pid = p.ppid,
	    .tid = p.ptid,
	};

	p.parent = search_process(processes, parent_target);

	*free_slot = p;
	return 1;
}

Process* search_process(Process* processes, Process p) {
	if (!processes || p.pid == 0 || p.tid == 0)
		return NULL;

	for (size_t i = 0; i < HISTORIC_SIZE; i++) {
		if (processes[i].pid == p.pid && processes[i].tid == p.tid) {
			return &processes[i];
		}
		Process* parent = processes[i].parent;
		while (parent != NULL) {
			if (parent->pid == p.pid && parent->tid == p.tid) {
				return parent;
			}
			parent = parent->parent;
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
			printf("  status: %s", processes[i].status == 0   ? "UNKOWN"
			                       : processes[i].status == 1 ? "RUNNING"
			                                                  : "EXITED");
			ExecRecord* eh = processes[i].exec_history;
			while (eh) {
				printf(" -> %s", eh->comm);
				eh = eh->previous;
			}
			printf("\n");
			Process* parent = processes[i].parent;
			int j = 2;
			while (parent) {
				for (int k = 0; k < j; k++) {
					putchar(' ');
				}
				printf("%s%s [%d]", CHILD_CHARS, parent->comm, parent->parent == NULL);
				ExecRecord* eh = parent->exec_history;
				while (eh) {
					printf(" -> %s", eh->comm);
					eh = eh->previous;
				}
				printf("\n");
				parent = parent->parent;
				j += 2;
			}
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
	    .ppid = -1,
	    .ptid = -1,
	    .exec_history = NULL,
	    .status = STATUS_RUNNING,
	};

	memcpy(parent.comm, e->comm, sizeof(parent.comm));

	return add_process(processes, parent);
}

int exit_process(Process* processes, Process p) {
	if (!processes || p.pid == 0 || p.tid == 0 || p.ppid == 0 || p.ptid == 0)
		return 0;

	Process* target = search_process(processes, p);
	if (!target)
		return 0;

	target->status = STATUS_EXITED;

	return 1;
}

void free_processes(Process* processes) {
	for (int i = 0; i < HISTORIC_SIZE; i++) {
		if (processes[i].pid == 0)
			continue;
		ExecRecord* eh = processes[i].exec_history;
		while (eh) {
			ExecRecord* next = eh->previous;
			free(eh);
			eh = next;
		}
		processes[i].exec_history = NULL;
	}
}
