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

#include <bpf/bpf_helpers.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "agent.h"
#include "events.h"

int is_referenced(Process* processes, Process* p) {
	if (!processes || p->pid == 0 || p->tid == 0)
		return 0;

	for (size_t i = 0; i < HISTORIC_SIZE; i++) {
		if (processes[i].pid != 0 && processes[i].parent == p)
			return 1;
	}
	return 0;
}

int count_exec_record(Process* p) {
	int i = 0;
	ExecRecord* eh = p->exec_history;
	while (eh != NULL) {
		i++;
		eh = eh->previous;
	}
	return i;
}

int pop_exec_record(Process* p) {
	if (count_exec_record(p) <= 1)
		return 0;
	ExecRecord* eh = p->exec_history;
	while (eh->previous->previous) {
		eh = eh->previous;
	}
	p->popped_er += 1;
	free(eh->previous);
	eh->previous = NULL;
	return 1;
}

int add_process(Process* processes, Process p) {
	if (!processes || p.pid == 0)
		return 0;

	Process* free_slot = NULL;
	for (size_t i = 0; i < HISTORIC_SIZE; i++) {
		if (processes[i].pid == p.pid && processes[i].tid == p.tid && processes[i].start_time_ns == p.start_time_ns) {
			ExecRecord* eh = malloc(sizeof(*eh));
			if (!eh)
				return 0;

			if (count_exec_record(&processes[i]) >= EXEC_RECORD_SIZE)
				pop_exec_record(&processes[i]);

			eh->previous = processes[i].exec_history;
			eh->timestamp_ns = processes[i].timestamp_ns;

			memcpy(eh->comm, processes[i].comm, sizeof(eh->comm));

			p.exec_history = eh;
			p.parent = processes[i].parent;
			p.popped_er = processes[i].popped_er;

			processes[i] = p;
			return 1;
		}

		if (!free_slot && processes[i].pid == 0 && processes[i].tid == 0)
			free_slot = &processes[i];
	}

	if (!free_slot) {
		if (evict_process(processes)) {
			return add_process(processes, p);
		}
		return 0;
	}

	Process parent_target = {
	    .pid = p.ppid,
	    .tid = p.ptid,
	    .start_time_ns = p.parent_start_time_ns,
	};

	p.parent = search_process(processes, parent_target);

	*free_slot = p;
	return 1;
}

Process* search_process(Process* processes, Process p) {
	if (!processes || p.pid == 0 || p.tid == 0)
		return NULL;

	for (size_t i = 0; i < HISTORIC_SIZE; i++) {
		if (processes[i].pid == p.pid && processes[i].tid == p.tid && processes[i].start_time_ns == p.start_time_ns) {
			return &processes[i];
		}
		Process* parent = processes[i].parent;
		while (parent != NULL) {
			if (parent->pid == p.pid && parent->tid == p.tid && parent->start_time_ns == p.start_time_ns) {
				return parent;
			}
			parent = parent->parent;
		}
	}
	return NULL;
}

int ensure_parent(Process* processes, struct event* e) {
	if (!processes || !e || e->ppid == 0 || e->ptid == 0)
		return 0;

	for (size_t i = 0; i < HISTORIC_SIZE; i++) {
		if (processes[i].pid == e->ppid && processes[i].tid == e->ptid &&
		    processes[i].start_time_ns == e->p_start_time_ns)
			return 1;
	}

	Process parent = {
	    .pid = e->ppid,
	    .tid = e->ptid,
	    .ppid = 0,
	    .ptid = 0,
	    .start_time_ns = e->p_start_time_ns,
	    .parent_start_time_ns = 0,
	    .exec_history = NULL,
	    .parent = NULL,
	    .status = STATUS_RUNNING,
	};

	memcpy(parent.comm, e->comm, sizeof(parent.comm));

	return add_process(processes, parent);
}

int exit_process(Process* processes, Process p) {
	if (!processes || p.pid == 0 || p.tid == 0)
		return 0;

	Process* target = search_process(processes, p);
	if (!target)
		return 0;

	target->status = STATUS_EXITED;

	return 1;
}

int evict_process(Process* processes) {
	// If the proc is RUNNING, it remains conserved.
	// If the proc is EXITED, it becomes a candidate for eviction.
	// If the proc is a parent, it remains conserved.
	// If a proc is evicted, we need to free all ExecRecords.
	Process* candidate = NULL;
	for (int i = 0; i < HISTORIC_SIZE; i++) {
		if (processes[i].status == STATUS_EXITED && !is_referenced(processes, &processes[i])) {
			candidate = &processes[i];
			break;
		}
	}

	if (candidate) {
		ExecRecord* eh = candidate->exec_history;
		while (eh) {
			ExecRecord* old_eh = eh;
			eh = eh->previous;
			free(old_eh);
		}
		memset(candidate, 0, sizeof(*candidate));
		return 1;
	}
	return 0;
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
