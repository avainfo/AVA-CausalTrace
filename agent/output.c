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

#include "output.h"
#include "agent.h"
#include "events.h"

#include <asm-generic/errno-base.h>
#include <bpf/libbpf.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char* const event_type_title[] = {
    "EVENT_EXEC_TITLE",   "EVENT_FORK_TITLE",   "EVENT_EXIT_TITLE",
    "EVENT_THREAD_TITLE", "OPENAT_ENTER_TITLE", "OPENAT_EXIT_TITLE",
};

void spacer(const int j) {
	for (int i = 0; i < j; i++)
		putchar(' ');
}

void print_title(char* title) {
	int title_len = strlen(title);

	printf("\n%s", BOX_TL);
	for (int i = 0; i < title_len + 2; i++) {
		printf("%s", BOX_H);
	}
	printf("%s\n%s %s %s\n%s", BOX_TR, BOX_V, title, BOX_V, BOX_BL);
	for (int i = 0; i < title_len + 2; i++) {
		printf("%s", BOX_H);
	}
	printf("%s\n", BOX_BR);
}

void print_parent(Process* p) {
	int j = 2;
	while (p) {
		spacer(j);
		printf("%s%s [%d][%d] (%llu)", CHILD_CHARS, p->comm, p->pid, p->tid, p->timestamp_ns);

		ExecRecord* eh = p->exec_history;
		while (eh) {
			printf(" -> %s", eh->comm);
			eh = eh->previous;
		}
		printf("\n");

		p = p->parent;
		j += 2;
	}
}

void print_process(Process* p) {
	printf("Process: %s [%d][%d] (%llu)", p->comm, p->pid, p->tid, p->timestamp_ns);

	ExecRecord* eh = p->exec_history;
	while (eh) {
		printf(" <- %s", eh->comm);
		eh = eh->previous;
	}
	printf("\n");

	int status = p->status;
	char* status_str = status == 0 ? "UNKOWN" : status == 1 ? "RUNNING" : "EXITED";
	printf("  status: %s\n", status_str);

	printf("  popped historic: %u\n", p->popped_er);
	printf("  start: %llu\n", (unsigned long long)p->start_time_ns);

	printf("  current: %llu\n", (unsigned long long)p->timestamp_ns);

	printf("  exit: %llu\n", (unsigned long long)p->exit_time_ns);

	print_parent(p->parent);
}

void show_processes(Process* processes) {
	if (!processes)
		return;

	print_title("Processes");
	int empty = 1;
	for (int i = 0; i < HISTORIC_SIZE; i++) {
		if (processes[i].pid != 0) {
			if (empty)
				empty = 0;
			print_process(&processes[i]);
		}
	}
	if (empty)
		printf("None\n");
}

void show_statistics(struct bpf_object* obj) {
	struct bpf_map* map = bpf_object__find_map_by_name(obj, "ringbuf_drops");
	if (!map) {
		fprintf(stderr, "BPF map not found: ringbuf_drops\n");
		return;
	}

	int ncpus = libbpf_num_possible_cpus();
	if (ncpus < 0) {
		fprintf(stderr, "Failed to get possible CPU count: %d\n", ncpus);
		return;
	}

	__u64* values = calloc((size_t)ncpus, sizeof(*values));
	if (!values) {
		perror("calloc");
		return;
	}

	print_title("Ava CausalTrace statistics");
	printf("Ring buffer drops:\n");

	__u64 total = 0;
	for (__u32 i = 1; i < EVENT_COUNT; i++) {
		spacer(2);

		const char* title = event_type_title[i - 1];

		int err = bpf_map__lookup_elem(map, &i, sizeof(i), values, ncpus * sizeof(*values), 0);
		if (err) {
			fprintf(stderr, "Lookup failed for %s: %d\n", title, err);
			continue;
		}

		__u64 count = 0;
		for (int cpu = 0; cpu < ncpus; cpu++)
			count += values[cpu];

		total += count;
		printf("%s%s:\t%llu\n", CHILD_CHARS, title, count);
	}
	spacer(2);
	printf("%sTotal:\t\t%llu\n", CHILD_CHARS, total);
	free(values);
}
