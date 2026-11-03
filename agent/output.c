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

#include <asm-generic/errno-base.h>
#include <bpf/libbpf.h>
#include <stddef.h>
#include <stdio.h>

void spacer(const int j) {
	for (int i = 0; i < j; i++)
		putchar(' ');
}

void show_processes(Process* processes) {
	if (!processes)
		return;

	for (int i = 0; i < HISTORIC_SIZE; i++) {
		if (processes[i].pid != 0) {
			printf("Process: %s [%d][%d]", processes[i].comm, processes[i].pid, processes[i].tid);

			ExecRecord* eh = processes[i].exec_history;
			while (eh) {
				printf(" <- %s", eh->comm);
				eh = eh->previous;
			}
			printf("\n");

			int status = processes[i].status;
			char* status_str = status == 0 ? "UNKOWN" : status == 1 ? "RUNNING" : "EXITED";
			printf("  status: %s\n", status_str);

			Process* parent = processes[i].parent;
			int j = 2;
			while (parent) {
				spacer(j);
				printf("%s%s [%d][%d]", CHILD_CHARS, parent->comm, parent->pid, parent->tid);

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

void show_statistics(struct bpf_object* obj) {
	printf("Ava CausalTrace statistics\n");
	printf("  Ring buffer drops:\n");

	struct bpf_map* map = bpf_object__find_map_by_name(obj, "ringbuf_drops");
	size_t value_size = libbpf_num_possible_cpus() * sizeof(__u64);
	if (!map) {
		fprintf(stderr, "BPF map not found: ringbuf_drops\n");
		return;
	}

	int total = 0;
	for (__u64 i = 1; i <= 4; i++) {
		spacer(4);

		char* title = i == 1 ? "EXEC" : i == 2 ? "FORK" : i == 3 ? "EXIT" : "THREAD";

		__u64* value = NULL;

		bpf_map__lookup_elem(map, &i, sizeof(__u32), value, value_size, 0);
		total += value ? *value : 0;

		printf("%s:\t%llu\n", title, value ? *value : 0);
	}
	spacer(4);
	printf("Total:\t%u\n", total);
}
