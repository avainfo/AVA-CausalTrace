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

#include <bpf/libbpf.h>
#include <stddef.h>
#include <stdio.h>

#include "events.h"

int callback(void* ctx, void* data, size_t size) {
	(void)ctx;

	if (size < sizeof(struct event))
		return 0;

	struct event* e = data;

	switch (e->type) {
	case EVENT_EXEC:
		printf("EXEC pid=%u comm=%s\n", e->pid, e->comm);
		break;
	case EVENT_FORK:
		printf("FORK parent=%u child=%u comm=%s\n", e->ppid, e->pid, e->comm);
		break;
	case EVENT_EXIT:
		printf("EXIT pid=%u tid=%u comm=%s\n", e->pid, e->tid, e->comm);
		break;
	case EVENT_THREAD:
		printf("THREAD tgid=%u tid=%u creator_tid=%u comm=%s\n", e->pid, e->tid, e->ptid, e->comm);
		break;
	}

	return 0;
}

int main(int argc, char* argv[]) {
	(void)argc;
	(void)argv;
	struct bpf_object* obj;

	obj = bpf_object__open_file("bin/causaltrace.bpf.o", NULL);
	if (!obj) {
		bpf_object__close(obj);
		return 1;
	}

	int obj_loaded = bpf_object__load(obj);
	if (obj_loaded != 0) {
		bpf_object__close(obj);
		return 1;
	}

	struct bpf_map* map = bpf_object__find_map_by_name(obj, "events");
	if (!map) {
		bpf_object__close(obj);
		return 1;
	}

	int map_fd = bpf_map__fd(map);
	if (map_fd < 0) {
		bpf_object__close(obj);
		return 1;
	}

	struct bpf_program* exec_prog = bpf_object__find_program_by_name(obj, "obs_execs");
	struct bpf_program* fork_prog = bpf_object__find_program_by_name(obj, "obs_forks");
	struct bpf_program* exit_prog = bpf_object__find_program_by_name(obj, "obs_exits");
	if (!exec_prog || !fork_prog || !exit_prog) {
		fprintf(stderr, "Cannot find BPF programs\n");
		bpf_object__close(obj);
		return 1;
	}

	struct bpf_link* exec_link = bpf_program__attach(exec_prog);
	struct bpf_link* fork_link = bpf_program__attach(fork_prog);
	struct bpf_link* exit_link = bpf_program__attach(exit_prog);
	if (!exec_link || !fork_link|| !exit_link) {
		fprintf(stderr, "Cannot attach BPF programs\n");

		if (exec_link)
			bpf_link__destroy(exec_link);

		if (fork_link)
			bpf_link__destroy(fork_link);

		if (exit_link)
			bpf_link__destroy(exit_link);

		bpf_object__close(obj);
		return 1;
	}

	struct ring_buffer* rb = ring_buffer__new(map_fd, callback, NULL, NULL);
	if (!rb) {
		bpf_link__destroy(exec_link);
		bpf_link__destroy(fork_link);
		bpf_link__destroy(exit_link);
		bpf_object__close(obj);
		return 1;
	}

	int loop = 1;
	while (loop) {
		int err = ring_buffer__poll(rb, 200);
		if (err < 0) {
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	}

	ring_buffer__free(rb);
	bpf_link__destroy(exec_link);
	bpf_link__destroy(fork_link);
	bpf_link__destroy(exit_link);
	bpf_object__close(obj);

	printf("SUCCEEDED");
	return 0;
}
