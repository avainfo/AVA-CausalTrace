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

#include <asm-generic/errno-base.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "agent.h"
#include "events.h"

static volatile sig_atomic_t running = 1;

static void handle_signal(int sig) {
	(void)sig;
	running = 0;
}

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

	struct bpf_object* obj = NULL;

	struct bpf_link* exec_link = NULL;
	struct bpf_link* fork_link = NULL;
	struct bpf_link* exit_link = NULL;

	struct ring_buffer* rb = NULL;

	struct Process* processes = NULL;

	struct bpf_map* map;

	struct bpf_program *exec_prog, *fork_prog, *exit_prog;

	int status = EXIT_FAILURE;
	int err;

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	obj = bpf_object__open_file("bin/causaltrace.bpf.o", NULL);
	if (!obj) {
		perror("bpf_object__open_file");
		goto cleanup;
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "BPF load: %s\n", strerror(-err));
		goto cleanup;
	}

	map = bpf_object__find_map_by_name(obj, "events");
	if (!map)
		goto cleanup;

	int map_fd = bpf_map__fd(map);
	if (map_fd < 0)
		goto cleanup;

	exec_prog = bpf_object__find_program_by_name(obj, "obs_execs");
	fork_prog = bpf_object__find_program_by_name(obj, "obs_forks");
	exit_prog = bpf_object__find_program_by_name(obj, "obs_exits");
	if (!exec_prog || !fork_prog || !exit_prog) {
		fprintf(stderr, "Cannot find BPF programs\n");
		goto cleanup;
	}

	exec_link = bpf_program__attach(exec_prog);
	if (!exec_link) {
		perror("attach obs_execs");
		goto cleanup;
	}

	fork_link = bpf_program__attach(fork_prog);
	if (!fork_link) {
		perror("attach obs_forks");
		goto cleanup;
	}

	exit_link = bpf_program__attach(exit_prog);
	if (!exit_link) {
		perror("attach obs_exits");
		goto cleanup;
	}

	processes = calloc(HISTORIC_SIZE, sizeof *processes);
	if (!processes) {
		perror("calloc");
		goto cleanup;
	}

	rb = ring_buffer__new(map_fd, callback, processes, NULL);
	if (!rb) {
		perror("ring_buffer__new");
		goto cleanup;
	}

	while (running) {
		err = ring_buffer__poll(rb, 200);

		if (err == -EINTR && !running)
			break;

		if (err < 0) {
			fprintf(stderr, "Ring buffer poll: %d\n", err);
			goto cleanup;
		}
	}

	status = EXIT_SUCCESS;

cleanup:
	ring_buffer__free(rb);
	free(processes);

	bpf_link__destroy(exit_link);
	bpf_link__destroy(fork_link);
	bpf_link__destroy(exec_link);

	bpf_object__close(obj);

	return status;
}
