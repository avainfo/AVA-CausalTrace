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
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "agent.h"
#include "events.h"
#include "signals.h"

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

void agent_destroy(Agent* agent) {
	for (size_t i = 0; i < PROGRAM_COUNT; i++)
		bpf_link__destroy(agent->links[i]);

	ring_buffer__free(agent->rb);
	free(agent->processes);
	bpf_object__close(agent->obj);
}

int agent_attach(Agent* agent) {
	for (size_t i = 0; i < PROGRAM_COUNT; i++) {
		const char* name = program_names[i];

		struct bpf_program* prog = bpf_object__find_program_by_name(agent->obj, name);
		if (!prog) {
			fprintf(stderr, "BPF program not found: %s\n", name);
			return -ENOENT;
		}

		agent->links[i] = bpf_program__attach(prog);
		if (!agent->links[i]) {
			int err = errno;
			fprintf(stderr, "Cannot attach %s: %s\n", name, strerror(err));
			return -err;
		}
	}

	return 0;
}

int agent_init(Agent* agent) {
	agent->obj = bpf_object__open_file("bin/causaltrace.bpf.o", NULL);
	if (!agent->obj) {
		perror("bpf_object__open_file");
		return -1;
	}

	int err = bpf_object__load(agent->obj);
	if (err) {
		fprintf(stderr, "BPF load: %s\n", strerror(-err));
		return err;
	}

	struct bpf_map* map = bpf_object__find_map_by_name(agent->obj, "events");
	if (!map) {
		fprintf(stderr, "BPF map not found: events\n");
		return -ENOENT;
	}

	int map_fd = bpf_map__fd(map);
	if (map_fd < 0) {
		fprintf(stderr, "Map FD: %s\n", strerror(-map_fd));
		return map_fd;
	}

	agent->processes = calloc(HISTORIC_SIZE, sizeof(*agent->processes));
	if (!agent->processes) {
		perror("calloc");
		return -ENOMEM;
	}

	agent->rb = ring_buffer__new(map_fd, callback, agent->processes, NULL);
	if (!agent->rb) {
		perror("ring_buffer__new");
		return -1;
	}

	return agent_attach(agent);
}

int agent_run(Agent* agent) {
	while (signals_running()) {
		int err = ring_buffer__poll(agent->rb, 200);
		if (err == -EINTR) {
			if (!signals_running())
				break;
			continue;
		}

		if (err < 0) {
			fprintf(stderr, "Ring buffer poll: %s\n", strerror(-err));
			return err;
		}
	}

	return 0;
}
