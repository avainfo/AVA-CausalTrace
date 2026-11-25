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
#include <string.h>

#include "agent.h"
#include "events.h"
#include "output.h"
#include "signals.h"

static const char* const program_names[PROGRAM_COUNT] = {
    [PROGRAM_EXEC] = "obs_execs",
    [PROGRAM_FORK] = "obs_forks",
    [PROGRAM_EXIT] = "obs_exits",
    [PROGRAM_ENTER_OPENAT] = "handle_enter_openat",
    [PROGRAM_EXIT_OPENAT] = "handle_exit_openat",
};

int callback(void* ctx, void* data, size_t size) {
	if (size < sizeof(struct event))
		return 0;

	struct event* e = data;
	Agent* agent = (Agent*)ctx;

	Process* processes = agent->processes;
	OpenAT* open_files = agent->open_files;

	Process p = {
	    .pid = e->pid,
	    .tid = e->tid,
	    .ppid = e->ppid,
	    .ptid = e->ptid,
	    .start_time_ns = e->start_time_ns,
	    .parent_start_time_ns = e->p_start_time_ns,
	    .timestamp_ns = e->timestamp_ns,
	    .exit_time_ns = 0,
	    .exec_history = NULL,
	    .status = 0,
	    .parent = NULL,
	    .popped_er = 0,
	    .failed_add = 0,
	};

	OpenAT file = {
	    .pid = e->pid,
	    .tid = e->tid,
	    .dfd = e->dfd,
	    .timestamp_ns = e->timestamp_ns,
	    .flags = e->flags,
	    .filename = e->fname,
	    .mode = e->mode,
	    .ret = e->open_return,
	};

	memcpy(p.comm, e->comm, sizeof(e->comm));

	switch (e->type) {
	case EVENT_EXEC:
		p.status = STATUS_RUNNING;
		if (add_process(processes, p))
			printf("EXEC pid=%u comm=%s\n", e->pid, e->comm);
		else {
			fprintf(stderr, "Failed to add the EXEC pid=%u comm=%s\n", e->pid, e->comm);
		}
		break;
	case EVENT_FORK:
		p.status = STATUS_RUNNING;
		if (!ensure_parent(processes, e)) {
			fprintf(stderr, "Failed to ensure parent ppid=%u ptid=%u for child pid=%u\n", e->ppid, e->ptid, e->pid);
			break;
		}
		if (add_process(processes, p))
			printf("FORK parent=%u child=%u comm=%s\n", e->ppid, e->pid, e->comm);
		else {
			fprintf(stderr, "Failed to add the FORK parent=%u child=%u comm=%s\n", e->ppid, e->pid, e->comm);
		}
		break;
	case EVENT_EXIT:
		if (!exit_process(processes, p))
			fprintf(stderr, "EXIT: task not found pid=%u tid=%u\n", e->pid, e->tid);
		printf("EXIT pid=%u comm=%s\n", e->pid, e->comm);
		break;
	case EVENT_THREAD:
		p.status = STATUS_RUNNING;
		if (add_process(processes, p))
			printf("THREAD tgid=%u tid=%u creator_tid=%u comm=%s\n", e->pid, e->tid, e->ptid, e->comm);
		else {
			fprintf(stderr, "Failed to add the THREAD tgid=%u tid=%u creator_tid=%u comm=%s\n", e->pid, e->tid, e->ptid,
			        e->comm);
		}
		break;
	case OPENAT_ENTER:
		// printf("EXIT OPENAT pid=%i ret=%lli\n", e->pid, e->open_return);
		// TODO : check for ENTER OPENAT
		add_open_file(open_files, file);
		break;
	case OPENAT_EXIT:
		exit_open_file(open_files, file, e->open_return);
		break;
	}

	return 0;
}

void agent_destroy(Agent* agent) {
	if (!agent)
		return;

	for (size_t i = 0; i < PROGRAM_COUNT; i++) {
		if (agent->links[i]) {
			bpf_link__destroy(agent->links[i]);
			agent->links[i] = NULL;
		}
	}

	if (agent->rb) {
		int n;

		do {
			n = ring_buffer__consume(agent->rb);
		} while (n > 0);

		if (n < 0)
			fprintf(stderr, "Ring buffer drain failed: %d\n", n);

		printf("\n");
		show_processes(agent->processes);

		if (agent->obj)
			show_statistics(agent->obj);
	}

	ring_buffer__free(agent->rb);
	free_processes(agent->processes);
	free(agent->processes);
	free(agent->open_files);
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
		perror("calloc processes");
		return -ENOMEM;
	}

	agent->open_files = calloc(OPEN_FILES_SIZE, sizeof(*agent->open_files));
	if (!agent->open_files) {
		perror("calloc open_files");
		return -ENOMEM;
	}

	agent->rb = ring_buffer__new(map_fd, callback, agent, NULL);
	if (!agent->rb) {
		perror("ring_buffer__new");
		return -1;
	}

	err = agent_attach(agent);
	if (err)
		return err;

	fprintf(stderr, "CausalTrace: ready\n");
	return 0;
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
