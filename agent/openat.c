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

#include "agent.h"

#include <bpf/bpf_helpers.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int add_open_file(OpenAT* open_files, OpenAT f) {
	if (!open_files || f.pid == 0 || f.tid == 0)
		return 0;

	OpenAT* free_slot = NULL;
	for (size_t i = 0; i < OPEN_FILES_SIZE; i++) {
		if (open_files[i].pid == f.pid && open_files[i].tid == f.tid) {
			open_files[i] = f;
			return 1;
		}

		if (!free_slot && open_files[i].pid == 0 && open_files[i].tid == 0)
			free_slot = &open_files[i];
	}

	if (!free_slot)
		free_slot = evict_open_file(open_files);

	if (!free_slot)
		return 0;

	*free_slot = f;
	return 1;
}

void exit_open_file(OpenAT* open_files, OpenAT f, __s64 ret) {
	if (!open_files || f.pid == 0 || f.tid == 0)
		return;

	OpenAT* open_file = NULL;

	for (size_t i = 0; i < OPEN_FILES_SIZE; i++) {
		if (open_files[i].pid == f.pid && open_files[i].tid == f.tid) {
			open_file = &open_files[i];
			break;
		}
	}

	if (!open_file) {
		fprintf(stderr,
		        "FILE_OPEN_ERROR Pending event not found "
		        "pid=%i tid=%i\n",
		        f.pid, f.tid);
		return;
	}

	open_file->ret = ret;
	const char* filename = open_file->fname_read_ret < 0 ? "<unavailable>" : open_file->filename;

	if (ret >= 0)
		printf("FILE_OPEN pid=%i tid=%i file=%s flags=0x%llx ret=%lli (%llu)\n", open_file->pid, open_file->tid,
		       filename, open_file->flags, open_file->ret, open_file->start_timestamp_ns);
	else
		fprintf(stderr, "FILE_OPEN_ERROR pid=%i tid=%i file=%s flags=0x%llx ret=%lli (%llu)\n", open_file->pid,
		        open_file->tid, filename, open_file->flags, open_file->ret, open_file->start_timestamp_ns);

	memset(open_file, 0, sizeof(*open_file));
}

OpenAT* evict_open_file(OpenAT* open_files) {
	if (!open_files)
		return NULL;

	OpenAT* last_file = &open_files[0];

	for (size_t i = 1; i < OPEN_FILES_SIZE; i++) {
		if (open_files[i].start_timestamp_ns < last_file->start_timestamp_ns)
			last_file = &open_files[i];
	}

	return last_file;
}
