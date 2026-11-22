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
#include <stdlib.h>
#include <string.h>

int add_open_file(OpenAT* open_files, OpenAT f) {
	if (!open_files || f.pid == 0 || f.tid == 0)
		return 0;

	OpenAT* free_slot = NULL;
	for (size_t i = 0; i < OPEN_FILES_SIZE; i++) {
		if (open_files[i].pid == f.pid && open_files[i].tid == f.tid && open_files[i].dfd == f.dfd &&
		    strcmp(open_files[i].filename, f.filename) == 0) {
			open_files[i] = f;
			return 1;
		}

		if (!free_slot && open_files[i].pid == 0 && open_files[i].tid == 0)
			free_slot = &open_files[i];
	}

	if (!free_slot) {
		if (evict_open_file(open_files)) {
			return add_open_file(open_files, f);
		}
		return 0;
	}

	*free_slot = f;
	return 1;
}

int exit_open_file(OpenAT* open_files, OpenAT f, __s64 ret) {
	if (!open_files || f.pid == 0 || f.tid == 0)
		return 0;
	(void)ret;

	return 1;
}

int evict_open_file(OpenAT* open_files) {
	if (!open_files)
		return 0;

	OpenAT* last_file = &open_files[0];

	for (size_t i = 1; i < OPEN_FILES_SIZE; i++) {
		if (open_files[i].timestamp_ns < last_file->timestamp_ns)
			last_file = &open_files[i];
	}

	memset(last_file, 0, sizeof(*last_file));
	return 1;
}
