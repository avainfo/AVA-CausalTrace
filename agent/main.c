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
#include <stddef.h>
#include <stdlib.h>

#include "agent.h"
#include "signals.h"

int main(void) {
	Agent agent = {0};

	if (signals_init() < 0)
		return EXIT_FAILURE;

	int err = agent_init(&agent);

	if (!err)
		err = agent_run(&agent);

	agent_destroy(&agent);

	return err ? EXIT_FAILURE : EXIT_SUCCESS;
}
