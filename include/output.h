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

#ifndef OUTPUT_H
#define OUTPUT_H

#include "agent.h"

#define CHILD_CHARS "╰╴"

void show_processes(Process* processes);
void show_statistics(struct bpf_object* obj);
void spacer(const int j);

#endif // OUTPUT_H
