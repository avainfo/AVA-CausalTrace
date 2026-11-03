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
#define BOX_TR "╮"
#define BOX_TL "╭"
#define BOX_BR "╯"
#define BOX_BL "╰"
#define BOX_H "─"
#define BOX_V "│"

void show_processes(Process* processes);
void show_statistics(struct bpf_object* obj);
void spacer(const int j);
void print_title(char* title);

#endif // OUTPUT_H
