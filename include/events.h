/*
 * Ava Info Conseils
 *
 * Author: Antonin Do Souto
 * Contact: antonindosouto@gmail.com
 *
 * Copyright (c) 2026 Antonin Do Souto
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef AVA_EVENTS_H
#define AVA_EVENTS_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

enum event_type {
	EVENT_EXEC = 1,
	EVENT_FORK = 2,
	EVENT_EXIT = 3,
	EVENT_THREAD = 4,
};

struct event {
	__u32 type;

	__u32 pid;
	__u32 tid;

	__u32 ppid;
	__u32 ptid;

	char comm[16];
};

#endif
