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

#ifndef EVENTS_H
#define EVENTS_H

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

	__u64 start_time_ns;
	__u64 p_start_time_ns;

	__u64 timestamp_ns;

	char comm[16];
};

#endif // EVENTS_H
