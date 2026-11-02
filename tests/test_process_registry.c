/*
 * AVA-CausalTrace: standalone userspace registry tests.
 *
 * Run current eviction tests:
 *   cc -g3 -O0 -Wall -Wextra -Werror -Iinclude \
 *      tests/test_process_registry.c agent/processes.c \
 *      -o /tmp/test_process_registry
 *   valgrind --leak-check=full --error-exitcode=42 /tmp/test_process_registry
 *
 * After adding Process.start_time_ns and Process.parent_start_time_ns,
 * enable task-identity regression tests with -DTEST_PID_REUSE.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "agent.h"

static Process* new_table(void) {
	Process* table = calloc(HISTORIC_SIZE, sizeof(*table));
	assert(table != NULL);
	return table;
}

static void destroy_table(Process* table) {
	free_processes(table);
	free(table);
}

static Process* full_running_table(void) {
	Process* table = new_table();
	for (size_t i = 0; i < HISTORIC_SIZE; i++) {
		table[i].pid = (unsigned)(1000 + i);
		table[i].tid = (unsigned)(1000 + i);
		table[i].status = STATUS_RUNNING;
	}
	return table;
}

static void test_eviction_preserves_referenced_parent(void) {
	Process* table = full_running_table();
	table[0].status = STATUS_EXITED;
	table[1].parent = &table[0];
	table[2].status = STATUS_EXITED;

	ExecRecord* history = calloc(1, sizeof(*history));
	assert(history != NULL);
	memcpy(history->comm, "old-command", sizeof("old-command"));
	table[2].exec_history = history;

	assert(is_referenced(table, &table[0]) == 1);
	assert(is_referenced(table, &table[2]) == 0);
	assert(evict_process(table) == 1);
	assert(table[0].pid == 1000);
	assert(table[1].parent == &table[0]);
	assert(table[2].pid == 0);
	assert(table[2].exec_history == NULL);
	destroy_table(table);
	puts("PASS: referenced parent protected, eligible task evicted");
}

static void test_no_eligible_candidate(void) {
	Process* table = full_running_table();
	table[0].status = STATUS_EXITED;
	table[1].parent = &table[0];

	assert(evict_process(table) == 0);
	Process incoming = {.pid = 70000, .tid = 70000, .status = STATUS_RUNNING};
	assert(add_process(table, incoming) == 0);
	assert(table[0].pid == 1000);
	assert(table[1].parent == &table[0]);
	destroy_table(table);
	puts("PASS: full table refuses insertion without eligible victim");
}

static void test_insert_reuses_eligible_slot(void) {
	Process* table = full_running_table();
	table[0].status = STATUS_EXITED;
	table[1].parent = &table[0];
	table[2].status = STATUS_EXITED;

	Process incoming = {.pid = 70000, .tid = 70000, .status = STATUS_RUNNING};
	assert(add_process(table, incoming) == 1);
	assert(table[0].pid == 1000);
	assert(table[2].pid == 70000);
	assert(table[2].status == STATUS_RUNNING);
	assert(table[1].parent == &table[0]);
	destroy_table(table);
	puts("PASS: full-table insertion reuses unreferenced EXITED slot");
}

static void test_exec_history_lifecycle(void) {
	Process* table = new_table();
	Process before = {.pid = 50, .tid = 50, .status = STATUS_RUNNING};
	memcpy(before.comm, "bash", sizeof("bash"));
	assert(add_process(table, before) == 1);
	Process after = before;
	memcpy(after.comm, "curl", sizeof("curl"));
	assert(add_process(table, after) == 1);
	assert(strcmp(table[0].comm, "curl") == 0);
	assert(table[0].exec_history != NULL);
	assert(strcmp(table[0].exec_history->comm, "bash") == 0);
	destroy_table(table);
	puts("PASS: exec history stored and released");
}

#ifdef TEST_PID_REUSE
static size_t count_task_instances(const Process* table, unsigned pid, unsigned tid) {
	size_t count = 0;
	for (size_t i = 0; i < HISTORIC_SIZE; ++i)
		if (table[i].pid == pid && table[i].tid == tid)
			count++;
	return count;
}

static void test_pid_reuse_does_not_merge_instances(void) {
	Process* table = new_table();
	Process old_task = {
	    .pid = 4200,
	    .tid = 4200,
	    .start_time_ns = 100,
	    .status = STATUS_EXITED,
	};
	memcpy(old_task.comm, "curl", sizeof("curl"));
	Process new_task = {
	    .pid = 4200,
	    .tid = 4200,
	    .start_time_ns = 200,
	    .status = STATUS_RUNNING,
	};
	memcpy(new_task.comm, "python3", sizeof("python3"));

	assert(add_process(table, old_task) == 1);
	assert(add_process(table, new_task) == 1);
	assert(count_task_instances(table, 4200, 4200) == 2);
	assert(table[0].status == STATUS_EXITED);
	assert(table[0].start_time_ns == 100);
	assert(table[1].status == STATUS_RUNNING);
	assert(table[1].start_time_ns == 200);
	assert(table[1].exec_history == NULL);
	assert(search_process(table, old_task) == &table[0]);
	assert(search_process(table, new_task) == &table[1]);
	assert(exit_process(table, new_task) == 1);
	assert(table[0].status == STATUS_EXITED && table[1].status == STATUS_EXITED);
	destroy_table(table);
	puts("PASS: distinct generations of one PID remain distinct");
}

static void test_parent_pid_reuse_preserves_lineage(void) {
	Process* table = new_table();
	Process parent_old = {
	    .pid = 900,
	    .tid = 900,
	    .start_time_ns = 100,
	    .status = STATUS_EXITED,
	};
	Process parent_new = {
	    .pid = 900,
	    .tid = 900,
	    .start_time_ns = 300,
	    .status = STATUS_RUNNING,
	};
	Process child_old = {
	    .pid = 901,
	    .tid = 901,
	    .start_time_ns = 200,
	    .ppid = 900,
	    .ptid = 900,
	    .parent_start_time_ns = 100,
	    .status = STATUS_EXITED,
	};
	Process child_new = {
	    .pid = 902,
	    .tid = 902,
	    .start_time_ns = 400,
	    .ppid = 900,
	    .ptid = 900,
	    .parent_start_time_ns = 300,
	    .status = STATUS_RUNNING,
	};

	assert(add_process(table, parent_old) == 1);
	assert(add_process(table, parent_new) == 1);
	assert(add_process(table, child_old) == 1);
	assert(add_process(table, child_new) == 1);
	assert(table[2].parent == &table[0]);
	assert(table[3].parent == &table[1]);
	assert(is_referenced(table, &table[0]) == 1);
	assert(is_referenced(table, &table[1]) == 1);
	destroy_table(table);
	puts("PASS: child linked to correct generation of reused parent PID");
}
#endif

int main(void) {
	test_eviction_preserves_referenced_parent();
	test_no_eligible_candidate();
	test_insert_reuses_eligible_slot();
	test_exec_history_lifecycle();
#ifdef TEST_PID_REUSE
	test_pid_reuse_does_not_merge_instances();
	test_parent_pid_reuse_preserves_lineage();
#else
	puts("SKIP: PID reuse tests (enable with -DTEST_PID_REUSE after schema update)");
#endif
	puts("ALL TESTS PASSED");
	return 0;
}
