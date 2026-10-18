#include <bpf/libbpf.h>
#include <bpf/libbpf_legacy.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

enum event_type {
	EVENT_EXEC = 1,
	EVENT_FORK = 2,
};

struct event {
	__u32 type;
	__u32 pid;
	__u32 tid;
	__u32 ppid;
	char comm[16];
};

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
	}

	return 0;
}

int main(int argc, char* argv[]) {
	(void)argc;
	(void)argv;
	struct bpf_object* obj;

	obj = bpf_object__open_file("causaltrace.bpf.o", NULL);
	if (!obj) {
		bpf_object__close(obj);
		return 1;
	}

	int obj_loaded = bpf_object__load(obj);
	if (obj_loaded != 0) {
		bpf_object__close(obj);
		return 1;
	}

	struct bpf_map* map = bpf_object__find_map_by_name(obj, "events");
	if (!map) {
		bpf_object__close(obj);
		return 1;
	}

	int map_fd = bpf_map__fd(map);
	if (map_fd < 0) {
		bpf_object__close(obj);
		return 1;
	}

	struct bpf_program* exec_prog = bpf_object__find_program_by_name(obj, "obs_procs");
	struct bpf_program* fork_prog = bpf_object__find_program_by_name(obj, "obs_forks");
	if (!exec_prog || !fork_prog) {
		fprintf(stderr, "Cannot find BPF programs\n");
		bpf_object__close(obj);
		return 1;
	}

	struct bpf_link* exec_link = bpf_program__attach(exec_prog);
	struct bpf_link* fork_link = bpf_program__attach(fork_prog);
	if (!exec_link || !fork_link) {
		fprintf(stderr, "Cannot attach BPF programs\n");

		if (exec_link)
			bpf_link__destroy(exec_link);

		if (fork_link)
			bpf_link__destroy(fork_link);

		bpf_object__close(obj);
		return 1;
	}

	struct ring_buffer* rb = ring_buffer__new(map_fd, callback, NULL, NULL);
	if (!rb) {
		bpf_link__destroy(exec_link);
		bpf_link__destroy(fork_link);
		bpf_object__close(obj);
		return 1;
	}

	int loop = true;
	while (loop) {
		int err = ring_buffer__poll(rb, 200);
		if (err < -1) {
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	}

	ring_buffer__free(rb);
	bpf_link__destroy(exec_link);
	bpf_link__destroy(fork_link);
	bpf_object__close(obj);

	printf("SUCCEEDED");
	return 0;
}
