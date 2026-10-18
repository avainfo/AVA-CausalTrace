#include <bpf/libbpf.h>
#include <bpf/libbpf_legacy.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

struct event {
	__u32 pid;
	__u32 tid;
	char comm[16];
};

int callback(void* ctx, void* data, size_t size) {
	(void)ctx;
	(void)size;

	struct event* e = data;

	printf("Received PID: %d\n", e->pid);
	printf("Received COMM: %s\n", e->comm);

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

	struct bpf_program* prog = bpf_object__find_program_by_name(obj, "obs_procs");
	if (!prog) {
		bpf_object__close(obj);
		return 1;
	}

	struct bpf_link* link = bpf_program__attach(prog);
	if (!link) {
		bpf_object__close(obj);
		return 1;
	}

	struct ring_buffer* rb = ring_buffer__new(map_fd, callback, NULL, NULL);
	if (!rb) {
		bpf_link__destroy(link);
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

	// bpf_link__destroy(link);
	// bpf_object__close(obj);

	printf("SUCCEEDED");
	return 0;
}
