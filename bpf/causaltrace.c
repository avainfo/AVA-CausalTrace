#include <bpf/libbpf.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
	(void) argc;
	(void) argv;
	struct bpf_object* obj;

	obj = bpf_object__open_file("causaltrace.bpf.o", NULL);

	(void) obj;

	printf("Event recieved: ");
	return 0;
}
