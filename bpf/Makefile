BPF_NAME = causaltrace

PROG_SRC = $(BPF_NAME).c
PROG_OBJ = $(BPF_NAME)

BPF_SRC = $(BPF_NAME).bpf.c
BPF_OBJ = $(BPF_NAME).bpf.o

LIBBPF_FLAGS = $(shell pkg-config --cflags --libs libbpf)

all: $(BPF_OBJ)

$(PROG_OBJ): $(PROG_SRC) $(BPF_OBJ)
	cc -Wall -Wextra -Werror $(PROG_SRC) -o $(PROG_OBJ) $(LIBBPF_FLAGS) \
		&& ./$(PROG_OBJ) \
		# && rm -i -f $(PROG_OBJ)

$(BPF_OBJ): $(BPF_SRC) vmlinux.h
	clang -g -O2 \
		-target bpf \
		-D__TARGET_ARCH_x86 \
		-I. \
		-c $(BPF_SRC) \
		-o $(BPF_OBJ)

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean: unload
	rm -f $(BPF_OBJ)
	rm -f $(PROG_OBJ)

load: $(BPF_OBJ)
	sudo bpftool prog load $(BPF_OBJ) /sys/fs/bpf/$(BPF_NAME) autoattach

unload:
	sudo rm -f /sys/fs/bpf/$(BPF_NAME)

.PHONY: all load unload
