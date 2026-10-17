BPF_NAME = causaltrace

PROG_SRC = $(BPF_NAME).c
PROG_OBJ = $(BPF_NAME)

BPF_SRC = $(BPF_NAME).bpf.c
BPF_OBJ = $(BPF_NAME).bpf.o

all: $(BPF_OBJ)

$(PROG_OBJ): $(PROG_SRC) $(BPF_OBJ)
	cc -Wall -Wextra -Werror $(PROG_SRC) -o $(PROG_OBJ) \
		&& ./$(PROG_OBJ) $(pkg-config --cflags --libs libbpf) \
		&& rm -i -f $(PROG_OBJ)

$(BPF_OBJ): $(BPF_SRC) vmlinux.h
	clang -g -O2 \
		-target bpf \
		-D__TARGET_ARCH_x86 \
		-I. \
		-c $(BPF_SRC) \
		-o $(BPF_OBJ)
	# bpftool prog load $(BPF_OBJ) /sys/fs/bpf/$(BPF_NAME) autoattach

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

load: $(BPF_OBJ)
	sudo bpftool prog load $(BPF_OBJ) /sys/fs/bpf/$(BPF_NAME) autoattach

unload:
	sudo rm -f /sys/fs/bpf/$(BPF_NAME)

clean:
	rm -f $(BPF_OBJ)

.PHONY: all load unload
