BPF_NAME = causaltrace
BPF_SRC = $(BPF_NAME).bpf.c
BPF_OBJ = $(BPF_NAME).bpf.o

all: $(BPF_OBJ)

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

$(BPF_OBJ): $(BPF_SRC) vmlinux.h
	clang -g -O2 \
		-target bpf \
		-D__TARGET_ARCH_x86 \
		-I. \
		-c $(BPF_SRC) \
		-o $(BPF_OBJ)
	bpftool prog load $(BPF_OBJ) /sys/fs/bpf/$(BPF_NAME) autoattach

clean:
	rm -f $(BPF_OBJ)
