BPF_SRC = causaltrace.bpf.c
BPF_OBJ = causaltrace.bpf.o

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

clean:
	rm -f $(BPF_OBJ)
