BPF_NAME = causaltrace

PROG_SRC = bpf/$(BPF_NAME).c
PROG_OBJ = $(BPF_NAME)

BPF_SRC = bpf/$(BPF_NAME).bpf.c
BPF_OBJ = bin/$(BPF_NAME).bpf.o

INC = ./include/*.h

LIBBPF_FLAGS = $(shell pkg-config --cflags --libs libbpf)

all: $(PROG_OBJ)

$(PROG_OBJ): $(PROG_SRC) $(BPF_OBJ) $(INC)
	cc -Wall -Wextra -Werror -Iinclude $(PROG_SRC) -o $(PROG_OBJ) $(LIBBPF_FLAGS)

$(BPF_OBJ): $(BPF_SRC) $(INC) ./include/vmlinux.h
	mkdir -p bin
	clang -g -O2 \
		-target bpf \
		-D__TARGET_ARCH_x86 \
		-Iinclude \
		-c $(BPF_SRC) \
		-o $(BPF_OBJ)

./include/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./include/vmlinux.h

run: $(PROG_OBJ)
	sudo ./$(PROG_OBJ)

clean: unload
	rm -f $(BPF_OBJ)
	rm -f $(PROG_OBJ)

load: $(BPF_OBJ)
	sudo bpftool prog loadall $(BPF_OBJ) /sys/fs/bpf/$(BPF_NAME) autoattach

unload:
	sudo rm -f /sys/fs/bpf/$(BPF_NAME)

compdb:
	bear -- $(MAKE) -B all

.PHONY: all run clean load unload compdb
