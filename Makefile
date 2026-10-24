
BPF_NAME = causaltrace

PROG_SRC = $(wildcard agent/*.c)
PROG_OBJ = $(patsubst agent/%.c,bin/agent/%.o,$(PROG_SRC))
PROG_DEP = $(PROG_OBJ:.o=.d)
PROG_BIN = bin/$(BPF_NAME)

BPF_SRC = bpf/$(BPF_NAME).bpf.c
BPF_OBJ = bin/$(BPF_NAME).bpf.o

CFLAGS = -Wall -Wextra -Werror -Iinclude -MMD -MP
LIBBPF_CFLAGS = $(shell pkg-config --cflags libbpf)
LIBBPF_LIBS = $(shell pkg-config --libs libbpf)

all: $(PROG_BIN) $(BPF_OBJ)

$(PROG_BIN): $(PROG_OBJ)
	$(CC) $(PROG_OBJ) -o $@ $(LIBBPF_LIBS)

bin/agent/%.o: agent/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) -c $< -o $@

$(BPF_OBJ): $(BPF_SRC) include/vmlinux.h
	mkdir -p $(dir $@)
	clang -g -O2 \
		-target bpf \
		-D__TARGET_ARCH_x86 \
		-Iinclude \
		-c $< \
		-o $@

include/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

run: all
	sudo ./$(PROG_BIN)

clean:
	rm -rf bin

load: $(BPF_OBJ)
	sudo bpftool prog loadall $(BPF_OBJ) /sys/fs/bpf/$(BPF_NAME) autoattach

unload:
	sudo rm -f /sys/fs/bpf/$(BPF_NAME)

compdb:
	bear -- $(MAKE) -B all

-include $(PROG_DEP)

.PHONY: all run clean load unload compdb
