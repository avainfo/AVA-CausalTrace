FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
		build-essential \
		clang \
		llvm \
		lld \
		gcc \
		make \
		cmake \
		git \
		pkg-config \
		libbpf-dev \
		libelf-dev \
		libcap-dev \
		zlib1g-dev \
		linux-tools-common \
		linux-tools-generic \
		libssl-dev \
		iproute2 \
		strace \
		gdb \
		curl \
		vim \
		&& rm -rf /var/lib/apt/lists/*

RUN rm -rf /sys/fs/bpf/causaltrace

RUN git clone --recurse-submodules https://github.com/libbpf/bpftool.git

RUN cd bpftool/src && make && make install

WORKDIR /workspace

CMD ["/bin/bash"]

