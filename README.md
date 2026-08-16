# AVA CausalTrace

**Causal root-cause analysis for Linux systems.**

AVA CausalTrace is an experimental Linux observability project focused on reconstructing the chain of events that caused a failure.

The goal is not only to identify where a problem becomes visible, but to trace it back to the deepest useful cause.

For example:

```text
Application timeout
        ↓
Thread waiting on socket
        ↓
Remote process blocked
        ↓
Slow filesystem read
        ↓
Storage latency
```

A traditional monitoring tool may tell us that the application timed out.

AVA should eventually be able to explain **why**.

## Idea

AVA uses eBPF to observe low-level Linux activity and collect events related to:

* processes and threads
* syscalls
* scheduling
* files and file descriptors
* sockets and network activity
* I/O
* resource waits
* signals

These events are collected by a userspace agent and converted into a normalized trace.

```text
Linux kernel
     │
     │ eBPF
     ▼
System events
     │
     ▼
AVA Agent
     │
     ▼
Normalized trace
     │
     ▼
Causal analysis
     │
     ▼
Root cause
```

The eBPF probes are only the observation layer.

The difficult part is determining which events are actually related and reconstructing the causal path that produced the final symptom.

## Architecture

AVA CausalTrace is split into two repositories.

### Public repository

```text
avainfo/ava-causaltrace
├── agent
├── bpf
├── cli
└── sdk
```

This repository contains the open tracing and integration components:

* `bpf`: eBPF programs used to observe Linux system activity
* `agent`: userspace event collector
* `cli`: command-line interface
* `sdk`: integration APIs and trace-related interfaces

### Private causal engine

```text
avainfo/ava-causal-engine
├── graph
├── inference
├── correlation
├── scoring
└── reducer
```

The causal engine is developed separately and is proprietary.

Its responsibilities include:

* `graph`: causal and dependency graph representation
* `correlation`: relationships between observed events
* `inference`: causal reasoning and root-cause candidate generation
* `scoring`: confidence and candidate ranking
* `reducer`: elimination of irrelevant or weaker explanations

The public repository is responsible for collecting reliable system evidence.

The private engine is responsible for turning that evidence into a causal explanation.

## First objective

The first version will intentionally focus on a small and reproducible failure scenario.

Something similar to:

```text
service A
    ↓ request
service B
    ↓
blocking I/O
    ↓
timeout
    ↓
service A appears frozen
```

The initial objective is simple:

> Can AVA collect enough information from the Linux system to automatically reconstruct this dependency chain?

If that works reliably, the system can progressively support more complex incidents.

## Technical direction

### Kernel side

* eBPF
* libbpf
* CO-RE
* BTF
* C

### Userspace

* Rust

The architecture is still experimental and will evolve as the project progresses.

## Roadmap

* [ ] Define the first supported failure scenario
* [ ] Define the event model
* [ ] Load the first eBPF program
* [ ] Stream events to userspace
* [ ] Track process and thread relationships
* [ ] Track blocking operations and resources
* [ ] Correlate related events
* [ ] Produce a normalized trace format
* [ ] Feed traces into the causal engine
* [ ] Build a basic dependency graph
* [ ] Traverse the graph backward from a symptom
* [ ] Identify root-cause candidates
* [ ] Validate results against controlled failures
* [ ] Measure tracing overhead

## Licensing

The public repository uses different licenses depending on the component.

```text
eBPF programs        GPL-2.0-only
Agent                Apache-2.0
CLI                  Apache-2.0
SDK                  Apache-2.0
Trace specification  Apache-2.0
```

The causal analysis engine in `avainfo/ava-causal-engine` is proprietary and is not part of this repository.

Source files will use SPDX license identifiers where appropriate.

## Status

AVA CausalTrace is currently at the beginning of development.

The priority is not to build a complete observability platform.

The first goal is to prove that a useful causal chain can be reconstructed from low-level Linux events.
