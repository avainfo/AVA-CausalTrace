# AVA-CausalTrace

AVA-CausalTrace is an experimental Linux tracing project built with eBPF, libbpf, and C.

Right now, it tracks process and thread creation, exec, and exit events. The agent keeps a small in-memory record of the tasks it sees, including previous command names.

The longer-term goal is to collect enough system-level evidence to investigate failures. The actual causal analysis will live in a separate engine; this repository does not perform root-cause analysis yet.

## Repository layout

```text
.
├── agent/      # Userspace collector and process tracking
├── bpf/        # eBPF programs
├── include/    # Shared event structures and agent headers
├── tests/      # Manual test workloads
├── cli/        # Reserved for the CLI
├── sdk/        # Reserved for integration APIs
└── Makefile
```

The causal analysis engine is developed separately in `avainfo/AVA-CausalEngine` (private). CausalTrace collects and organizes evidence; the engine will use it to build and evaluate causal relationships.

## What works today

The eBPF side attaches to three BTF tracepoints:

- `sched_process_fork`: process and thread creation
- `sched_process_exec`: program execution
- `sched_process_exit`: task termination

Creation events are classified as `FORK` or `THREAD` using the child's PID and TGID. Events are sent to userspace through a 256 KiB BPF ring buffer.

The agent currently:

- Prints `FORK`, `EXEC`, `THREAD`, and `EXIT` events.
- Records PID, TID, parent/creator IDs, and the task's command name (`comm`).
- Keeps a fixed table of 512 task records and a linked history of previous command names.
- Prints the recorded state when stopped with Ctrl+C or SIGTERM.

The event layout is defined in `include/events.h`. The shared structure uses `pid` for TGID and `tid` for the task ID. For `FORK` and `THREAD`, the parent fields identify the creating task; for `EXEC` and `EXIT`, they come from `real_parent`.

## Build

Requirements:

- Linux with BTF at `/sys/kernel/btf/vmlinux`, BPF ring-buffer support, and the three `tp_btf` tracepoints above
- Clang with BPF target support
- libbpf development headers and libraries
- `bpftool`, a C compiler, GNU Make, and `pkg-config`
- Root privileges to load and attach the eBPF programs

The Makefile currently targets x86 (`__TARGET_ARCH_x86`). Other architectures have not been configured.

From the repository root:

```sh
make
make run
```

`make` builds `bin/causaltrace` and `bin/causaltrace.bpf.o`. If `include/vmlinux.h` is missing, the Makefile generates it from the running kernel's BTF.

`make run` launches the agent with `sudo`. Run it from the repository root: the agent opens `bin/causaltrace.bpf.o` using a relative path.

Other useful targets:

- `make clean`: removes `bin/` but leaves the generated `include/vmlinux.h`
- `make compdb`: generates `compile_commands.json` with Bear (requires `bear`)

`load` and `unload` are separate helpers for manual `bpftool` experiments. They are not needed for `make run`. Note that the current `unload` target does not remove a pin directory created by `loadall`.

## Test it

Start the agent in one terminal:

```sh
make run
```

In another terminal, run the included thread test (Python 3.8+):

```sh
python3 tests/test_causaltrace_threads.py
```

The script starts two worker threads, one sleeping for one second and the other for two seconds. It prints the process PID and each thread's native TID so you can compare them with CausalTrace's output.

You should see events along these lines (IDs will differ):

```text
FORK parent=1156 child=3000 comm=bash
EXEC pid=3000 comm=python3
THREAD tgid=3000 tid=3001 creator_tid=3000 comm=python3
THREAD tgid=3000 tid=3002 creator_tid=3000 comm=python3
EXIT pid=3000 tid=3001 comm=python3
EXIT pid=3000 tid=3002 comm=python3
EXIT pid=3000 tid=3000 comm=python3
```

The exact order of the worker thread events can vary. After the test finishes, stop the agent with Ctrl+C to inspect its in-memory task records and command-name history.

This is a manual workload, not an automated test suite. It doesn't start the agent or assert on the collected output.

For a simpler fork/exec test:

```sh
bash -c 'exec /bin/sleep 1'
```

This should produce a fork, an exec of Bash, an exec of `sleep` under the same PID, and an exit.

## Known limitations

- Events are collected system-wide. There is no process filter, initial `/proc` snapshot, or CLI yet.
- The task table has 512 slots. Exited entries are kept in memory and slots are not reused, so new tasks are dropped once it fills.
- Records are still a prototype: new threads don't receive a running status, and exit lookup currently compares parent IDs as well as PID/TID. Reparenting can therefore break matching.
- PID reuse is not handled. The agent also does not detect missed events or count ring-buffer reservation failures.
- Events have no timestamps or sequence numbers.
- Command history stores previous `comm` values, not executable paths or full command lines.
- Exit codes, syscall failures, network activity, file I/O, and application logs are not collected yet.
- There is no persistent trace format, causal-engine integration, or automated root-cause analysis.
- Tests are manual; there is no assertion-based test suite or CI workflow yet.

The next step is to make process/thread state reliable, including exit handling, record retention, and parent-child relationships. Timestamps and failure-related syscalls come after that.

## Licensing

The code currently uses SPDX identifiers in individual source files:

| Component | License |
| --- | --- |
| eBPF programs | GPL-2.0-only |
| `include/events.h` | GPL-2.0-only |
| C agent and its headers | Apache-2.0 |

The planned CLI and SDK are intended to use Apache-2.0. Standalone license files have not been added yet. The separate causal engine is proprietary.
