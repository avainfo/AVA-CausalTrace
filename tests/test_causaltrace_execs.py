#!/usr/bin/env python3
"""Test AVA-CausalTrace: chain multiple execve() calls within the same PID."""

import os
import shutil
import sys
import tempfile
import time

TOTAL_STEPS = 12


def main() -> None:
    script_path = os.path.abspath(__file__)

    if len(sys.argv) == 1:
        tmpdir = tempfile.mkdtemp(prefix="causaltrace_exec_")
        python_bin = sys.executable

        for i in range(TOTAL_STEPS):
            link_path = os.path.join(tmpdir, f"exec-step-{i}")
            os.symlink(python_bin, link_path)

        print(f"START EXEC CHAIN: pid={os.getpid()} ({TOTAL_STEPS} steps)", flush=True)
        first_bin = os.path.join(tmpdir, "exec-step-0")
        os.execv(first_bin, [first_bin, script_path, tmpdir, "0"])

    tmpdir = sys.argv[1]
    step = int(sys.argv[2])

    print(f"  -> running comm='exec-step-{step}' (pid={os.getpid()})", flush=True)
    time.sleep(0.05)

    next_step = step + 1
    if next_step < TOTAL_STEPS:
        next_bin = os.path.join(tmpdir, f"exec-step-{next_step}")
        os.execv(next_bin, [next_bin, script_path, tmpdir, str(next_step)])
    else:
        shutil.rmtree(tmpdir, ignore_errors=True)
        print(
            f"END EXEC CHAIN: pid={os.getpid()} finished at exec-step-{step}",
            flush=True,
        )


if __name__ == "__main__":
    main()
