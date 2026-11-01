#!/usr/bin/env python3
"""Test AVA-CausalTrace: process + two worker threads with distinct lifetimes."""

import os
import threading
import time


def worker(name: str, duration: float) -> None:
    tid = threading.get_native_id()
    print(f"START {name}: pid={os.getpid()}, tid={tid}", flush=True)
    time.sleep(duration)
    print(f"END   {name}: pid={os.getpid()}, tid={tid}", flush=True)


def main() -> None:
    print(f"MAIN: pid={os.getpid()}, tid={threading.get_native_id()}", flush=True)
    threads = [
        threading.Thread(target=worker, args=("worker-1", 1.0)),
        threading.Thread(target=worker, args=("worker-2", 2.0)),
    ]

    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    print("MAIN: both workers finished; exiting", flush=True)


if __name__ == "__main__":
    main()
