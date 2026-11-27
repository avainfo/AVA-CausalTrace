import os
import threading


def worker(index):
    path = f"/tmp/causaltrace-thread-{index}.txt"

    print(f"PID={os.getpid()} TID={threading.get_native_id()}")

    for _ in range(100):
        fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o644)
        os.close(fd)


threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]

for thread in threads:
    thread.start()

for thread in threads:
    thread.join()
