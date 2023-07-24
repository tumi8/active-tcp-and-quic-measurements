import psutil


def count_running(pname: str, p_cmdline: str) -> int:
    cnt = 0
    for p in psutil.process_iter():
        if pname == p.name() and p_cmdline in " ".join(p.cmdline()):
            cnt += 1

    return cnt
