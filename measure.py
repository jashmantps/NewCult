#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# measure.py  --  test & measure the cultsandbox isolation (Project 2/3)
#
# Launches each attack victim twice -- once WITHOUT the cgroup caps and once
# WITH them -- and records what the cgroup did, writing CSV files that the
# graphing script turns into the poster figures.
#
#   cpu   : cpuhog, sample the cgroup's CPU%% over time         -> cpu.csv
#   mem   : memhog, sample the cgroup's memory.current over time-> mem.csv
#   pids  : forkbomb, record how many forks succeeded           -> pids.csv
#
# Run as root (or with a delegated /sys/fs/cgroup/cult) on a cgroup-v2 host.
#   sudo python3 measure.py all
# ---------------------------------------------------------------------------

import os
import sys
import time
import signal
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.environ.get("CULT_OUT", HERE)
CGROUP_BASE = "/sys/fs/cgroup/cult"


def _ensure_parent():
    """Enable controllers on the delegated parent cgroup (needs privilege)."""
    try:
        os.makedirs(CGROUP_BASE, exist_ok=True)
        with open("/sys/fs/cgroup/cgroup.subtree_control", "w") as f:
            f.write("+cpu +memory +pids")
    except OSError:
        pass
    try:
        with open(os.path.join(CGROUP_BASE, "cgroup.subtree_control"), "w") as f:
            f.write("+cpu +memory +pids")
    except OSError:
        pass


def _launch(victim, cpu, mem, pids, no_cgroup):
    cmd = [sys.executable, os.path.join(HERE, "cultsandbox.py"),
           "--victim", victim, "--cpu", str(cpu), "--mem", str(mem),
           "--pids", str(pids)]
    if no_cgroup:
        cmd.append("--no-cgroup")
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE, text=True)


def _find_cgroup(pid):
    p = os.path.join(CGROUP_BASE, "p%d" % pid)
    return p if os.path.isdir(p) else None


def _read_int(path):
    try:
        with open(path) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def _read_usage_usec(cg):
    try:
        with open(os.path.join(cg, "cpu.stat")) as f:
            for line in f:
                if line.startswith("usage_usec"):
                    return int(line.split()[1])
    except OSError:
        pass
    return None


def measure_cpu(cap=20, seconds=10):
    rows = [("t_s", "capped_cpu_pct", "uncapped_cpu_pct")]
    series = {}
    for label, no_cg in (("uncapped", True), ("capped", False)):
        proc = _launch("cpuhog", cap, 128, 64, no_cgroup=no_cg)
        time.sleep(0.8)
        cg = None if no_cg else _find_cgroup(proc.pid)
        samples = []
        last = _read_usage_usec(cg) if cg else None
        # Without a cgroup we read the process's own CPU time from /proc.
        last_proc = _proc_cputime(proc.pid)
        t0 = time.time()
        while time.time() - t0 < seconds:
            time.sleep(1.0)
            if cg:
                now = _read_usage_usec(cg)
                pct = (now - last) / 1_000_000 * 100 if (now and last) else 0.0
                last = now
            else:
                nowp = _proc_cputime(proc.pid)
                pct = (nowp - last_proc) * 100 if (nowp and last_proc) else 0.0
                last_proc = nowp
            samples.append(round(pct, 1))
        series[label] = samples
        _kill(proc)
        time.sleep(0.3)
    n = max(len(series["capped"]), len(series["uncapped"]))
    for i in range(n):
        c = series["capped"][i] if i < len(series["capped"]) else ""
        u = series["uncapped"][i] if i < len(series["uncapped"]) else ""
        rows.append((i + 1, c, u))
    _write_csv("cpu.csv", rows)
    print("CPU cap=%d%%: capped=%s  uncapped=%s" %
          (cap, series["capped"], series["uncapped"]))


def _proc_cputime(pid):
    """Total CPU seconds used by a process (utime+stime) from /proc."""
    try:
        with open("/proc/%d/stat" % pid) as f:
            parts = f.read().split()
        clk = os.sysconf("SC_CLK_TCK")
        return (int(parts[13]) + int(parts[14])) / clk
    except (OSError, ValueError, IndexError):
        return None


def measure_mem(cap_mb=64, seconds=12):
    rows = [("t_s", "capped_mem_mb", "cap_mb")]
    proc = _launch("memhog", 50, cap_mb, 64, no_cgroup=False)
    time.sleep(0.8)
    cg = _find_cgroup(proc.pid)
    t0 = time.time()
    killed_at = None
    while time.time() - t0 < seconds:
        cur = _read_int(os.path.join(cg, "memory.current")) if cg else None
        mb = round(cur / 1024 / 1024, 1) if cur else 0.0
        rows.append((round(time.time() - t0, 1), mb, cap_mb))
        if proc.poll() is not None and killed_at is None:
            killed_at = round(time.time() - t0, 1)
        time.sleep(0.5)
    # was it OOM-killed by the cgroup?
    events = ""
    try:
        with open(os.path.join(cg, "memory.events")) as f:
            events = f.read().replace("\n", " ")
    except OSError:
        pass
    _kill(proc)
    _write_csv("mem.csv", rows)
    print("MEM cap=%dMB: process exited=%s at t=%s; memory.events: %s" %
          (cap_mb, proc.poll() is not None, killed_at, events.strip()))


def measure_pids(cap=16, seconds=6):
    proc = _launch("forkbomb", 50, 128, cap, no_cgroup=False)
    time.sleep(0.8)
    cg = _find_cgroup(proc.pid)
    peak = 0
    t0 = time.time()
    while time.time() - t0 < seconds:
        cur = _read_int(os.path.join(cg, "pids.current")) if cg else None
        if cur:
            peak = max(peak, cur)
        time.sleep(0.3)
    maxv = None
    try:
        with open(os.path.join(cg, "pids.max")) as f:
            maxv = f.read().strip()
    except OSError:
        pass
    _kill(proc)
    _write_csv("pids.csv", [("pids_max", "pids_peak_observed"), (maxv, peak)])
    print("PIDS cap=%s: peak live processes in cgroup=%d (fork bomb contained)"
          % (maxv, peak))


def _kill(proc):
    try:
        proc.send_signal(signal.SIGKILL)
    except OSError:
        pass
    # reap any lingering forkbomb children of ours
    try:
        proc.wait(timeout=2)
    except Exception:
        pass


def _write_csv(name, rows):
    path = os.path.join(OUT, name)
    with open(path, "w") as f:
        for r in rows:
            f.write(",".join(str(x) for x in r) + "\n")
    print("  wrote", path)


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    _ensure_parent()
    if which in ("all", "cpu"):
        measure_cpu()
    if which in ("all", "mem"):
        measure_mem()
    if which in ("all", "pids"):
        measure_pids()
