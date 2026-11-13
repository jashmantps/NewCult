#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# cultsandbox.py  --  The Cult: player isolation launcher  (Project 2/3)
#
# Author: Abhishek Singh
# Course: CSE/CEN Advanced Operating Systems, ASU, Fall 2026
#
# THIS IS THE NEW ISOLATION MECHANISM added for Projects 2/3.
#
# Instead of running the client directly:
#       python3 cultclient.py <sock> <name>
# a player runs it *through the sandbox*:
#       python3 cultsandbox.py --sock <sock> --name <name>
#
# The sandbox wraps the player's process in two independent Linux isolation
# layers before the game client ever runs:
#
#   1. cgroups v2  (resource isolation / robustness)
#      The process is placed in its own control group with hard caps on:
#        * CPU time     (cpu.max)     -> a busy-looping player can't starve
#                                         the server or other players
#        * memory       (memory.max)  -> a memory-bomb player is OOM-killed
#                                         inside its own cgroup, nobody else
#        * process count(pids.max)    -> a fork-bomb player hits the pid cap
#      So one misbehaving player can no longer bring down the machine or the
#      game server by exhausting shared resources.
#
#   2. seccomp-BPF  (syscall isolation / security)
#      A Berkeley Packet Filter program is installed into the kernel for this
#      process (and everything it spawns) that KILLS the process if it tries
#      a dangerous system call -- executing another program (execve),
#      tracing other processes (ptrace), loading kernel modules, mounting
#      filesystems, kexec, bpf, reboot, etc.  A compromised or malicious
#      client is confined to talking on its game socket; it cannot spawn a
#      shell or tamper with the rest of the system.
#      The filter is written here as raw BPF via ctypes, so it needs NO
#      external library (no libseccomp/pyseccomp) to run on the VM.
#
# After both layers are installed, the sandbox runs the real game client
# IN-PROCESS (it imports cultclient and calls its main) -- it never calls
# execve, which is exactly what the seccomp filter forbids.
#
# Built-in attack victims (for testing the isolation, see --victim):
#   cpuhog   : busy-loop forever        (tests cpu.max)
#   memhog   : allocate until killed     (tests memory.max)
#   forkbomb : fork aggressively         (tests pids.max)
#   execshell: try to exec /bin/sh       (tests the seccomp block)
#   ptrace   : try to ptrace             (tests the seccomp block)
# ---------------------------------------------------------------------------

import os
import sys
import ctypes
import struct
import argparse

CGROUP_BASE = "/sys/fs/cgroup/cult"     # delegated parent created by install.sh


# ===========================================================================
# cgroups v2
# ===========================================================================

def apply_cgroup(cpu_pct, mem_mb, pids_max, base=CGROUP_BASE):
    """Create a per-process cgroup v2 with CPU/memory/pids caps and join it.

    Returns the cgroup path on success, or None if cgroups are unavailable
    (e.g. not set up by install.sh, or no delegation). We degrade gracefully
    so the game still runs; the caps are simply not enforced.
    """
    cg = os.path.join(base, "p%d" % os.getpid())
    try:
        os.makedirs(cg, exist_ok=True)
    except (PermissionError, FileNotFoundError, OSError) as e:
        sys.stderr.write("[sandbox] cgroup unavailable (%s); "
                         "resource caps NOT enforced.\n" % e)
        return None

    def write(name, value):
        try:
            with open(os.path.join(cg, name), "w") as f:
                f.write(value)
            return True
        except OSError as e:
            sys.stderr.write("[sandbox] could not set %s=%s (%s)\n"
                             % (name, value, e))
            return False

    # cpu.max is "QUOTA PERIOD" in microseconds. 20% -> "20000 100000".
    period = 100000
    quota = int(period * cpu_pct / 100.0)
    write("cpu.max", "%d %d" % (quota, period))
    write("memory.max", str(int(mem_mb) * 1024 * 1024))
    write("pids.max", str(int(pids_max)))

    # Join: writing our PID into cgroup.procs moves this process in.
    if not write("cgroup.procs", str(os.getpid())):
        sys.stderr.write("[sandbox] could not join cgroup; caps NOT enforced.\n")
        return None
    sys.stderr.write("[sandbox] cgroup %s  cpu=%d%% mem=%dMB pids=%s\n"
                     % (cg, cpu_pct, mem_mb, pids_max))
    return cg


# ===========================================================================
# seccomp-BPF  (raw filter, no external library)
# ===========================================================================

# BPF instruction encodings
BPF_LD = 0x00
BPF_W = 0x00
BPF_ABS = 0x20
BPF_JMP = 0x05
BPF_JEQ = 0x10
BPF_K = 0x00
BPF_RET = 0x06

# seccomp return actions
SECCOMP_RET_ALLOW = 0x7fff0000
SECCOMP_RET_KILL_PROCESS = 0x80000000

AUDIT_ARCH_X86_64 = 0xC000003E

# prctl / seccomp constants
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2

# x86_64 syscall numbers we refuse (the "dangerous" set).
BLOCKED = {
    "execve": 59, "execveat": 322,     # spawn another program (e.g. a shell)
    "ptrace": 101,                      # trace/inject into other processes
    "mount": 165, "umount2": 166,       # tamper with the filesystem tree
    "pivot_root": 155, "chroot": 161,
    "unshare": 272, "setns": 308,       # escape/alter namespaces
    "kexec_load": 246, "kexec_file_load": 320,
    "init_module": 175, "finit_module": 313, "delete_module": 176,
    "bpf": 321,                         # load further BPF / tamper
    "reboot": 169,
    "swapon": 167, "swapoff": 168,
    "settimeofday": 164, "clock_settime": 227,
}


class SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_uint16),
                ("jt", ctypes.c_uint8),
                ("jf", ctypes.c_uint8),
                ("k", ctypes.c_uint32)]


class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort),
                ("filter", ctypes.POINTER(SockFilter))]


def _stmt(code, k):
    return SockFilter(code, 0, 0, k)


def _jump(code, k, jt, jf):
    return SockFilter(code, jt, jf, k)


def build_filter():
    """Default-ALLOW blocklist: kill the process on any BLOCKED syscall.

    A blocklist (rather than a strict allowlist) is chosen deliberately: it
    runs reliably across kernel/CPython versions without risking killing the
    interpreter on a syscall we forgot to permit, while still confining the
    player away from the genuinely dangerous calls. The trade-off (an
    allowlist would be stricter) is discussed in the report.
    """
    prog = []
    # A = seccomp_data.arch  (offset 4)
    prog.append(_stmt(BPF_LD | BPF_W | BPF_ABS, 4))
    # if arch == x86_64 -> skip the next (kill) instruction; else kill.
    prog.append(_jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0))
    prog.append(_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS))
    # A = seccomp_data.nr  (offset 0)
    prog.append(_stmt(BPF_LD | BPF_W | BPF_ABS, 0))
    # For each blocked nr: if A == nr -> fall to RET KILL; else skip it.
    for nr in sorted(set(BLOCKED.values())):
        prog.append(_jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1))
        prog.append(_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS))
    # default: allow
    prog.append(_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))
    return prog


def apply_seccomp():
    """Install the seccomp-BPF filter on this process (and descendants)."""
    libc = ctypes.CDLL("libc.so.6", use_errno=True)

    # Required so an unprivileged process may install a filter.
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")

    instrs = build_filter()
    arr = (SockFilter * len(instrs))(*instrs)
    prog = SockFprog(len(instrs), arr)
    rc = libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
                    ctypes.byref(prog), 0, 0)
    if rc != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_SECCOMP failed")
    sys.stderr.write("[sandbox] seccomp filter installed "
                     "(%d dangerous syscalls blocked)\n" % len(BLOCKED))


# ===========================================================================
# built-in attack victims (for testing the isolation)
# ===========================================================================

def victim_cpuhog():
    sys.stderr.write("[victim] cpuhog: busy-looping forever\n")
    x = 0
    while True:
        x = (x * 1103515245 + 12345) & 0x7fffffff


def victim_memhog():
    sys.stderr.write("[victim] memhog: allocating until killed\n")
    blobs = []
    while True:
        blobs.append(bytearray(10 * 1024 * 1024))   # 10 MB at a time
        for b in blobs[-1:]:
            b[::4096] = b"\x01" * len(b[::4096])     # touch pages (commit)


def victim_forkbomb():
    sys.stderr.write("[victim] forkbomb: forking aggressively\n")
    n = 0
    while True:
        try:
            pid = os.fork()
        except OSError as e:
            sys.stderr.write("[victim] fork blocked after %d: %s\n" % (n, e))
            # keep the survivors around briefly so the cap is observable
            import time
            time.sleep(5)
            os._exit(0)
        if pid == 0:
            import time
            time.sleep(30)      # child lingers to hold a pid slot
            os._exit(0)
        n += 1


def victim_execshell():
    sys.stderr.write("[victim] execshell: trying to exec /bin/sh "
                     "(seccomp should kill us now)\n")
    sys.stderr.flush()
    os.execv("/bin/sh", ["/bin/sh", "-c", "echo ESCAPED > /tmp/escaped.txt"])
    sys.stderr.write("[victim] execv returned -- NOT blocked!\n")


def victim_ptrace():
    sys.stderr.write("[victim] ptrace: trying ptrace(PTRACE_TRACEME) "
                     "(seccomp should kill us now)\n")
    sys.stderr.flush()
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.syscall(101, 0, 0, 0, 0)       # ptrace == 101 on x86_64
    sys.stderr.write("[victim] ptrace returned -- NOT blocked!\n")


VICTIMS = {
    "cpuhog": victim_cpuhog, "memhog": victim_memhog,
    "forkbomb": victim_forkbomb, "execshell": victim_execshell,
    "ptrace": victim_ptrace,
}


# ===========================================================================
# entry point
# ===========================================================================

def run_client(sock, name):
    """Run the real game client in-process (no execve)."""
    sys.argv = ["cultclient.py"]
    if sock:
        sys.argv.append(sock)
    if name:
        sys.argv.append(name)
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import cultclient
    cultclient.main()


def main():
    ap = argparse.ArgumentParser(description="Run a Cult player under "
                                             "cgroup + seccomp isolation.")
    ap.add_argument("--sock", default=None, help="server socket path")
    ap.add_argument("--name", default=None, help="player display name")
    ap.add_argument("--cpu", type=float, default=20.0, help="CPU %% cap")
    ap.add_argument("--mem", type=float, default=128.0, help="memory MB cap")
    ap.add_argument("--pids", type=int, default=64, help="max processes")
    ap.add_argument("--no-cgroup", action="store_true", help="skip cgroup")
    ap.add_argument("--no-seccomp", action="store_true", help="skip seccomp")
    ap.add_argument("--victim", choices=sorted(VICTIMS),
                    help="run a built-in attack instead of the client")
    args = ap.parse_args()

    # 1) resource isolation
    if not args.no_cgroup:
        apply_cgroup(args.cpu, args.mem, args.pids)

    # 2) syscall isolation (must be AFTER any cgroup setup that may fork)
    if not args.no_seccomp:
        try:
            apply_seccomp()
        except OSError as e:
            sys.stderr.write("[sandbox] seccomp unavailable: %s\n" % e)

    # 3) run the protected workload
    if args.victim:
        VICTIMS[args.victim]()
    else:
        run_client(args.sock, args.name)


if __name__ == "__main__":
    main()
