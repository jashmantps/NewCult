#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# plot.py  --  render the Project 2/3 result figures from CSV data.
#
#   fig_dos.png   : server responsiveness under attack, old vs hardened
#                   (from dos_results.csv -- collected by the DoS harness)
#   fig_cpu.png   : CPU% of a busy player, capped vs uncapped
#   fig_mem.png   : memory of a memory-bomb player vs the cgroup cap
#   fig_pids.png  : fork-bomb processes vs the pids cap
#                   (cpu/mem/pids from measure.py's CSVs -- run on the VM)
#
# Usage:  python3 plot.py <data_dir> <out_dir>
# ---------------------------------------------------------------------------

import os
import sys
import csv

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

DATA = sys.argv[1] if len(sys.argv) > 1 else "."
OUT = sys.argv[2] if len(sys.argv) > 2 else "."

PURPLE = "#5b1a8a"
RED = "#c0392b"
GREEN = "#2e7d32"
GREY = "#888888"


def _load(name):
    path = os.path.join(DATA, name)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return list(csv.reader(f))


def plot_dos():
    rows = _load("dos_results.csv")
    if not rows:
        return
    # header: attack,library,before_answered,before_total,during_answered,during_total,avg_rtt_ms
    data = {}
    for r in rows[1:]:
        attack, lib = r[0], r[1]
        pct = 100.0 * float(r[4]) / float(r[5]) if float(r[5]) else 0.0
        data.setdefault(attack, {})[lib] = pct
    attacks = list(data.keys())
    x = range(len(attacks))
    w = 0.35
    orig = [data[a].get("original", 0) for a in attacks]
    hard = [data[a].get("hardened", 0) for a in attacks]
    fig, ax = plt.subplots(figsize=(6, 3.6))
    ax.bar([i - w / 2 for i in x], orig, w, label="Project 1 (blocking)",
           color=RED)
    ax.bar([i + w / 2 for i in x], hard, w, label="Project 2/3 (hardened)",
           color=GREEN)
    ax.set_xticks(list(x))
    ax.set_xticklabels([a.replace("_", "\n") for a in attacks])
    ax.set_ylabel("% of pings answered\nduring the attack")
    ax.set_ylim(0, 105)
    ax.set_title("Server stays responsive under a malicious client")
    ax.legend(fontsize=8)
    for i in x:
        ax.text(i - w / 2, orig[i] + 2, "%.0f%%" % orig[i], ha="center", fontsize=8)
        ax.text(i + w / 2, hard[i] + 2, "%.0f%%" % hard[i], ha="center", fontsize=8)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "fig_dos.png"), dpi=140)
    plt.close(fig)
    print("wrote fig_dos.png")


def plot_cpu():
    rows = _load("cpu.csv")
    if not rows:
        return
    # header: t_s,capped_cpu_pct,uncapped_cpu_pct
    t = [int(r[0]) for r in rows[1:] if r[0]]
    capped = [float(r[1]) for r in rows[1:] if r[1] not in ("", None)]
    unc = [float(r[2]) for r in rows[1:] if r[2] not in ("", None)]
    fig, ax = plt.subplots(figsize=(6, 3.6))
    ax.plot(range(1, len(unc) + 1), unc, "-o", color=RED,
            label="no sandbox (busy loop)")
    ax.plot(range(1, len(capped) + 1), capped, "-o", color=GREEN,
            label="sandboxed (cpu.max = 20%)")
    ax.axhline(20, ls="--", color=GREY, lw=1)
    ax.text(0.5, 23, "20% cap", color=GREY, fontsize=8)
    ax.set_xlabel("time (s)")
    ax.set_ylabel("CPU usage (%)")
    ax.set_ylim(0, 110)
    ax.set_title("cgroup cpu.max caps a busy player")
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "fig_cpu.png"), dpi=140)
    plt.close(fig)
    print("wrote fig_cpu.png")


def plot_mem():
    rows = _load("mem.csv")
    if not rows:
        return
    # header: t_s,capped_mem_mb,cap_mb
    t = [float(r[0]) for r in rows[1:]]
    mb = [float(r[1]) for r in rows[1:]]
    cap = float(rows[1][2]) if len(rows) > 1 else 0
    fig, ax = plt.subplots(figsize=(6, 3.6))
    ax.plot(t, mb, "-o", color=PURPLE, label="player memory.current")
    ax.axhline(cap, ls="--", color=RED, lw=1)
    ax.text(t[0] if t else 0, cap + 2, "memory.max = %d MB (OOM-kill)" % cap,
            color=RED, fontsize=8)
    ax.set_xlabel("time (s)")
    ax.set_ylabel("resident memory (MB)")
    ax.set_title("cgroup memory.max contains a memory bomb")
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "fig_mem.png"), dpi=140)
    plt.close(fig)
    print("wrote fig_mem.png")


def plot_pids():
    rows = _load("pids.csv")
    if not rows:
        return
    # header: pids_max,pids_peak_observed
    pmax = rows[1][0]
    peak = int(rows[1][1])
    fig, ax = plt.subplots(figsize=(4.5, 3.6))
    ax.bar(["pids.max\n(cap)", "peak live\n(fork bomb)"],
           [int(pmax), peak], color=[GREY, GREEN])
    ax.set_ylabel("processes")
    ax.set_title("cgroup pids.max stops a fork bomb")
    for i, v in enumerate([int(pmax), peak]):
        ax.text(i, v + 0.3, str(v), ha="center", fontsize=9)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "fig_pids.png"), dpi=140)
    plt.close(fig)
    print("wrote fig_pids.png")


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    plot_dos()
    plot_cpu()
    plot_mem()
    plot_pids()
