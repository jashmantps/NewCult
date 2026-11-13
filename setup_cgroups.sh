#!/bin/bash
# setup_cgroups.sh  --  prepare the delegated cgroup v2 parent for the sandbox.
#
# Run as root on a cgroup-v2 host (Ubuntu 26.04 is pure cgroup v2).
# cgroup settings do NOT survive a reboot, so re-run this after each boot
# (install.sh calls it once for you).
#
#   sudo ./setup_cgroups.sh
#
# What it does:
#   * creates the parent control group /sys/fs/cgroup/cult
#   * enables the cpu, memory and pids controllers for its children
#   * delegates it to the 'cult' group so unprivileged players may create
#     their own capped sub-cgroup via cultsandbox.py

set -u
CG=/sys/fs/cgroup/cult

if [ ! -f /sys/fs/cgroup/cgroup.controllers ]; then
    echo "ERROR: this host is not using cgroup v2 (no unified hierarchy)." >&2
    echo "The sandbox needs cgroup v2; on older hosts boot with "          >&2
    echo "systemd.unified_cgroup_hierarchy=1." >&2
    exit 1
fi

getent group cult >/dev/null || groupadd cult

mkdir -p "$CG"

# Make the controllers available to children of the root and of /cult.
echo "+cpu +memory +pids" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true
echo "+cpu +memory +pids" > "$CG/cgroup.subtree_control" 2>/dev/null || true

# Delegate /cult to the 'cult' group: group members may create sub-cgroups
# and move their own processes in (standard cgroup-v2 delegation).
chgrp cult "$CG" "$CG/cgroup.procs" "$CG/cgroup.subtree_control" 2>/dev/null || true
chmod 2775 "$CG"                       # g+rwx + setgid so children inherit grp
chmod g+w "$CG/cgroup.procs" "$CG/cgroup.subtree_control" 2>/dev/null || true

echo "cgroup parent ready at $CG"
echo "  controllers: $(cat "$CG/cgroup.controllers" 2>/dev/null)"
