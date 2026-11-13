#!/bin/bash
# install.sh [numPlayers]   --  The Cult, Project 2/3 (hardened + sandboxed)
#
#   sudo ./install.sh 6
#
# Sets up the cultmaster user, the player users, the 'cult' group that gates
# the socket, the UID allowlist, and the delegated cgroup parent for the
# isolation sandbox.
#
# After install:
#   * start the server:   sudo -u cultmaster bash -c 'cd /home/cultmaster && python3 cultserver.py'
#   * start a player (sandboxed):
#         sudo -u player0 python3 /home/player0/cultsandbox.py \
#              --sock /home/cultmaster/cult.sock --name player0

set -u
NUM="${1:-6}"

# 0. A dedicated group that is allowed to reach the 0660 game socket.
getent group cult >/dev/null || sudo groupadd cult

# 1. Create the cultmaster user (owns the server, socket, and logs).
sudo adduser --disabled-password --gecos "" cultmaster

# 2. Copy the whole game into cultmaster's home.
sudo cp -r ./* /home/cultmaster/
sudo mkdir -p /home/cultmaster/log

# 3. Ownership + permissions.
sudo chown -R cultmaster:cultmaster /home/cultmaster
#    Home is group 'cult' + setgid (2711): traversable by players so they can
#    reach the socket by name, and the setgid bit makes the socket cultmaster
#    creates inside inherit group 'cult' (so 0660 + group cult lets players
#    connect, while the directory itself still cannot be listed by them).
sudo chgrp cult /home/cultmaster
sudo chmod 2711 /home/cultmaster

#    Master/public logs stay private to cultmaster.
sudo chmod 700 /home/cultmaster/log
sudo chmod 700 /home/cultmaster/cultserver.py
sudo chmod 644 /home/cultmaster/cultconfig

# 4. Create the player users (each added to the 'cult' group) and give them
#    the client + comms library + the sandbox launcher.
cd /home/cultmaster
sudo python3 makeplayers.py "$NUM"

# 5. Write the UID allowlist of the expected player accounts.
sudo rm -f /home/cultmaster/allowed_uids
for i in $(seq 0 $((NUM-1))); do
    id -u "player$i" | sudo tee -a /home/cultmaster/allowed_uids >/dev/null
done
sudo chown cultmaster:cultmaster /home/cultmaster/allowed_uids
sudo chmod 644 /home/cultmaster/allowed_uids

# 6. Prepare the delegated cgroup parent for the sandbox (cgroup v2).
sudo bash /home/cultmaster/setup_cgroups.sh || \
    echo "NOTE: cgroup setup skipped/failed; sandbox will run seccomp-only."

echo
echo "Install complete with $NUM players."
echo "Start the server: sudo -u cultmaster bash -c 'cd /home/cultmaster && python3 cultserver.py'"
echo "Start a player  : sudo -u player0 python3 /home/player0/cultsandbox.py --sock /home/cultmaster/cult.sock --name player0"
