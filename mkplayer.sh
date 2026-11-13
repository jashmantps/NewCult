#!/bin/bash
# mkplayer.sh <N> <password>
# Create Linux user playerN, add it to the 'cult' group (so it may reach the
# 0660 game socket), and drop the client, comms library, and the isolation
# sandbox into its home. Each player is its own Linux user so the server can
# authenticate them by UID via SO_PEERCRED.

echo "setting up user: player$1"

# Create the user with a home directory and a bash shell.
sudo /usr/sbin/useradd -c "player$1" -m -k /dev/null -s /bin/bash "player$1"

# Set the password non-interactively.
echo "player$1:$2" | sudo chpasswd

# Allow this player to reach the game socket (group 'cult', mode 0660).
getent group cult >/dev/null || sudo groupadd cult
sudo usermod -aG cult "player$1"

# Give the player a private copy of the client, the comms library, and the
# sandbox launcher they use to join the game under isolation.
for f in cultclient.py cultnet.py cultsandbox.py; do
    sudo cp "$f" "/home/player$1/$f"
    sudo chown "player$1:player$1" "/home/player$1/$f"
    sudo chmod 700 "/home/player$1/$f"
done
