#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# cultnet.py  --  The Cult: communications library  (Project 2/3 hardened)
#
# Author: Abhishek Singh
# Course: CSE/CEN Advanced Operating Systems, ASU, Fall 2026
#
# This single file is the ENTIRE communications library for "The Cult".
# Both the game server (cultserver.py) and the player client (cultclient.py)
# import this module and talk to each other ONLY through the functions
# defined here. Nothing else in the project opens a socket or frames a
# message directly.
#
# Communications primitive
# -------------------------
# UNIX domain STREAM sockets (AF_UNIX, SOCK_STREAM) multiplexed in a single
# server process with an event loop built on the standard-library
# `selectors` module (which wraps epoll on Linux).
#
# ---------------------------------------------------------------------------
# WHAT CHANGED FOR PROJECT 2/3 (robustness + security hardening)
# ---------------------------------------------------------------------------
# Classmate feedback on the Project 1 version exposed three real problems in
# this file.  The fixes are all here:
#
#   1. BLOCKING READS IN THE EVENT LOOP (denial of service).
#      P1 set each accepted socket to BLOCKING and called a blocking
#      _recv_frame() straight from the selector loop.  A client that sent a
#      4-byte length prefix and then dribbled (or never sent) the body froze
#      the single server thread for EVERY player -- and a large length value
#      hung it outright.  P2/P3 makes every accepted socket NON-BLOCKING and
#      reads incrementally into a per-connection buffer, parsing whole frames
#      only when they have fully arrived.  One slow client can no longer
#      stall anyone else.
#
#   2. UNBOUNDED FRAMES / SLOWLORIS.
#      A declared length is now rejected if it exceeds MAX_FRAME (the
#      "large prefix hangs the server" bug), and a connection that holds a
#      partial frame longer than PARTIAL_TIMEOUT seconds is dropped.  The
#      outbound side is buffered and capped too, so a client that stops
#      reading cannot wedge the server's writes.
#
#   3. WEAK LOCAL AUTHORISATION.
#      P1 chmod'd the socket 0o777 (world-connectable) and only *recorded*
#      the peer UID without using it.  P2/P3 defaults the socket to 0o660
#      (so only the owning group may connect), and the server can enforce an
#      allowlist of expected player UIDs and a one-connection-per-UID rule.
#      Identity still comes from the kernel via SO_PEERCRED; now it is also
#      an access-control gate, not just a label.
#
# Message framing
# ---------------
# Every logical message is a JSON object sent as:
#       [ 4-byte big-endian unsigned length ][ UTF-8 JSON payload ]
#
# Public API (unchanged for the game layer)
# -----------------------------------------
#   SERVER SIDE (class CultServer):
#       CultServer(sock_path, allowed_uids=None, one_per_uid=False,
#                  sock_mode=0o660, max_frame=65536, out_max=1<<20,
#                  partial_timeout=10.0)
#       .poll(timeout)                 -- pump the event loop once
#       .send(cid, obj)                -- UNICAST one JSON obj to one player
#       .multicast(cids, obj)          -- MULTICAST to a subset of players
#       .broadcast(obj)                -- BROADCAST to every connected player
#       .peers()                       -- list of connected connection ids
#       .uid_of(cid)                   -- kernel-verified UID for a connection
#       .close()                       -- tear everything down
#
#   CLIENT SIDE (class CultClient):
#       CultClient(sock_path)          -- connect to the server
#       .send(obj) / .recv(timeout) / .close()
# ---------------------------------------------------------------------------

import os
import json
import time
import socket
import struct
import selectors

# SO_PEERCRED returns a `struct ucred { pid_t pid; uid_t uid; gid_t gid; }`;
# three native 32-bit ints on Linux.
_UCRED_FMT = "iii"
_UCRED_SIZE = struct.calcsize(_UCRED_FMT)

# Length prefix: 4-byte unsigned big-endian integer.
_LEN_FMT = "!I"
_LEN_SIZE = struct.calcsize(_LEN_FMT)

# Defaults for the hardening limits (overridable via CultServer kwargs).
DEFAULT_MAX_FRAME = 64 * 1024          # largest accepted single message
DEFAULT_OUT_MAX = 1 * 1024 * 1024      # largest per-client outbound backlog
DEFAULT_PARTIAL_TIMEOUT = 10.0         # seconds a half-sent frame may linger
_RECV_CHUNK = 65536


# ---------------------------------------------------------------------------
# Low-level framing helpers
# ---------------------------------------------------------------------------

def _encode(obj):
    """Serialise a Python object to a length-prefixed JSON frame (bytes)."""
    body = json.dumps(obj).encode("utf-8")
    return struct.pack(_LEN_FMT, len(body)) + body


def _peer_uid(sock):
    """Kernel-verified UID of the process on the other end (SO_PEERCRED)."""
    cred = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED_SIZE)
    _pid, uid, _gid = struct.unpack(_UCRED_FMT, cred)
    return uid


# ---- blocking helpers, used by the CLIENT side only -----------------------
# (The client is not the DoS target; a simple blocking reader is fine there.)

def _recv_exactly(sock, nbytes):
    chunks = []
    remaining = nbytes
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _recv_frame(sock, max_frame=DEFAULT_MAX_FRAME):
    header = _recv_exactly(sock, _LEN_SIZE)
    if header is None:
        return None
    (length,) = struct.unpack(_LEN_FMT, header)
    if length == 0 or length > max_frame:
        raise ValueError("bad frame length %d" % length)
    body = _recv_exactly(sock, length)
    if body is None:
        return None
    return json.loads(body.decode("utf-8"))


# ---------------------------------------------------------------------------
# Server side
# ---------------------------------------------------------------------------

class _Conn:
    """Per-connection state: socket, identity, and the I/O buffers."""
    __slots__ = ("sock", "cid", "uid", "inbuf", "outbuf",
                 "pending_since", "want_write")

    def __init__(self, sock, cid, uid):
        self.sock = sock
        self.cid = cid
        self.uid = uid
        self.inbuf = bytearray()       # bytes received, not yet framed
        self.outbuf = bytearray()      # bytes queued to send
        self.pending_since = 0.0       # when the current partial frame began
        self.want_write = False        # currently registered for EVENT_WRITE


class CultServer:
    """Non-blocking event-loop server for The Cult.

    One listening UNIX stream socket; every accepted client is registered
    with a selector and served without ever blocking the loop. Each
    connection has a unique integer id (cid) used for delivery and carries
    the kernel-supplied peer UID, which can also gate who may connect.
    """

    def __init__(self, sock_path, allowed_uids=None, one_per_uid=False,
                 sock_mode=0o660, max_frame=DEFAULT_MAX_FRAME,
                 out_max=DEFAULT_OUT_MAX,
                 partial_timeout=DEFAULT_PARTIAL_TIMEOUT):
        self.sock_path = sock_path
        # allowed_uids: iterable of UIDs permitted to connect, or None to
        # allow any UID (the kernel-verified identity is still recorded).
        self.allowed_uids = set(allowed_uids) if allowed_uids is not None else None
        self.one_per_uid = one_per_uid
        self.max_frame = max_frame
        self.out_max = out_max
        self.partial_timeout = partial_timeout

        try:
            os.unlink(sock_path)
        except FileNotFoundError:
            pass

        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(sock_path)
        self.listener.listen(128)
        self.listener.setblocking(False)

        # 0o660: only the socket's owner and group may connect. Combined with
        # a dedicated 'cult' group (set up by install.sh) this keeps random
        # local users off the socket; SO_PEERCRED then identifies who it is.
        try:
            os.chmod(sock_path, sock_mode)
        except OSError:
            pass

        self.sel = selectors.DefaultSelector()
        self.sel.register(self.listener, selectors.EVENT_READ, data=None)

        self._next_cid = 0
        self.conns = {}         # cid  -> _Conn
        self._by_sock = {}      # sock -> _Conn
        self._uid_conns = {}    # uid  -> cid (for one-per-uid enforcement)

    # -- addressing -----------------------------------------------------

    def peers(self):
        return list(self.conns.keys())

    def uid_of(self, cid):
        c = self.conns.get(cid)
        return c.uid if c else None

    # -- sending (buffered, never blocks the loop) ----------------------

    def send(self, cid, obj):
        """UNICAST: queue one JSON object for one connection."""
        c = self.conns.get(cid)
        if c is None:
            return False
        c.outbuf.extend(_encode(obj))
        # Drop a client whose backlog grows without bound (it isn't reading).
        if len(c.outbuf) > self.out_max:
            self._drop(c)
            return False
        self._flush(c)
        return True

    def multicast(self, cids, obj):
        frame = _encode(obj)
        for cid in list(cids):
            c = self.conns.get(cid)
            if c is None:
                continue
            c.outbuf.extend(frame)
            if len(c.outbuf) > self.out_max:
                self._drop(c)
                continue
            self._flush(c)

    def broadcast(self, obj):
        self.multicast(self.peers(), obj)

    def _flush(self, c):
        """Try to push as much of a connection's outbuf as the kernel takes."""
        while c.outbuf:
            try:
                n = c.sock.send(c.outbuf)
            except (BlockingIOError, InterruptedError):
                break                      # kernel buffer full; finish later
            except OSError:
                self._drop(c)
                return
            if n == 0:
                break
            del c.outbuf[:n]
        # Register/clear EVENT_WRITE depending on whether bytes remain.
        self._update_interest(c)

    def _update_interest(self, c):
        want_write = bool(c.outbuf)
        if want_write == c.want_write:
            return
        events = selectors.EVENT_READ
        if want_write:
            events |= selectors.EVENT_WRITE
        try:
            self.sel.modify(c.sock, events, data=c.cid)
            c.want_write = want_write
        except (KeyError, ValueError):
            pass

    # -- the event loop -------------------------------------------------

    def poll(self, timeout=0.2):
        """Pump the selector once and return a list of events.

            ('connect',    cid, uid)
            ('message',    cid, obj)
            ('disconnect', cid)
        """
        events = []
        for key, mask in self.sel.select(timeout=timeout):
            if key.data is None:
                self._accept(events)
                continue
            c = self._by_sock.get(key.fileobj)
            if c is None:
                continue
            if mask & selectors.EVENT_WRITE:
                self._flush(c)
            if mask & selectors.EVENT_READ:
                self._read(c, events)
        # Sweep out slowloris connections holding a half-sent frame too long.
        self._sweep_partial(events)
        return events

    def _accept(self, events):
        try:
            conn, _addr = self.listener.accept()
        except OSError:
            return
        uid = _peer_uid(conn)           # kernel-verified identity

        # --- access control gate (new in P2/P3) ---
        if self.allowed_uids is not None and uid not in self.allowed_uids:
            conn.close()                # not an expected player account
            return
        if self.one_per_uid and uid in self._uid_conns:
            # A player already has a live connection; reject the duplicate.
            # (This also makes stale-socket / double-connect handling clean.)
            conn.close()
            return

        conn.setblocking(False)         # NON-BLOCKING: never stall the loop
        cid = self._next_cid
        self._next_cid += 1
        c = _Conn(conn, cid, uid)
        self.conns[cid] = c
        self._by_sock[conn] = c
        if self.one_per_uid:
            self._uid_conns[uid] = cid
        self.sel.register(conn, selectors.EVENT_READ, data=cid)
        events.append(("connect", cid, uid))

    def _read(self, c, events):
        """Read available bytes (non-blocking) and parse any whole frames."""
        try:
            data = c.sock.recv(_RECV_CHUNK)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            self._drop(c)
            events.append(("disconnect", c.cid))
            return
        if not data:                    # clean EOF
            self._drop(c)
            events.append(("disconnect", c.cid))
            return

        c.inbuf.extend(data)
        # Extract every complete frame now sitting in the buffer.
        while True:
            if len(c.inbuf) < _LEN_SIZE:
                break
            (length,) = struct.unpack(_LEN_FMT, bytes(c.inbuf[:_LEN_SIZE]))
            # Oversized or zero length -> protocol violation -> drop the peer.
            if length == 0 or length > self.max_frame:
                self._drop(c)
                events.append(("disconnect", c.cid))
                return
            if len(c.inbuf) < _LEN_SIZE + length:
                break                   # body not fully here yet; wait
            body = bytes(c.inbuf[_LEN_SIZE:_LEN_SIZE + length])
            del c.inbuf[:_LEN_SIZE + length]
            try:
                obj = json.loads(body.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                self._drop(c)
                events.append(("disconnect", c.cid))
                return
            events.append(("message", c.cid, obj))

        # Track how long an incomplete frame has been pending (slowloris).
        c.pending_since = time.monotonic() if c.inbuf else 0.0

    def _sweep_partial(self, events):
        if self.partial_timeout <= 0:
            return
        now = time.monotonic()
        for c in list(self.conns.values()):
            if c.inbuf and c.pending_since and \
               (now - c.pending_since) > self.partial_timeout:
                self._drop(c)
                events.append(("disconnect", c.cid))

    def _drop(self, c):
        self.conns.pop(c.cid, None)
        self._by_sock.pop(c.sock, None)
        if self._uid_conns.get(c.uid) == c.cid:
            self._uid_conns.pop(c.uid, None)
        try:
            self.sel.unregister(c.sock)
        except (KeyError, ValueError):
            pass
        try:
            c.sock.close()
        except OSError:
            pass

    def close(self):
        for c in list(self.conns.values()):
            self._drop(c)
        try:
            self.sel.unregister(self.listener)
        except (KeyError, ValueError):
            pass
        try:
            self.listener.close()
        except OSError:
            pass
        try:
            os.unlink(self.sock_path)
        except FileNotFoundError:
            pass


# ---------------------------------------------------------------------------
# Client side (blocking is fine here: the client is not the DoS target)
# ---------------------------------------------------------------------------

class CultClient:
    """Thin client wrapper around one UNIX stream socket to the server."""

    def __init__(self, sock_path):
        self.sock_path = sock_path
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(sock_path)

    def send(self, obj):
        self.sock.sendall(_encode(obj))

    def recv(self, timeout=None):
        if timeout is not None:
            self.sock.settimeout(timeout)
            try:
                return _recv_frame(self.sock)
            except socket.timeout:
                return None
            finally:
                self.sock.settimeout(None)
        return _recv_frame(self.sock)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
