"""SecureChat server: TLS over TCP, one thread per client, relays chat and file frames.

Run standalone:   python server.py [--host 0.0.0.0] [--port 5555] [--plain]
Or via the GUI:   python dashboard.py

The server never imports GUI code. If given an `events` queue it pushes dicts
like {"event": "client_joined", ...} onto it; dashboard.py renders them.
"""

import argparse
import base64
import socket
import ssl
import threading
import time
from pathlib import Path

from auth import UserStore
from protocol import ProtocolError, recv_msg, send_msg

BASE = Path(__file__).resolve().parent
DEFAULT_CERT = BASE / "certs" / "server.crt"
DEFAULT_KEY = BASE / "certs" / "server.key"
DEFAULT_USERS = BASE / "users.json"

AUTH_TIMEOUT = 30          # FR2: must log in within 30 s
HANDSHAKE_TIMEOUT = 10
MAX_TEXT = 4000
MAX_FILE_SIZE = 4 * 1024 ** 3


def cert_common_name(certfile):
    """Read the CN out of a PEM cert using only the stdlib (best effort)."""
    try:
        info = ssl._ssl._test_decode_cert(str(certfile))   # private but stable since 3.x
        for rdn in info.get("subject", ()):
            for key, value in rdn:
                if key == "commonName":
                    return value
    except Exception:
        pass
    return "?"


def lan_ip():
    """Best guess at this machine's LAN address (no packets are actually sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


class ClientSession:
    """One connected socket. send() is thread-safe; any thread may route to this client."""

    def __init__(self, sock, addr):
        self.sock = sock
        self.addr = addr
        self.user = None
        self.since = time.time()
        self.tls_version = None
        self.cipher = None
        self.send_lock = threading.Lock()
        self.alive = True

    @property
    def addr_str(self):
        return f"{self.addr[0]}:{self.addr[1]}"

    def send(self, obj):
        """Send a frame; returns bytes written, or 0 if the client is gone."""
        if not self.alive:
            return 0
        try:
            with self.send_lock:
                return send_msg(self.sock, obj)
        except (OSError, ProtocolError):
            self.kill()
            return 0

    def kill(self):
        """Close the socket. The client's handler thread then sees EOF and cleans up."""
        self.alive = False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


class Transfer:
    def __init__(self, fid, sender, receiver, name, size):
        self.id = fid
        self.sender = sender
        self.receiver = receiver
        self.name = name
        self.size = size
        self.state = "offered"      # offered -> active -> (removed)
        self.relayed = 0
        self.last_pct = -1


class ChatServer:
    def __init__(self, host="0.0.0.0", port=5555, certfile=DEFAULT_CERT, keyfile=DEFAULT_KEY,
                 users_file=DEFAULT_USERS, use_tls=True, events=None, verbose=True):
        self.host, self.port = host, port
        self.certfile, self.keyfile = certfile, keyfile
        self.use_tls = use_tls
        self.events = events
        self.verbose = verbose
        self.users = UserStore(users_file)

        self.clients = {}                 # FR4: username -> ClientSession, guarded by clients_lock
        self.clients_lock = threading.Lock()
        self.transfers = {}               # file id -> Transfer, guarded by transfers_lock
        self.transfers_lock = threading.Lock()

        self.stats = {"messages": 0, "bytes": 0, "files": 0}
        self.stats_lock = threading.Lock()

        self.ssl_ctx = None
        self.cert_cn = None
        self._listener = None
        self._running = threading.Event()
        self.started_at = None

    # ---------------------------------------------------------------- plumbing

    def _emit(self, event, **data):
        if self.events is not None:
            data["event"] = event
            self.events.put(data)

    def log(self, kind, text):
        """FR7: log routing metadata (never message content)."""
        ts = time.strftime("%H:%M:%S")
        if self.verbose:
            print(f"[{ts}] {kind.upper():<6} {text}", flush=True)
        self._emit("log", ts=ts, kind=kind, text=text)

    def _count(self, messages=0, nbytes=0, files=0):
        with self.stats_lock:
            self.stats["messages"] += messages
            self.stats["bytes"] += nbytes
            self.stats["files"] += files

    def get(self, user):
        with self.clients_lock:
            return self.clients.get(user)

    def online(self):
        with self.clients_lock:
            return sorted(self.clients)

    def broadcast(self, obj, exclude=None):
        # Copy under the lock, send outside it: a slow client must not block joins/leaves.
        with self.clients_lock:
            targets = [c for u, c in self.clients.items() if u != exclude]
        total = 0
        for c in targets:
            total += c.send(obj)
        return total

    def send_to(self, client, obj):
        n = client.send(obj)
        self._count(nbytes=n)
        return n

    def sys(self, client, text, **extra):
        client.send({"type": "sys", "text": text, **extra})

    # ---------------------------------------------------------------- lifecycle

    def _make_ssl_context(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=str(self.certfile), keyfile=str(self.keyfile))
        return ctx

    def bind(self):
        """FR1: bind and listen. Raises on failure (bad cert, port in use)."""
        if self.use_tls:
            self.ssl_ctx = self._make_ssl_context()
            self.cert_cn = cert_common_name(self.certfile)
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(64)
        srv.settimeout(0.5)       # lets serve_forever notice stop() promptly on every OS
        self._listener = srv
        self.port = srv.getsockname()[1]
        self.started_at = time.time()
        self._running.set()
        shown = lan_ip() if self.host in ("0.0.0.0", "") else self.host
        self._emit("server_started", host=shown, port=self.port, tls=self.use_tls, cn=self.cert_cn)
        mode = f"TLS enabled (CN={self.cert_cn})" if self.use_tls else "PLAINTEXT - no encryption!"
        self.log("start", f"Listening on {shown}:{self.port} - {mode}")

    def serve_forever(self):
        while self._running.is_set():
            try:
                conn, addr = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            conn.settimeout(None)
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()

    def start_background(self):
        self.bind()
        t = threading.Thread(target=self.serve_forever, daemon=True, name="accept-loop")
        t.start()
        return t

    def stop(self):
        self._running.clear()
        if self._listener:
            try:
                self._listener.close()
            except OSError:
                pass
        with self.clients_lock:
            clients = list(self.clients.values())
        for c in clients:
            c.kill()
        self.log("stop", "Server stopped")

    # ---------------------------------------------------------------- per-client thread

    def _handle(self, raw, addr):
        sock = raw
        tag = f"{addr[0]}:{addr[1]}"
        if self.use_tls:
            # Handshake here, not in the accept loop, so one slow client can't stall everyone.
            try:
                raw.settimeout(HANDSHAKE_TIMEOUT)
                sock = self.ssl_ctx.wrap_socket(raw, server_side=True)
            except (ssl.SSLError, OSError) as e:
                reason = getattr(e, "reason", None) or str(e) or type(e).__name__
                self.log("tls", f"Handshake failed from {tag}: {reason}")
                self._emit("tls_failed", addr=tag, reason=reason)
                raw.close()
                return
        client = ClientSession(sock, addr)
        if self.use_tls:
            client.tls_version = sock.version()
            client.cipher = sock.cipher()[0]
        try:
            if not self._authenticate(client):
                client.kill()
                return
            sock.settimeout(None)
            self._on_join(client)
            while True:
                msg = recv_msg(sock)
                if msg is None:
                    break
                self._dispatch(client, msg)
        except (OSError, ProtocolError) as e:
            if client.alive and client.user:
                self.log("error", f"{client.user}: {type(e).__name__}: {e}")
        except Exception as e:      # FR6: a bug in one handler must never take the server down
            self.log("error", f"Unexpected error for {client.user or tag}: {e!r}")
        finally:
            client.kill()
            if client.user:
                self._on_leave(client)

    def _authenticate(self, client):
        """FR2/FR3: one auth attempt within AUTH_TIMEOUT; failure closes the connection (T4)."""
        client.sock.settimeout(AUTH_TIMEOUT)
        try:
            msg = recv_msg(client.sock)
        except socket.timeout:
            self.log("auth", f"{client.addr_str} did not authenticate within {AUTH_TIMEOUT}s")
            return False
        if msg is None:
            return False
        if msg.get("type") != "auth":
            client.send({"type": "auth_fail", "reason": "Expected auth frame"})
            return False

        user = str(msg.get("user", "")).strip()
        password = str(msg.get("pass", ""))
        mode = msg.get("mode", "login")

        if mode == "register":
            ok, reason = self.users.register(user, password)
            if ok:
                self.log("auth", f"New account registered: {user}")
        else:
            ok, reason = self.users.verify(user, password)
        if not ok:
            self.log("auth", f"Auth FAILED for '{user[:20]}' from {client.addr_str}: {reason}")
            self._emit("auth_failed", user=user[:20], addr=client.addr_str, reason=reason)
            client.send({"type": "auth_fail", "reason": reason})
            return False

        # Hold this client's send lock while it becomes visible, so auth_ok is
        # guaranteed to be the first frame it receives even if a broadcast races us.
        with client.send_lock:
            with self.clients_lock:
                if user in self.clients:
                    dup = True
                else:
                    dup = False
                    client.user = user
                    self.clients[user] = client
            if dup:
                send_msg(client.sock, {"type": "auth_fail", "reason": f"'{user}' is already logged in"})
                self.log("auth", f"Duplicate login rejected for {user} from {client.addr_str}")
                self._emit("auth_failed", user=user, addr=client.addr_str, reason="already online")
                return False
            send_msg(client.sock, {"type": "auth_ok", "user": user})
        return True

    def _on_join(self, client):
        u = client.user
        self.log("join", f"{u} connected from {client.addr_str}"
                 + (f" ({client.tls_version}, {client.cipher})" if self.use_tls else " (plain TCP)"))
        self._emit("client_joined", user=u, addr=client.addr_str, since=client.since,
                   tls_version=client.tls_version or "none", cipher=client.cipher or "none")
        self.broadcast({"type": "sys", "text": f"{u} joined", "event": "join", "user": u}, exclude=u)
        self.broadcast({"type": "users", "list": self.online()})

    def _on_leave(self, client):
        u = client.user
        with self.clients_lock:
            if self.clients.get(u) is client:
                del self.clients[u]
            else:
                return
        # Cancel any transfer this user was part of and tell the other side (T7).
        with self.transfers_lock:
            dead = [t for t in self.transfers.values() if u in (t.sender, t.receiver)]
            for t in dead:
                del self.transfers[t.id]
        for t in dead:
            other = self.get(t.receiver if t.sender == u else t.sender)
            if other:
                other.send({"type": "file_cancel", "id": t.id, "reason": f"{u} disconnected"})
                self.sys(other, f"Transfer of '{t.name}' cancelled: {u} disconnected", error=True)
            self._emit("transfer_finished", id=t.id, status="cancelled")
            self.log("file", f"Transfer {t.id[:8]} '{t.name}' cancelled ({u} disconnected)")
        self.log("leave", f"{u} disconnected")
        self._emit("client_left", user=u)
        self.broadcast({"type": "sys", "text": f"{u} left", "event": "leave", "user": u})
        self.broadcast({"type": "users", "list": self.online()})

    # ---------------------------------------------------------------- routing (FR5)

    def _dispatch(self, client, msg):
        routes = {
            "msg": self._on_msg, "dm": self._on_dm, "users": self._on_users,
            "file_offer": self._on_file_offer, "file_accept": self._on_file_accept,
            "file_reject": self._on_file_reject, "file_chunk": self._on_file_chunk,
            "file_end": self._on_file_end, "file_cancel": self._on_file_cancel,
        }
        handler = routes.get(msg["type"])
        if handler is None:
            self.sys(client, f"Unknown message type '{msg['type']}'", error=True)
            return
        handler(client, msg)

    def _on_msg(self, client, msg):
        text = msg.get("text")
        if not isinstance(text, str) or not text.strip():
            return
        text = text[:MAX_TEXT]
        n = self.broadcast({"type": "msg", "from": client.user, "text": text, "ts": time.time()},
                           exclude=client.user)
        self._count(messages=1, nbytes=n)
        self.log("msg", f"Broadcast from {client.user} ({len(text.encode())} bytes)")

    def _on_dm(self, client, msg):
        to, text = msg.get("to"), msg.get("text")
        if not isinstance(text, str) or not text.strip() or not isinstance(to, str):
            return
        target = self.get(to)
        if target is None:
            self.sys(client, f"{to} is not online", error=True, user=to)
            self.log("dm", f"DM {client.user} -> {to} failed: offline")
            return
        n = self.send_to(target, {"type": "dm", "from": client.user, "to": to,
                                  "text": text[:MAX_TEXT], "ts": time.time()})
        self._count(messages=1)
        self.log("dm", f"DM {client.user} -> {to} ({len(text.encode())} bytes)")
        self._emit("dm_routed", src=client.user, dst=to, size=n)

    def _on_users(self, client, msg):
        client.send({"type": "users", "list": self.online()})

    # --- file relay

    def _on_file_offer(self, client, msg):
        to, fid, name = msg.get("to"), msg.get("id"), msg.get("name")
        size, digest = msg.get("size"), msg.get("sha256")
        if not (isinstance(fid, str) and 0 < len(fid) <= 64 and isinstance(name, str) and name
                and isinstance(size, int) and 0 <= size <= MAX_FILE_SIZE
                and isinstance(digest, str) and len(digest) == 64 and isinstance(to, str)):
            self.sys(client, "Malformed file offer", error=True)
            return
        target = self.get(to)
        if target is None or to == client.user:
            client.send({"type": "file_cancel", "id": fid, "reason": f"{to} is not online"})
            self.sys(client, f"{to} is not online", error=True, user=to)
            return
        with self.transfers_lock:
            if fid in self.transfers:
                dup = True
            else:
                dup = False
                self.transfers[fid] = Transfer(fid, client.user, to, name, size)
        if dup:
            client.send({"type": "file_cancel", "id": fid, "reason": "Duplicate transfer id"})
            return
        self.send_to(target, {"type": "file_offer", "from": client.user, "to": to, "name": name,
                              "size": size, "sha256": digest, "id": fid})
        self.log("file", f"Offer {fid[:8]}: {client.user} -> {to} '{name}' ({size} bytes)")
        self._emit("transfer_started", id=fid, src=client.user, dst=to, name=name, size=size)

    def _transfer_for(self, fid, user, role):
        with self.transfers_lock:
            t = self.transfers.get(fid)
        if t is None or getattr(t, role) != user:
            return None
        return t

    def _on_file_accept(self, client, msg):
        t = self._transfer_for(msg.get("id"), client.user, "receiver")
        if t is None or t.state != "offered":
            return
        sender = self.get(t.sender)
        if sender is None:
            return
        t.state = "active"
        self.send_to(sender, {"type": "file_accept", "id": t.id, "from": client.user})
        self.log("file", f"{client.user} accepted {t.id[:8]} '{t.name}'")
        self._emit("transfer_progress", id=t.id, done=0, size=t.size, state="active")

    def _on_file_reject(self, client, msg):
        t = self._transfer_for(msg.get("id"), client.user, "receiver")
        if t is None:
            return
        with self.transfers_lock:
            self.transfers.pop(t.id, None)
        sender = self.get(t.sender)
        if sender:
            self.send_to(sender, {"type": "file_reject", "id": t.id, "from": client.user})
        self.log("file", f"{client.user} rejected {t.id[:8]} '{t.name}'")
        self._emit("transfer_finished", id=t.id, status="rejected")

    def _on_file_chunk(self, client, msg):
        t = self._transfer_for(msg.get("id"), client.user, "sender")
        if t is None or t.state != "active":
            return
        receiver = self.get(t.receiver)
        if receiver is None:
            return
        data = msg.get("data", "")
        if not isinstance(data, str):
            return
        # Relay immediately - never buffer the whole file on the server.
        self.send_to(receiver, {"type": "file_chunk", "id": t.id, "seq": msg.get("seq"), "data": data})
        t.relayed += len(data) * 3 // 4 - data[-2:].count("=")
        pct = int(t.relayed * 100 / t.size) if t.size else 100
        if pct != t.last_pct:
            t.last_pct = pct
            self._emit("transfer_progress", id=t.id, done=t.relayed, size=t.size, state="active")

    def _on_file_end(self, client, msg):
        t = self._transfer_for(msg.get("id"), client.user, "sender")
        if t is None:
            return
        with self.transfers_lock:
            self.transfers.pop(t.id, None)
        receiver = self.get(t.receiver)
        if receiver:
            self.send_to(receiver, {"type": "file_end", "id": t.id})
        self._count(files=1)
        self.log("file", f"Transfer {t.id[:8]} '{t.name}' relayed ({t.relayed} bytes) {t.sender} -> {t.receiver}")
        self._emit("transfer_finished", id=t.id, status="done")

    def _on_file_cancel(self, client, msg):
        fid = msg.get("id")
        with self.transfers_lock:
            t = self.transfers.get(fid)
            if t is None or client.user not in (t.sender, t.receiver):
                return
            del self.transfers[fid]
        other = self.get(t.receiver if client.user == t.sender else t.sender)
        reason = str(msg.get("reason") or f"cancelled by {client.user}")[:200]
        if other:
            other.send({"type": "file_cancel", "id": fid, "reason": reason})
        self.log("file", f"Transfer {fid[:8]} '{t.name}' cancelled by {client.user}")
        self._emit("transfer_finished", id=fid, status="cancelled")


def main():
    p = argparse.ArgumentParser(description="SecureChat server")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=5555)
    p.add_argument("--cert", default=str(DEFAULT_CERT))
    p.add_argument("--key", default=str(DEFAULT_KEY))
    p.add_argument("--users", default=str(DEFAULT_USERS))
    p.add_argument("--plain", action="store_true", help="disable TLS (for the Wireshark before/after demo)")
    a = p.parse_args()

    server = ChatServer(a.host, a.port, a.cert, a.key, a.users, use_tls=not a.plain)
    try:
        server.bind()
    except FileNotFoundError:
        raise SystemExit(f"Certificate not found ({a.cert}). Run: python gen_cert.py")
    except OSError as e:
        raise SystemExit(f"Cannot start server: {e}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()


if __name__ == "__main__":
    main()
