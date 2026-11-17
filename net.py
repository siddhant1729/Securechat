"""ChatConnection: the networking core shared by client.py (CLI) and gui_client.py.

It owns the TLS socket and a receiver thread. Every incoming frame (plus a few
synthetic events, listed below) is pushed onto `self.inbox`, a queue.Queue.
The UI only reads that queue, so no UI code ever runs on the network thread.

File chunks are handled here, not by the UI: they are written to disk on the
receiver thread and only throttled progress events reach the inbox. That keeps
the GUI responsive during big transfers.

Synthetic inbox events (not on the wire):
  {"type": "file_offered",  "id"}                       our offer was sent
  {"type": "file_progress", "id", "done", "total", "direction": "send"|"recv"}
  {"type": "file_sent",     "id"}                       last chunk + file_end sent
  {"type": "file_done",     "id", "ok", "path", "expected", "actual", "reason"}
  {"type": "file_failed",   "id", "reason"}             local error (I/O, bad chunk)
  {"type": "conn_lost"}                                 socket died unexpectedly
"""

import base64
import hashlib
import os
import queue
import socket
import ssl
import threading
import time
import uuid
from pathlib import Path

from protocol import CHUNK_SIZE, ProtocolError, recv_msg, send_msg

BASE = Path(__file__).resolve().parent
DEFAULT_CA = BASE / "certs" / "server.crt"
DEFAULT_DOWNLOADS = BASE / "downloads"


class ConnectError(Exception):
    """Connection or login failed; str(e) is a short, user-facing reason."""


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def safe_filename(name):
    name = os.path.basename(str(name).replace("\\", "/")).strip().lstrip(".")
    name = "".join(c for c in name if c not in '<>:"|?*\0' and ord(c) >= 32)
    return name[:150] or "file"


def unique_path(folder, name):
    folder.mkdir(parents=True, exist_ok=True)
    p = folder / name
    stem, suffix = p.stem, p.suffix
    i = 1
    while p.exists() or p.with_name(p.name + ".part").exists():
        p = folder / f"{stem} ({i}){suffix}"
        i += 1
    return p


class ChatConnection:
    def __init__(self, host, port, cafile=DEFAULT_CA, use_tls=True,
                 download_dir=DEFAULT_DOWNLOADS, corrupt_test=False):
        self.host, self.port = host, int(port)
        self.cafile = cafile
        self.use_tls = use_tls
        self.download_dir = Path(download_dir)
        self.corrupt_test = corrupt_test     # T6: flip a byte in the first chunk we send

        self.inbox = queue.Queue()
        self.username = None
        self.tls_version = None
        self.cipher = None
        self.cert_verified = False

        self._sock = None
        self._send_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._closing = False
        self._outgoing = {}     # id -> {"path", "to", "name", "size", "sha256", "cancel": Event}
        self._incoming = {}     # id -> {"offer", "file", "part", "final", "received", "seq", "last"}

    # ---------------------------------------------------------------- connect / close

    def connect(self, username, password, mode="login", timeout=10.0):
        """Open TCP, do the TLS handshake (FR8), authenticate. Raises ConnectError."""
        try:
            raw = socket.create_connection((self.host, self.port), timeout=timeout)
        except socket.timeout:
            raise ConnectError(f"Timed out connecting to {self.host}:{self.port}") from None
        except ConnectionRefusedError:
            raise ConnectError("Connection refused - is the server running?") from None
        except socket.gaierror:
            raise ConnectError(f"Unknown host '{self.host}'") from None
        except OSError as e:
            raise ConnectError(f"Cannot reach server: {e.strerror or e}") from None

        sock = raw
        if self.use_tls:
            try:
                # cafile = our bundled server.crt: the ONLY certificate we trust (pinning).
                # The system CA store is not loaded, so no other cert can impersonate the server.
                ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(self.cafile))
            except (FileNotFoundError, ssl.SSLError) as e:
                raw.close()
                raise ConnectError(f"Cannot load CA certificate {self.cafile}: {e}") from None
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.verify_mode = ssl.CERT_REQUIRED
            # Hostname check off so the demo works by LAN IP with a CN=localhost cert.
            # Safe here because the trust store contains exactly one pinned certificate.
            ctx.check_hostname = False
            try:
                sock = ctx.wrap_socket(raw, server_hostname=self.host)
            except ssl.SSLCertVerificationError:
                raw.close()
                raise ConnectError("Certificate verification failed") from None
            except (ssl.SSLError, OSError) as e:
                raw.close()
                raise ConnectError(f"TLS handshake failed: {getattr(e, 'reason', None) or e}") from None
            self.tls_version = sock.version()
            self.cipher = sock.cipher()[0]
            self.cert_verified = True

        try:
            send_msg(sock, {"type": "auth", "user": username, "pass": password, "mode": mode})
            reply = recv_msg(sock)
        except socket.timeout:
            sock.close()
            raise ConnectError("Server did not answer the login request") from None
        except (OSError, ProtocolError) as e:
            sock.close()
            raise ConnectError(f"Connection error during login: {e}") from None
        if reply is None:
            sock.close()
            raise ConnectError("Server closed the connection")
        if reply.get("type") != "auth_ok":
            sock.close()
            raise ConnectError(reply.get("reason") or "Login failed")

        sock.settimeout(None)
        self._sock = sock
        self.username = reply.get("user", username)
        # No users request needed: the server pushes the list to everyone (us included) on join.
        threading.Thread(target=self._recv_loop, daemon=True, name="receiver").start()

    def close(self):
        self._closing = True
        with self._state_lock:
            outgoing = list(self._outgoing.values())
        for o in outgoing:
            o["cancel"].set()
        if self._sock:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self._sock.close()
            except OSError:
                pass

    @property
    def connected(self):
        return self._sock is not None and not self._closing

    # ---------------------------------------------------------------- sending

    def _send(self, obj):
        """Thread-safe send. Returns False if the socket is dead (receiver thread reports it)."""
        if self._sock is None:
            return False
        try:
            with self._send_lock:
                send_msg(self._sock, obj)
            return True
        except (OSError, ProtocolError):
            return False

    def send_text(self, text):
        return self._send({"type": "msg", "text": text})

    def send_dm(self, to, text):
        return self._send({"type": "dm", "to": to, "text": text})

    def request_users(self):
        return self._send({"type": "users"})

    def offer_file(self, to, path):
        """Start offering a file. Returns the transfer id at once; hashing runs in the background."""
        path = Path(path)
        fid = uuid.uuid4().hex
        size = path.stat().st_size
        with self._state_lock:
            self._outgoing[fid] = {"path": path, "to": to, "name": path.name, "size": size,
                                   "sha256": None, "cancel": threading.Event()}
        threading.Thread(target=self._hash_and_offer, args=(fid,), daemon=True).start()
        return fid

    def _hash_and_offer(self, fid):
        out = self._outgoing.get(fid)
        try:
            out["sha256"] = sha256_file(out["path"])
        except OSError as e:
            self._drop_outgoing(fid)
            self.inbox.put({"type": "file_failed", "id": fid, "reason": f"Cannot read file: {e}"})
            return
        if out["cancel"].is_set():
            return
        self._send({"type": "file_offer", "to": out["to"], "name": out["name"], "size": out["size"],
                    "sha256": out["sha256"], "id": fid})
        self.inbox.put({"type": "file_offered", "id": fid, "sha256": out["sha256"]})

    def accept_file(self, fid):
        with self._state_lock:
            inc = self._incoming.get(fid)
            if inc is None or inc["file"] is not None:
                return False
            final = unique_path(self.download_dir, safe_filename(inc["offer"]["name"]))
            part = final.with_name(final.name + ".part")
            try:
                inc["file"] = open(part, "wb")
            except OSError as e:
                self._incoming.pop(fid, None)
                self.inbox.put({"type": "file_failed", "id": fid, "reason": f"Cannot write file: {e}"})
                self._send({"type": "file_cancel", "id": fid, "reason": "receiver could not save file"})
                return False
            inc.update(part=part, final=final, hash=hashlib.sha256())
        return self._send({"type": "file_accept", "id": fid})

    def reject_file(self, fid):
        with self._state_lock:
            self._incoming.pop(fid, None)
        return self._send({"type": "file_reject", "id": fid})

    def cancel_file(self, fid, reason="cancelled"):
        self._drop_outgoing(fid)
        self._drop_incoming(fid)
        return self._send({"type": "file_cancel", "id": fid, "reason": reason})

    def _send_file(self, fid):
        out = self._outgoing.get(fid)
        if out is None:
            return
        total, sent, seq, last = out["size"], 0, 0, 0.0
        try:
            with open(out["path"], "rb") as f:
                while not out["cancel"].is_set():
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    if self.corrupt_test and seq == 0:
                        chunk = bytes([chunk[0] ^ 0xFF]) + chunk[1:]
                    ok = self._send({"type": "file_chunk", "id": fid, "seq": seq,
                                     "data": base64.b64encode(chunk).decode("ascii")})
                    if not ok:
                        return          # connection died; receiver thread reports conn_lost
                    seq += 1
                    sent += len(chunk)
                    now = time.monotonic()
                    if now - last > 0.1 or sent == total:
                        last = now
                        self.inbox.put({"type": "file_progress", "id": fid, "done": sent,
                                        "total": total, "direction": "send"})
        except OSError as e:
            self._drop_outgoing(fid)
            self._send({"type": "file_cancel", "id": fid, "reason": "sender could not read file"})
            self.inbox.put({"type": "file_failed", "id": fid, "reason": f"Read error: {e}"})
            return
        if out["cancel"].is_set():
            return
        self._send({"type": "file_end", "id": fid})
        self._drop_outgoing(fid)
        self.inbox.put({"type": "file_progress", "id": fid, "done": total, "total": total, "direction": "send"})
        self.inbox.put({"type": "file_sent", "id": fid})

    # ---------------------------------------------------------------- receiving (FR9)

    def _recv_loop(self):
        try:
            while True:
                msg = recv_msg(self._sock)
                if msg is None:
                    break
                self._dispatch(msg)
        except (OSError, ProtocolError, ValueError):
            pass
        finally:
            for fid in list(self._incoming):
                self._drop_incoming(fid)
            with self._state_lock:
                for o in self._outgoing.values():
                    o["cancel"].set()
                self._outgoing.clear()
            if not self._closing:
                self.inbox.put({"type": "conn_lost"})

    def _dispatch(self, msg):
        t = msg["type"]
        fid = msg.get("id")
        if t == "file_chunk":
            self._on_chunk(msg)
            return
        if t == "file_end":
            self._on_file_end(fid)
            return
        if t == "file_offer":
            with self._state_lock:
                self._incoming[fid] = {"offer": msg, "file": None, "received": 0, "seq": 0, "last": 0.0}
        elif t == "file_accept":
            if fid in self._outgoing:
                threading.Thread(target=self._send_file, args=(fid,), daemon=True, name="file-send").start()
        elif t == "file_reject":
            self._drop_outgoing(fid)
        elif t == "file_cancel":
            self._drop_outgoing(fid)
            self._drop_incoming(fid)
        self.inbox.put(msg)

    def _fail_incoming(self, fid, reason):
        self._drop_incoming(fid)
        self._send({"type": "file_cancel", "id": fid, "reason": f"receiver error: {reason}"})
        self.inbox.put({"type": "file_failed", "id": fid, "reason": reason})

    def _on_chunk(self, msg):
        fid = msg.get("id")
        inc = self._incoming.get(fid)
        if inc is None or inc["file"] is None:
            return
        if msg.get("seq") != inc["seq"]:
            self._fail_incoming(fid, f"chunk out of order (got {msg.get('seq')}, expected {inc['seq']})")
            return
        try:
            data = base64.b64decode(msg.get("data", ""), validate=True)
            inc["file"].write(data)
        except (ValueError, OSError) as e:
            self._fail_incoming(fid, f"bad chunk: {e}")
            return
        inc["seq"] += 1
        inc["received"] += len(data)
        total = inc["offer"]["size"]
        now = time.monotonic()
        if now - inc["last"] > 0.1 or inc["received"] >= total:
            inc["last"] = now
            self.inbox.put({"type": "file_progress", "id": fid, "done": inc["received"],
                            "total": total, "direction": "recv"})

    def _on_file_end(self, fid):
        """FR11: re-hash what actually landed on disk and compare with the offer."""
        with self._state_lock:
            inc = self._incoming.pop(fid, None)
        if inc is None or inc["file"] is None:
            return
        offer = inc["offer"]
        try:
            inc["file"].close()
            actual = sha256_file(inc["part"])
        except OSError as e:
            self.inbox.put({"type": "file_failed", "id": fid, "reason": str(e)})
            return
        expected = offer["sha256"]
        ok = actual == expected and inc["received"] == offer["size"]
        result = {"type": "file_done", "id": fid, "ok": ok, "expected": expected, "actual": actual,
                  "name": offer["name"], "from": offer.get("from"), "path": None, "reason": ""}
        if ok:
            os.replace(inc["part"], inc["final"])
            result["path"] = str(inc["final"])
        else:
            result["reason"] = ("size mismatch" if inc["received"] != offer["size"] else "SHA-256 mismatch")
            try:
                os.remove(inc["part"])      # never keep a file that failed verification
            except OSError:
                pass
        self.inbox.put(result)

    # ---------------------------------------------------------------- bookkeeping

    def _drop_outgoing(self, fid):
        with self._state_lock:
            out = self._outgoing.pop(fid, None)
        if out:
            out["cancel"].set()

    def _drop_incoming(self, fid):
        with self._state_lock:
            inc = self._incoming.pop(fid, None)
        if inc and inc["file"] is not None:
            try:
                inc["file"].close()
                os.remove(inc["part"])
            except OSError:
                pass

    def incoming_offer(self, fid):
        inc = self._incoming.get(fid)
        return inc["offer"] if inc else None

    def outgoing_info(self, fid):
        return self._outgoing.get(fid)
