"""End-to-end tests for the PRD test cases. Run:  python -m unittest discover -s tests -v

Each test starts a real TLS server on a free port and connects real ChatConnection
clients to it over loopback, so this covers the full stack (TLS, framing, auth, relay).
"""

import os
import queue
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from net import ChatConnection, ConnectError, sha256_file  # noqa: E402
from protocol import recv_exact, recv_msg, send_msg  # noqa: E402
from server import ChatServer  # noqa: E402

CERT = ROOT / "certs" / "server.crt"
KEY = ROOT / "certs" / "server.key"


def wait_for(inbox, pred, timeout=10.0):
    """Pop inbox items until pred(item) is true; return that item (skipping others)."""
    end = time.monotonic() + timeout
    while True:
        left = end - time.monotonic()
        if left <= 0:
            raise AssertionError("timed out waiting for event")
        item = inbox.get(timeout=left)
        if pred(item):
            return item


class Base(unittest.TestCase):
    use_tls = True

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.events = queue.Queue()
        self.server = ChatServer("127.0.0.1", 0, CERT, KEY, self.dir / "users.json",
                                 use_tls=self.use_tls, events=self.events, verbose=False)
        self.server.start_background()
        self.conns = []

    def tearDown(self):
        for c in self.conns:
            c.close()
        self.server.stop()
        self.tmp.cleanup()

    def client(self, user, mode="register", password="secret", **kw):
        kw.setdefault("download_dir", self.dir / f"dl_{user}")
        c = ChatConnection("127.0.0.1", self.server.port, cafile=CERT, use_tls=self.use_tls, **kw)
        c.connect(user, password, mode=mode)
        self.conns.append(c)
        return c

    def make_file(self, name, size):
        p = self.dir / name
        with open(p, "wb") as f:
            f.write(os.urandom(size))
        return p

    def transfer(self, sender, receiver, path):
        fid = sender.offer_file(receiver.username, path)
        offer = wait_for(receiver.inbox, lambda m: m["type"] == "file_offer")
        self.assertEqual(offer["id"], fid)
        receiver.accept_file(fid)
        return fid, wait_for(receiver.inbox, lambda m: m["type"] in ("file_done", "file_failed"), timeout=60)


class TestFraming(unittest.TestCase):
    def test_split_and_merged_frames(self):
        a, b = socket.socketpair()
        send_msg(a, {"type": "x", "n": 1})
        send_msg(a, {"type": "x", "n": 2})          # two frames back to back -> merged on the wire
        self.assertEqual(recv_msg(b)["n"], 1)
        self.assertEqual(recv_msg(b)["n"], 2)
        # A frame dribbled in one byte at a time must still decode.
        import json, struct
        body = json.dumps({"type": "y", "s": "hello"}).encode()
        data = struct.pack(">I", len(body)) + body
        t = threading.Thread(target=lambda: [a.send(data[i:i + 1]) or time.sleep(0.001) for i in range(len(data))])
        t.start()
        self.assertEqual(recv_msg(b)["s"], "hello")
        t.join()
        a.close()
        self.assertIsNone(recv_msg(b))
        b.close()


class TestChat(Base):
    def test_tls_details(self):
        a = self.client("alice")
        self.assertIn(a.tls_version, ("TLSv1.2", "TLSv1.3"))
        self.assertTrue(a.cipher)
        self.assertTrue(a.cert_verified)

    def test_T1_broadcast_order(self):
        names = ["alice", "bob", "charlie"]
        cs = [self.client(n) for n in names]
        time.sleep(0.2)
        N = 30
        threads = [threading.Thread(target=lambda c=c: [c.send_text(f"{c.username}-{i}") for i in range(N)])
                   for c in cs]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        for c in cs:
            got = {}
            while sum(len(v) for v in got.values()) < 2 * N:
                m = wait_for(c.inbox, lambda m: m["type"] == "msg")
                got.setdefault(m["from"], []).append(m["text"])
            for sender, texts in got.items():
                self.assertNotEqual(sender, c.username)
                self.assertEqual(texts, [f"{sender}-{i}" for i in range(N)])   # in order per sender

    def test_dm_and_T2_offline(self):
        a, b, c = self.client("alice"), self.client("bob"), self.client("charlie")
        a.send_dm("bob", "psst")
        m = wait_for(b.inbox, lambda m: m["type"] == "dm")
        self.assertEqual((m["from"], m["text"]), ("alice", "psst"))
        a.send_dm("ghost", "hello?")
        m = wait_for(a.inbox, lambda m: m["type"] == "sys" and m.get("error"))
        self.assertIn("not online", m["text"])
        time.sleep(0.2)
        self.assertFalse(any(x["type"] == "dm" for x in list(c.inbox.queue)))   # charlie saw nothing

    def test_users_and_join_leave(self):
        a = self.client("alice")
        b = self.client("bob")
        wait_for(a.inbox, lambda m: m["type"] == "sys" and m.get("event") == "join" and m["user"] == "bob")
        m = wait_for(a.inbox, lambda m: m["type"] == "users" and len(m["list"]) == 2)
        self.assertEqual(m["list"], ["alice", "bob"])
        b.close()
        wait_for(a.inbox, lambda m: m["type"] == "sys" and m.get("event") == "leave" and m["user"] == "bob")

    def test_T3_duplicate_login(self):
        self.client("alice")
        with self.assertRaises(ConnectError) as cm:
            self.client("alice", mode="login")
        self.assertIn("already logged in", str(cm.exception))

    def test_T4_wrong_password_closes(self):
        self.client("alice").close()
        time.sleep(0.2)
        with self.assertRaises(ConnectError) as cm:
            self.client("alice", mode="login", password="WRONG")
        self.assertIn("Wrong username or password", str(cm.exception))
        ev = wait_for(self.events, lambda e: e["event"] == "auth_failed")
        self.assertEqual(ev["user"], "alice")
        # Raw check that the server really closes the socket after auth_fail.
        ctx = ssl.create_default_context(cafile=str(CERT))
        ctx.check_hostname = False
        with ctx.wrap_socket(socket.create_connection(("127.0.0.1", self.server.port))) as s:
            send_msg(s, {"type": "auth", "user": "alice", "pass": "nope", "mode": "login"})
            self.assertEqual(recv_msg(s)["type"], "auth_fail")
            s.settimeout(5)
            self.assertIsNone(recv_msg(s))

    def test_registration_rules(self):
        self.client("alice")
        with self.assertRaises(ConnectError):
            self.client("alice", mode="register")        # taken
        with self.assertRaises(ConnectError):
            self.client("bad name!", mode="register")

    def test_passwords_not_plaintext(self):
        self.client("alice", password="hunter22").close()
        self.assertNotIn("hunter22", (self.dir / "users.json").read_text())

    def test_server_overrides_spoofed_sender(self):
        a, b = self.client("alice"), self.client("bob")
        a._send({"type": "msg", "from": "bob", "text": "i am bob"})
        m = wait_for(b.inbox, lambda m: m["type"] == "msg")
        self.assertEqual(m["from"], "alice")

    def test_T5_file_transfer_verified(self):
        a, b = self.client("alice"), self.client("bob")
        src = self.make_file("notes.bin", 10 * 1024 * 1024 + 123)
        fid, done = self.transfer(a, b, src)
        self.assertEqual(done["type"], "file_done")
        self.assertTrue(done["ok"], done)
        self.assertEqual(sha256_file(done["path"]), sha256_file(src))
        wait_for(a.inbox, lambda m: m["type"] == "file_sent" and m["id"] == fid)
        self.assertEqual(self.server.stats["files"], 1)

    def test_empty_file(self):
        a, b = self.client("alice"), self.client("bob")
        _, done = self.transfer(a, b, self.make_file("empty.txt", 0))
        self.assertTrue(done["ok"])

    def test_T6_corrupt_chunk_detected(self):
        a, b = self.client("alice", corrupt_test=True), self.client("bob")
        _, done = self.transfer(a, b, self.make_file("x.bin", 300_000))
        self.assertFalse(done["ok"])
        self.assertNotEqual(done["expected"], done["actual"])
        self.assertEqual(list((self.dir / "dl_bob").glob("*")), [])   # bad file not kept

    def test_reject(self):
        a, b = self.client("alice"), self.client("bob")
        fid = a.offer_file("bob", self.make_file("r.bin", 1000))
        wait_for(b.inbox, lambda m: m["type"] == "file_offer")
        b.reject_file(fid)
        wait_for(a.inbox, lambda m: m["type"] == "file_reject" and m["id"] == fid)

    def test_offer_to_offline_user(self):
        a = self.client("alice")
        fid = a.offer_file("ghost", self.make_file("g.bin", 10))
        wait_for(a.inbox, lambda m: m["type"] == "file_cancel" and m["id"] == fid)

    def test_T7_sender_dies_mid_transfer(self):
        a, b, c = self.client("alice"), self.client("bob"), self.client("charlie")
        fid = a.offer_file("bob", self.make_file("big.bin", 40 * 1024 * 1024))
        wait_for(b.inbox, lambda m: m["type"] == "file_offer")
        b.accept_file(fid)
        wait_for(b.inbox, lambda m: m["type"] == "file_progress" and m["done"] > 0)
        a._closing = True
        a._sock.shutdown(socket.SHUT_RDWR)  # simulate a crash: socket dies, no goodbye frame
        m = wait_for(b.inbox, lambda m: m["type"] == "file_cancel" and m["id"] == fid)
        self.assertIn("disconnected", m["reason"])
        wait_for(b.inbox, lambda m: m["type"] == "sys" and "cancelled" in m["text"])
        # Server still works for everyone else.
        c.send_text("still alive?")
        self.assertEqual(wait_for(b.inbox, lambda m: m["type"] == "msg")["text"], "still alive?")
        self.assertEqual(list((self.dir / "dl_bob").glob("*")), [])   # partial file removed

    def test_chat_flows_during_big_transfer(self):
        """T10 core: chat keeps flowing while a large file is mid-transfer."""
        a, b, c = self.client("alice"), self.client("bob"), self.client("charlie")
        fid = a.offer_file("bob", self.make_file("big.bin", 50 * 1024 * 1024))
        wait_for(b.inbox, lambda m: m["type"] == "file_offer")
        b.accept_file(fid)
        wait_for(b.inbox, lambda m: m["type"] == "file_progress" and m["done"] > 0)
        t0 = time.monotonic()
        c.send_dm("bob", "ping")
        wait_for(b.inbox, lambda m: m["type"] == "dm")
        self.assertLess(time.monotonic() - t0, 2.0)
        done = wait_for(b.inbox, lambda m: m["type"] == "file_done", timeout=120)
        self.assertTrue(done["ok"])

    def test_T9_wrong_cert_rejected(self):
        other = self.dir / "other.crt"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout",
                        str(self.dir / "other.key"), "-out", str(other), "-days", "1",
                        "-subj", "/CN=localhost"], check=True, capture_output=True)
        c = ChatConnection("127.0.0.1", self.server.port, cafile=other)
        with self.assertRaises(ConnectError) as cm:
            c.connect("alice", "secret", mode="register")
        self.assertEqual(str(cm.exception), "Certificate verification failed")
        wait_for(self.events, lambda e: e["event"] == "tls_failed")

    def test_plain_client_cannot_talk_to_tls_server(self):
        c = ChatConnection("127.0.0.1", self.server.port, use_tls=False)
        with self.assertRaises(ConnectError):
            c.connect("alice", "secret", mode="register", timeout=3)

    def test_T11_server_stop_notifies_clients(self):
        a = self.client("alice")
        self.server.stop()
        wait_for(a.inbox, lambda m: m["type"] == "conn_lost")

    def test_garbage_does_not_crash_server(self):
        ctx = ssl.create_default_context(cafile=str(CERT))
        ctx.check_hostname = False
        with ctx.wrap_socket(socket.create_connection(("127.0.0.1", self.server.port))) as s:
            s.sendall(b"\xff\xff\xff\xffgarbage")
            s.settimeout(5)
            try:
                self.assertIsNone(recv_msg(s))
            except OSError:
                pass
        self.client("alice").send_text("fine")      # still serving

    def test_dashboard_events(self):
        a = self.client("alice")
        ev = wait_for(self.events, lambda e: e["event"] == "client_joined")
        self.assertEqual(ev["user"], "alice")
        self.assertIn(ev["tls_version"], ("TLSv1.2", "TLSv1.3"))
        a.close()
        wait_for(self.events, lambda e: e["event"] == "client_left")


class TestPlain(Base):
    use_tls = False

    def test_plain_mode_works(self):
        a, b = self.client("alice"), self.client("bob")
        a.send_text("visible on the wire")
        self.assertEqual(wait_for(b.inbox, lambda m: m["type"] == "msg")["text"], "visible on the wire")
        self.assertIsNone(a.tls_version)


if __name__ == "__main__":
    unittest.main()
