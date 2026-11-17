"""SecureChat command-line client (for debugging; the demo uses gui_client.py).

    python client.py [--host 127.0.0.1] [--port 5555] [--user alice] [--register] [--plain]

Commands:
    <text>                  broadcast to everyone
    /dm <user> <text>       private message
    /users                  list online users
    /send <user> <path>     offer a file
    /accept <id>            accept an offer (the short id shown is enough)
    /reject <id>            reject an offer
    /quit                   disconnect
"""

import argparse
import getpass
import sys
import threading
import time

from net import DEFAULT_CA, DEFAULT_DOWNLOADS, ChatConnection, ConnectError, human_size

HELP = __doc__.split("Commands:")[1]


def ts(t=None):
    return time.strftime("%H:%M", time.localtime(t or time.time()))


class CLI:
    def __init__(self, conn):
        self.conn = conn
        self.offers = {}         # full id -> offer
        self.lock = threading.Lock()
        self.running = True

    def out(self, line):
        # Reprint the prompt so incoming messages don't mangle what the user is typing.
        with self.lock:
            sys.stdout.write(f"\r\033[K{line}\n> ")
            sys.stdout.flush()

    def resolve(self, short):
        matches = [f for f in self.offers if f.startswith(short)]
        return matches[0] if len(matches) == 1 else None

    def printer(self):
        while self.running:
            m = self.conn.inbox.get()
            t = m["type"]
            if t == "msg":
                self.out(f"[{ts(m.get('ts'))}] {m['from']}: {m['text']}")
            elif t == "dm":
                self.out(f"[{ts(m.get('ts'))}] (DM) {m['from']}: {m['text']}")
            elif t == "sys":
                self.out(f"*** {m['text']}")
            elif t == "users":
                self.out(f"Online ({len(m['list'])}): {', '.join(m['list'])}")
            elif t == "file_offer":
                self.offers[m["id"]] = m
                self.out(f"📄 {m['from']} wants to send '{m['name']}' ({human_size(m['size'])}). "
                         f"/accept {m['id'][:8]}  or  /reject {m['id'][:8]}")
            elif t == "file_offered":
                self.out(f"Offer {m['id'][:8]} sent, waiting for the receiver…")
            elif t == "file_accept":
                self.out(f"{m.get('from', 'Receiver')} accepted {m['id'][:8]}, sending…")
            elif t == "file_reject":
                self.out(f"{m.get('from', 'Receiver')} rejected {m['id'][:8]}")
            elif t == "file_cancel":
                self.out(f"Transfer {m['id'][:8]} cancelled: {m.get('reason', '')}")
            elif t == "file_progress":
                pct = m["done"] * 100 // m["total"] if m["total"] else 100
                if pct in (25, 50, 75) or m["done"] == m["total"]:
                    self.out(f"  {m['id'][:8]} {m['direction']} {pct}%")
            elif t == "file_sent":
                self.out(f"Transfer {m['id'][:8]} sent ✓")
            elif t == "file_done":
                if m["ok"]:
                    self.out(f"✅ '{m['name']}' SHA-256 verified, saved to {m['path']}")
                else:
                    self.out(f"❌ '{m['name']}' integrity check FAILED ({m['reason']})\n"
                             f"   expected {m['expected']}\n   actual   {m['actual']}")
            elif t == "file_failed":
                self.out(f"❌ Transfer {m['id'][:8]} failed: {m['reason']}")
            elif t == "conn_lost":
                self.out("!!! Connection lost. Press Enter to exit.")
                self.running = False

    def run(self):
        threading.Thread(target=self.printer, daemon=True).start()
        self.out(f"Logged in as {self.conn.username}. Type /help for commands.")
        while self.running:
            try:
                line = input().strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not self.running:
                break
            if not line:
                sys.stdout.write("> ")
                sys.stdout.flush()
                continue
            if not line.startswith("/"):
                self.conn.send_text(line)
                self.out(f"[{ts()}] you: {line}")
                continue
            cmd, *rest = line.split(" ", 2)
            if cmd == "/quit":
                break
            elif cmd == "/help":
                self.out(HELP)
            elif cmd == "/users":
                self.conn.request_users()
            elif cmd == "/dm" and len(rest) == 2:
                self.conn.send_dm(rest[0], rest[1])
                self.out(f"[{ts()}] (DM to {rest[0]}) you: {rest[1]}")
            elif cmd == "/send" and len(rest) == 2:
                try:
                    fid = self.conn.offer_file(rest[0], rest[1].strip('"'))
                    self.out(f"Hashing '{rest[1]}' (id {fid[:8]})…")
                except OSError as e:
                    self.out(f"Cannot open file: {e}")
            elif cmd in ("/accept", "/reject") and len(rest) == 1:
                fid = self.resolve(rest[0])
                if not fid:
                    self.out("No such offer id")
                elif cmd == "/accept":
                    self.conn.accept_file(fid)
                    self.out(f"Accepted, downloading to {self.conn.download_dir}/")
                else:
                    self.conn.reject_file(fid)
                    self.offers.pop(fid, None)
            else:
                self.out("Unknown command. Type /help")
        self.running = False
        self.conn.close()


def main():
    p = argparse.ArgumentParser(description="SecureChat CLI client")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5555)
    p.add_argument("--user")
    p.add_argument("--password", help="(insecure, for scripts) otherwise you are prompted")
    p.add_argument("--register", action="store_true", help="create the account first")
    p.add_argument("--cafile", default=str(DEFAULT_CA), help="trusted server certificate")
    p.add_argument("--plain", action="store_true", help="no TLS (Wireshark comparison only)")
    p.add_argument("--downloads", default=str(DEFAULT_DOWNLOADS))
    p.add_argument("--corrupt-test", action="store_true", help="T6: corrupt the first chunk of files you send")
    a = p.parse_args()

    user = a.user or input("Username: ").strip()
    password = a.password if a.password is not None else getpass.getpass("Password: ")
    conn = ChatConnection(a.host, a.port, cafile=a.cafile, use_tls=not a.plain,
                          download_dir=a.downloads, corrupt_test=a.corrupt_test)
    try:
        conn.connect(user, password, mode="register" if a.register else "login")
    except ConnectError as e:
        raise SystemExit(f"Error: {e}")
    if conn.use_tls:
        print(f"🔒 {conn.tls_version} · {conn.cipher} · cert verified")
    else:
        print("⚠  PLAINTEXT connection - everything is visible on the wire")
    CLI(conn).run()


if __name__ == "__main__":
    main()
