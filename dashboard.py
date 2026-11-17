"""SecureChat server dashboard: runs ChatServer in a background thread and shows its state.

    python dashboard.py [--host 0.0.0.0] [--port 5555] [--plain]

The server knows nothing about this GUI. It pushes event dicts onto a
queue.Queue; this window drains the queue every 100 ms on the main thread.
"""

import argparse
import os
import queue
import sys
import time
from tkinter import ttk

import customtkinter as ctk

from net import human_size
from server import DEFAULT_CERT, DEFAULT_KEY, DEFAULT_USERS, ChatServer

BG = "#14161b"
PANEL = "#1c1f26"
PANEL_2 = "#232731"
BORDER = "#2e3340"
TEXT = "#e8eaee"
MUTED = "#9aa1ad"
ACCENT = "#3b82f6"
GREEN = "#22c55e"
RED = "#ef4444"
AMBER = "#f59e0b"

LOCK = "🔒" if sys.platform != "linux" or os.environ.get("SECURECHAT_EMOJI") == "1" else "■"

LOG_COLORS = {"join": GREEN, "leave": AMBER, "auth": RED, "tls": RED, "error": RED,
              "file": ACCENT, "dm": "#a78bfa", "msg": TEXT, "start": GREEN, "stop": AMBER}


def fmt_uptime(sec):
    sec = int(sec)
    return f"{sec // 3600:02d}:{sec % 3600 // 60:02d}:{sec % 60:02d}"


class Dashboard(ctk.CTk):
    def __init__(self, args):
        super().__init__(fg_color=BG)
        self.title("SecureChat Server Dashboard")
        self.geometry("1280x800")
        self.minsize(1000, 640)
        self.events = queue.Queue()
        self.transfers = {}     # id -> widgets
        self.f = {
            "title": ctk.CTkFont(size=24, weight="bold"),
            "head": ctk.CTkFont(size=16, weight="bold"),
            "body": ctk.CTkFont(size=15),
            "small": ctk.CTkFont(size=14),
            "stat": ctk.CTkFont(size=28, weight="bold"),
        }
        self._build()
        self.server = ChatServer(args.host, args.port, args.cert, args.key, args.users,
                                 use_tls=not args.plain, events=self.events)
        try:
            self.server.start_background()
        except FileNotFoundError:
            self._fatal(f"Certificate not found: {args.cert}\nRun:  python gen_cert.py")
        except Exception as e:
            self._fatal(f"Cannot start server on {args.host}:{args.port}\n{e}")
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.after(100, self.poll)
        self.after(1000, self.tick)

    # ------------------------------------------------------------ layout

    def _panel(self, title, row, col, colspan=1):
        p = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=12, border_width=1, border_color=BORDER)
        p.grid(row=row, column=col, columnspan=colspan, sticky="nsew", padx=8, pady=8)
        p.grid_columnconfigure(0, weight=1)
        p.grid_rowconfigure(1, weight=1)
        lbl = ctk.CTkLabel(p, text=title, font=self.f["head"], text_color=MUTED)
        lbl.grid(row=0, column=0, sticky="w", padx=16, pady=(12, 6))
        return p, lbl

    def _build(self):
        self.grid_columnconfigure(0, weight=3)
        self.grid_columnconfigure(1, weight=2)
        self.grid_rowconfigure(2, weight=3)
        self.grid_rowconfigure(3, weight=2)

        # Header
        head = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=0)
        head.grid(row=0, column=0, columnspan=2, sticky="ew")
        ctk.CTkLabel(head, text="SecureChat Server", font=self.f["title"], text_color=TEXT).pack(
            side="left", padx=(20, 24), pady=14)
        self.listen_lbl = ctk.CTkLabel(head, text="Starting…", font=self.f["head"], text_color=TEXT)
        self.listen_lbl.pack(side="left", padx=10)
        self.tls_lbl = ctk.CTkLabel(head, text="", font=self.f["head"], text_color=GREEN)
        self.tls_lbl.pack(side="left", padx=10)
        self.uptime_lbl = ctk.CTkLabel(head, text="Uptime 00:00:00", font=self.f["head"], text_color=MUTED)
        self.uptime_lbl.pack(side="right", padx=20)

        # Stats tiles
        stats = ctk.CTkFrame(self, fg_color="transparent")
        stats.grid(row=1, column=0, columnspan=2, sticky="ew", padx=8, pady=(8, 0))
        self.stat_lbls = {}
        for i, (key, label) in enumerate([("clients", "Clients online"), ("messages", "Messages routed"),
                                          ("bytes", "Bytes relayed"), ("files", "Files completed")]):
            stats.grid_columnconfigure(i, weight=1)
            tile = ctk.CTkFrame(stats, fg_color=PANEL, corner_radius=12, border_width=1, border_color=BORDER)
            tile.grid(row=0, column=i, sticky="ew", padx=8)
            v = ctk.CTkLabel(tile, text="0", font=self.f["stat"], text_color=TEXT)
            v.pack(anchor="w", padx=16, pady=(10, 0))
            ctk.CTkLabel(tile, text=label, font=self.f["small"], text_color=MUTED).pack(
                anchor="w", padx=16, pady=(0, 10))
            self.stat_lbls[key] = v

        # Connected clients table
        p, self.clients_title = self._panel("CONNECTED CLIENTS (0)", 2, 0)
        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("Dash.Treeview", background=PANEL, fieldbackground=PANEL, foreground=TEXT,
                        rowheight=34, font=("TkDefaultFont", 14), borderwidth=0)
        style.configure("Dash.Treeview.Heading", background=PANEL_2, foreground=MUTED,
                        font=("TkDefaultFont", 14, "bold"), relief="flat", padding=6)
        style.map("Dash.Treeview", background=[("selected", ACCENT)])
        style.map("Dash.Treeview.Heading", background=[("active", BORDER)])
        cols = ("user", "addr", "since", "tls", "cipher")
        self.table = ttk.Treeview(p, columns=cols, show="headings", style="Dash.Treeview")
        for c, title, w in zip(cols, ("Username", "IP:port", "Since", "TLS", "Cipher"),
                               (130, 180, 110, 100, 280)):
            self.table.heading(c, text=title, anchor="w")
            self.table.column(c, width=w, anchor="w", stretch=True)
        self.table.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))

        # Active transfers
        p, _ = self._panel("ACTIVE TRANSFERS", 2, 1)
        self.transfer_box = ctk.CTkScrollableFrame(p, fg_color=PANEL, corner_radius=0)
        self.transfer_box.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 10))
        self.transfer_box.grid_columnconfigure(0, weight=1)
        self.no_transfers = ctk.CTkLabel(self.transfer_box, text="No active transfers", font=self.f["small"],
                                         text_color=MUTED)
        self.no_transfers.grid(row=0, column=0, pady=20)

        # Event log
        p, _ = self._panel("EVENT LOG  (metadata only - message text is never logged)", 3, 0, colspan=2)
        self.log = ctk.CTkTextbox(p, font=ctk.CTkFont(family="Courier", size=14), fg_color=BG,
                                  text_color=TEXT, wrap="word")
        self.log.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))
        for kind, color in LOG_COLORS.items():
            self.log.tag_config(kind, foreground=color)
        self.log.tag_config("ts", foreground=MUTED)
        self.log.configure(state="disabled")

    def _fatal(self, text):
        self.listen_lbl.configure(text="NOT RUNNING", text_color=RED)
        self.add_log(time.strftime("%H:%M:%S"), "error", text)

    # ------------------------------------------------------------ updates

    def add_log(self, ts, kind, text):
        self.log.configure(state="normal")
        self.log.insert("end", f"{ts}  ", "ts")
        self.log.insert("end", f"{kind.upper():<6} ", kind if kind in LOG_COLORS else None)
        self.log.insert("end", text + "\n")
        if int(self.log.index("end-1c").split(".")[0]) > 2000:
            self.log.delete("1.0", "200.0")
        self.log.see("end")
        self.log.configure(state="disabled")

    def refresh_clients_title(self):
        n = len(self.table.get_children())
        self.clients_title.configure(text=f"CONNECTED CLIENTS ({n})")
        self.stat_lbls["clients"].configure(text=str(n))

    def add_transfer(self, e):
        self.no_transfers.grid_remove()
        row = ctk.CTkFrame(self.transfer_box, fg_color=PANEL_2, corner_radius=10)
        row.grid(row=len(self.transfers) + 1, column=0, sticky="ew", pady=4, padx=4)
        row.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(row, text=f"{e['src']}  →  {e['dst']}", font=self.f["head"], text_color=TEXT).grid(
            row=0, column=0, sticky="w", padx=12, pady=(8, 0))
        ctk.CTkLabel(row, text=f"{e['name']}  ·  {human_size(e['size'])}", font=self.f["small"],
                     text_color=MUTED).grid(row=1, column=0, sticky="w", padx=12)
        bar = ctk.CTkProgressBar(row, height=10)
        bar.set(0)
        bar.grid(row=2, column=0, sticky="ew", padx=12, pady=(4, 2))
        status = ctk.CTkLabel(row, text="Waiting for receiver to accept…", font=self.f["small"],
                              text_color=MUTED)
        status.grid(row=3, column=0, sticky="w", padx=12, pady=(0, 8))
        self.transfers[e["id"]] = {"row": row, "bar": bar, "status": status}

    def finish_transfer(self, fid, state):
        t = self.transfers.get(fid)
        if not t:
            return
        ok = state == "done"
        t["bar"].configure(progress_color=GREEN if ok else RED)
        if ok:
            t["bar"].set(1)
        t["status"].configure(text={"done": "Relayed ✔ (receiver verifies SHA-256)", "rejected": "Rejected",
                                    "cancelled": "Cancelled"}.get(state, state),
                              text_color=GREEN if ok else RED)

        def remove():
            w = self.transfers.pop(fid, None)
            if w:
                w["row"].destroy()
            if not self.transfers:
                self.no_transfers.grid()
        self.after(6000, remove)

    def handle(self, e):
        ev = e["event"]
        if ev == "log":
            self.add_log(e["ts"], e["kind"], e["text"])
        elif ev == "server_started":
            self.listen_lbl.configure(text=f"Listening on {e['host']}:{e['port']}", text_color=TEXT)
            if e["tls"]:
                self.tls_lbl.configure(text=f"{LOCK} TLS enabled  ·  cert CN={e['cn']}", text_color=GREEN)
            else:
                self.tls_lbl.configure(text="⚠ PLAINTEXT MODE - no encryption", text_color=RED)
        elif ev == "client_joined":
            if self.table.exists(e["user"]):
                self.table.delete(e["user"])
            self.table.insert("", "end", iid=e["user"], values=(
                e["user"], e["addr"], time.strftime("%H:%M:%S", time.localtime(e["since"])),
                e["tls_version"], e["cipher"]))
            self.refresh_clients_title()
        elif ev == "client_left":
            if self.table.exists(e["user"]):
                self.table.delete(e["user"])
            self.refresh_clients_title()
        elif ev == "transfer_started":
            self.add_transfer(e)
        elif ev == "transfer_progress":
            t = self.transfers.get(e["id"])
            if t:
                frac = e["done"] / e["size"] if e["size"] else 1
                t["bar"].set(frac)
                t["status"].configure(text=f"Relaying… {frac * 100:.0f}%  ({human_size(e['done'])})",
                                      text_color=MUTED)
        elif ev == "transfer_finished":
            self.finish_transfer(e["id"], e["status"])

    def poll(self):
        for _ in range(500):
            try:
                e = self.events.get_nowait()
            except queue.Empty:
                break
            try:
                self.handle(e)
            except Exception as ex:
                print("dashboard error:", repr(ex), file=sys.stderr)
        s = self.server.stats
        self.stat_lbls["messages"].configure(text=f"{s['messages']:,}")
        self.stat_lbls["bytes"].configure(text=human_size(s["bytes"]))
        self.stat_lbls["files"].configure(text=str(s["files"]))
        self.after(100, self.poll)

    def tick(self):
        if self.server.started_at:
            self.uptime_lbl.configure(text=f"Uptime {fmt_uptime(time.time() - self.server.started_at)}")
        self.after(1000, self.tick)

    def on_close(self):
        self.server.stop()
        self.destroy()


def main():
    p = argparse.ArgumentParser(description="SecureChat server with dashboard")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=5555)
    p.add_argument("--cert", default=str(DEFAULT_CERT))
    p.add_argument("--key", default=str(DEFAULT_KEY))
    p.add_argument("--users", default=str(DEFAULT_USERS))
    p.add_argument("--plain", action="store_true", help="disable TLS (Wireshark comparison)")
    args = p.parse_args()
    ctk.set_appearance_mode("dark")
    Dashboard(args).mainloop()


if __name__ == "__main__":
    main()
