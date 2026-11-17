"""SecureChat desktop client (CustomTkinter). The demo frontend.

    python gui_client.py [--host 192.168.1.10] [--port 5555] [--user alice] [--plain] [--corrupt-test]

Threading rule: Tkinter is not thread-safe. Only the main thread touches widgets.
The network thread (inside net.ChatConnection) puts events on conn.inbox, and
the UI drains that queue every 50 ms with after().
"""

import argparse
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path
from tkinter import filedialog

import customtkinter as ctk

from net import DEFAULT_CA, DEFAULT_DOWNLOADS, ChatConnection, ConnectError, human_size

# ---------------------------------------------------------------- theme

BG = "#14161b"
PANEL = "#1c1f26"
PANEL_2 = "#232731"
BORDER = "#2e3340"
TEXT = "#e8eaee"
MUTED = "#9aa1ad"
ACCENT = "#3b82f6"
OWN_BUBBLE = "#2563eb"
OTHER_BUBBLE = "#2a2f3a"
GREEN = "#22c55e"
RED = "#ef4444"
AMBER = "#f59e0b"

# Some Linux Tk builds crash on colour-emoji fonts, so fall back to plain symbols there.
_EMOJI = sys.platform != "linux" or os.environ.get("SECURECHAT_EMOJI") == "1"
ICON = {
    "lock": "🔒" if _EMOJI else "■",
    "warn": "⚠",
    "file": "📄" if _EMOJI else "▤",
    "clip": "📎" if _EMOJI else "+",
    "ok": "✅" if _EMOJI else "✔",
    "bad": "❌" if _EMOJI else "✘",
    "power": "⏻" if _EMOJI else "",
    "dot": "●",
}


def hhmm(ts=None):
    return time.strftime("%H:%M", time.localtime(ts or time.time()))


def open_folder(path):
    path = str(path)
    try:
        if sys.platform.startswith("win"):
            os.startfile(path)                       # noqa: S606 - local folder only
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except OSError:
        pass


# ================================================================ login screen

class LoginView(ctk.CTkFrame):
    def __init__(self, app, args, error=""):
        super().__init__(app, fg_color=BG)
        self.app, self.args = app, args
        self.result_q = queue.Queue()
        f = app.fonts

        card = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=16, border_width=1, border_color=BORDER)
        card.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(card, text=f"{ICON['lock']}  SecureChat", font=f["title"], text_color=TEXT).pack(
            padx=48, pady=(36, 4))
        sub = "TLS-encrypted chat & file transfer" if not args.plain else "PLAIN TCP MODE - not encrypted"
        ctk.CTkLabel(card, text=sub, font=f["small"], text_color=MUTED if not args.plain else RED).pack(
            pady=(0, 20))

        self.mode = ctk.CTkSegmentedButton(card, values=["Login", "Register"], font=f["body"], height=36,
                                           command=self._mode_changed)
        self.mode.set("Login")
        self.mode.pack(padx=48, fill="x", pady=(0, 16))

        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(padx=48, fill="x")
        self.host = self._entry(row, "Server IP", args.host, width=230)
        self.host.grid(row=1, column=0, sticky="ew", padx=(0, 8))
        self.port = self._entry(row, "Port", str(args.port), width=90)
        self.port.grid(row=1, column=1, sticky="ew")
        ctk.CTkLabel(row, text="Server IP", font=f["small"], text_color=MUTED).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(row, text="Port", font=f["small"], text_color=MUTED).grid(row=0, column=1, sticky="w")

        self.user = self._labeled(card, "Username", args.user or "")
        self.pw = self._labeled(card, "Password", "", show="•")

        self.button = ctk.CTkButton(card, text="Connect", font=f["bold"], height=44, command=self.connect)
        self.button.pack(padx=48, pady=(22, 8), fill="x")
        self.spinner = ctk.CTkProgressBar(card, mode="indeterminate", height=4)
        self.status = ctk.CTkLabel(card, text=error, font=f["small"], text_color=RED, wraplength=330,
                                   justify="center")
        self.status.pack(padx=48, pady=(4, 28))

        for w in (self.host, self.port, self.user, self.pw):
            w.bind("<Return>", lambda e: self.connect())
        (self.pw if args.user else self.user).focus_set()

    def _entry(self, master, placeholder, value, show=None, width=330):
        e = ctk.CTkEntry(master, placeholder_text=placeholder, font=self.app.fonts["body"], height=40,
                         width=width, show=show)
        if value:
            e.insert(0, value)
        return e

    def _labeled(self, card, label, value, show=None):
        ctk.CTkLabel(card, text=label, font=self.app.fonts["small"], text_color=MUTED).pack(
            padx=48, anchor="w", pady=(12, 0))
        e = self._entry(card, label, value, show=show)
        e.pack(padx=48, fill="x")
        return e

    def _mode_changed(self, value):
        self.button.configure(text="Create account & connect" if value == "Register" else "Connect")

    def connect(self):
        if str(self.button.cget("state")) == "disabled":
            return
        host, user, pw = self.host.get().strip(), self.user.get().strip(), self.pw.get()
        try:
            port = int(self.port.get())
        except ValueError:
            self.status.configure(text="Port must be a number", text_color=RED)
            return
        if not host or not user or not pw:
            self.status.configure(text="Fill in server, username and password", text_color=RED)
            return
        mode = "register" if self.mode.get() == "Register" else "login"
        self.button.configure(state="disabled", text="Connecting…")
        self.status.configure(text="TLS handshake…" if not self.args.plain else "Connecting…",
                              text_color=MUTED)
        self.spinner.pack(padx=48, fill="x", before=self.status)
        self.spinner.start()

        conn = ChatConnection(host, port, cafile=self.args.cafile, use_tls=not self.args.plain,
                              download_dir=self.args.downloads, corrupt_test=self.args.corrupt_test)

        def work():
            try:
                conn.connect(user, pw, mode=mode)
                self.result_q.put(("ok", conn))
            except ConnectError as e:
                self.result_q.put(("err", str(e)))
            except Exception as e:  # never leave the spinner running forever
                self.result_q.put(("err", f"Unexpected error: {e}"))

        threading.Thread(target=work, daemon=True).start()
        self.after(50, self._check)

    def _check(self):
        try:
            kind, value = self.result_q.get_nowait()
        except queue.Empty:
            self.after(50, self._check)
            return
        self.spinner.stop()
        self.spinner.pack_forget()
        if kind == "ok":
            self.app.show_chat(value)
        else:
            self.button.configure(state="normal")
            self._mode_changed(self.mode.get())
            self.status.configure(text=value, text_color=RED)


# ================================================================ chat widgets

class Conversation:
    """One tab: '#everyone' or a DM with a single user."""

    def __init__(self, view, key, title):
        self.view, self.key, self.title = view, key, title
        self.unread = 0
        self.cards = set()
        self.frame = ctk.CTkScrollableFrame(view.conv_host, fg_color=BG, corner_radius=0)
        self.frame.grid_columnconfigure(0, weight=1)
        self.rows = 0

        f = view.app.fonts
        self.tab = ctk.CTkFrame(view.tabbar, fg_color=PANEL_2, corner_radius=8)
        self.tab.pack(side="left", padx=(0, 6), pady=6)
        self.btn = ctk.CTkButton(self.tab, text=title, font=f["body"], height=34, corner_radius=8,
                                 fg_color="transparent", hover_color=BORDER, text_color=TEXT,
                                 command=lambda: view.select(key))
        self.btn.pack(side="left")
        if key != "#everyone":
            ctk.CTkButton(self.tab, text="✕", width=30, height=34, font=f["body"], corner_radius=8,
                          fg_color="transparent", hover_color=RED, text_color=MUTED,
                          command=lambda: view.close_conv(key)).pack(side="left")

    def refresh_tab(self, active):
        label = self.title + (f"  {ICON['dot']} {self.unread}" if self.unread and not active else "")
        self.tab.configure(fg_color=ACCENT if active else PANEL_2)
        self.btn.configure(text=label, text_color="white" if active else (AMBER if self.unread else TEXT))

    def add(self, widget, sticky="ew", pady=4):
        widget.grid(row=self.rows, column=0, sticky=sticky, padx=14, pady=pady)
        self.rows += 1
        self.view.after(30, self.scroll_bottom)

    def scroll_bottom(self):
        try:
            self.frame.update_idletasks()
            self.frame._parent_canvas.yview_moveto(1.0)
        except Exception:
            pass

    def destroy(self):
        self.frame.destroy()
        self.tab.destroy()


class FileCard(ctk.CTkFrame):
    """Shows one transfer: name, size, progress, status, and buttons."""

    def __init__(self, conv, fid, name, size, outgoing, peer):
        super().__init__(conv.frame, fg_color=PANEL_2, corner_radius=12, border_width=1, border_color=BORDER)
        self.view, self.fid, self.outgoing, self.peer = conv.view, fid, outgoing, peer
        f = self.view.app.fonts
        caption = f"You → {peer}" if outgoing else f"{peer} → you"
        ctk.CTkLabel(self, text=f"{caption}  ·  {hhmm()}", font=f["small"], text_color=MUTED).pack(
            anchor="w", padx=14, pady=(10, 0))
        ctk.CTkLabel(self, text=f"{ICON['file']}  {name}   {human_size(size)}", font=f["bold"],
                     text_color=TEXT, wraplength=380, justify="left").pack(anchor="w", padx=14, pady=(2, 6))
        self.bar = ctk.CTkProgressBar(self, height=10, progress_color=ACCENT)
        self.bar.set(0)
        self.bar.pack(fill="x", padx=14)
        self.status = ctk.CTkLabel(self, text="", font=f["small"], text_color=MUTED, wraplength=380,
                                   justify="left")
        self.status.pack(anchor="w", padx=14, pady=(4, 0))
        self.status.pack_configure(pady=(4, 12))
        self.buttons = ctk.CTkFrame(self, fg_color="transparent")
        conv.add(self, sticky="e" if outgoing else "w", pady=6)
        conv.cards.add(fid)

    def alive(self):
        try:
            return bool(self.winfo_exists())
        except Exception:
            return False

    def set_status(self, text, color=MUTED):
        if self.alive():
            self.status.configure(text=text, text_color=color)

    def set_progress(self, done, total):
        if self.alive():
            frac = done / total if total else 1.0
            self.bar.set(frac)
            verb = "Sending" if self.outgoing else "Receiving"
            self.status.configure(text=f"{verb}… {frac * 100:.0f}%  ({human_size(done)} / {human_size(total)})",
                                  text_color=MUTED)

    def clear_buttons(self):
        for w in self.buttons.winfo_children():
            w.destroy()
        self.buttons.pack_forget()
        self.status.pack_configure(pady=(4, 12))

    def button(self, text, command, color=ACCENT, hover=None):
        if not self.buttons.winfo_ismapped() and not self.buttons.winfo_children():
            self.status.pack_configure(pady=(4, 0))
            self.buttons.pack(anchor="w", padx=14, pady=(6, 12))
        b = ctk.CTkButton(self.buttons, text=text, command=command, font=self.view.app.fonts["body"],
                          height=34, width=110, fg_color=color, hover_color=hover)
        b.pack(side="left", padx=(0, 8))
        return b

    def finish(self, ok, text):
        if not self.alive():
            return
        self.clear_buttons()
        self.bar.configure(progress_color=GREEN if ok else RED)
        if ok:
            self.bar.set(1)
        self.set_status(text, GREEN if ok else RED)


# ================================================================ main chat view

class ChatView(ctk.CTkFrame):
    def __init__(self, app, conn):
        super().__init__(app, fg_color=BG)
        self.app, self.conn = app, conn
        self.convs = {}
        self.active = None
        self.cards = {}
        self.online = []
        self.lost = False
        f = app.fonts

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # --- status bar (UI1): the on-screen security proof
        bar = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=0, height=48)
        bar.grid(row=0, column=0, columnspan=2, sticky="ew")
        if conn.use_tls:
            sec, color = f"{ICON['lock']}  {conn.tls_version}  ·  {conn.cipher}  ·  cert verified", GREEN
        else:
            sec, color = f"{ICON['warn']}  UNENCRYPTED - plain TCP, readable by anyone on the network", RED
        self.sec_label = ctk.CTkLabel(bar, text=sec, font=f["bold"], text_color=color)
        self.sec_label.pack(side="left", padx=16, pady=10)
        ctk.CTkButton(bar, text=f"{ICON['power']} Log out", width=100, height=34, font=f["body"],
                      fg_color=PANEL_2, hover_color=RED, command=self.disconnect).pack(side="right", padx=(6, 12))
        ctk.CTkLabel(bar, text=f"{conn.username}  ·  {conn.host}:{conn.port}", font=f["body"],
                     text_color=TEXT).pack(side="right", padx=6)

        # --- connection-lost banner (UI8), hidden until needed
        self.banner = ctk.CTkFrame(self, fg_color="#7f1d1d", corner_radius=0)
        ctk.CTkLabel(self.banner, text=f"{ICON['warn']}  Connection lost - the server is unreachable.",
                     font=f["bold"], text_color="white").pack(side="left", padx=16, pady=10)
        ctk.CTkButton(self.banner, text="Back to login", font=f["body"], fg_color="white", text_color="#7f1d1d",
                      hover_color="#fecaca", command=lambda: self.app.show_login()).pack(side="right", padx=12)

        # --- sidebar (UI2)
        side = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=0, width=230)
        side.grid(row=2, column=0, rowspan=2, sticky="nsw")
        side.grid_propagate(False)
        side.grid_rowconfigure(1, weight=1)
        side.grid_columnconfigure(0, weight=1)
        self.online_label = ctk.CTkLabel(side, text="ONLINE", font=f["small_bold"], text_color=MUTED)
        self.online_label.grid(row=0, column=0, sticky="w", padx=16, pady=(14, 4))
        self.user_list = ctk.CTkScrollableFrame(side, fg_color=PANEL, corner_radius=0)
        self.user_list.grid(row=1, column=0, sticky="nsew", padx=4)
        ctk.CTkLabel(side, text="Click a user to DM", font=f["small"], text_color=MUTED).grid(
            row=2, column=0, sticky="w", padx=16, pady=10)

        # --- tabs + conversation area (UI3)
        chat = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        chat.grid(row=2, column=1, sticky="nsew")
        chat.grid_rowconfigure(1, weight=1)
        chat.grid_columnconfigure(0, weight=1)
        self.tabbar = ctk.CTkFrame(chat, fg_color=BG, corner_radius=0)
        self.tabbar.grid(row=0, column=0, sticky="ew", padx=10)
        self.conv_host = ctk.CTkFrame(chat, fg_color=BG, corner_radius=0)
        self.conv_host.grid(row=1, column=0, sticky="nsew")
        self.conv_host.grid_rowconfigure(0, weight=1)
        self.conv_host.grid_columnconfigure(0, weight=1)

        # --- input row
        inp = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=0)
        inp.grid(row=3, column=1, sticky="ew")
        inp.grid_columnconfigure(0, weight=1)
        self.entry = ctk.CTkEntry(inp, placeholder_text="Type a message…", font=f["body"], height=44)
        self.entry.grid(row=0, column=0, sticky="ew", padx=(14, 8), pady=12)
        self.entry.bind("<Return>", lambda e: self.send())
        self.attach_btn = ctk.CTkButton(inp, text=ICON["clip"], width=48, height=44, font=f["bold"],
                                        fg_color=PANEL_2, hover_color=BORDER, command=self.attach)
        self.attach_btn.grid(row=0, column=1, padx=(0, 8))
        self.send_btn = ctk.CTkButton(inp, text="Send", width=96, height=44, font=f["bold"], command=self.send)
        self.send_btn.grid(row=0, column=2, padx=(0, 14))

        self.open_conv("#everyone", "# Everyone")
        self.select("#everyone")
        sec_note = (f"Connected securely ({conn.tls_version}, server certificate verified)" if conn.use_tls
                    else "Connected WITHOUT encryption")
        self.sys_line(self.convs["#everyone"], sec_note, GREEN if conn.use_tls else RED)
        self.entry.focus_set()
        self.after(50, self.poll)

    # ------------------------------------------------------------ conversations

    def open_conv(self, key, title=None):
        if key not in self.convs:
            self.convs[key] = Conversation(self, key, title or key)
            self.refresh_tabs()
        return self.convs[key]

    def select(self, key):
        if self.active and self.active in self.convs:
            self.convs[self.active].frame.grid_remove()
        self.active = key
        conv = self.convs[key]
        conv.unread = 0
        conv.frame.grid(row=0, column=0, sticky="nsew")
        conv.scroll_bottom()
        self.refresh_tabs()
        self.update_attach()
        if not self.lost:
            self.entry.focus_set()

    def close_conv(self, key):
        conv = self.convs.pop(key, None)
        if conv is None:
            return
        for fid in conv.cards:
            self.cards.pop(fid, None)
        conv.destroy()
        if self.active == key:
            self.active = None
            self.select("#everyone")
        else:
            self.refresh_tabs()

    def refresh_tabs(self):
        for k, c in self.convs.items():
            c.refresh_tab(k == self.active)

    def update_attach(self):
        # UI5: files go to one person, so the paperclip only works in a DM tab.
        enabled = self.active != "#everyone" and not self.lost
        self.attach_btn.configure(state="normal" if enabled else "disabled")

    def notify(self, conv):
        if conv.key != self.active:
            conv.unread += 1
            self.refresh_tabs()

    # ------------------------------------------------------------ rendering (UI4)

    def bubble(self, conv, sender, text, ts=None, own=False):
        f = self.app.fonts
        row = ctk.CTkFrame(conv.frame, fg_color="transparent")
        if not own:
            ctk.CTkLabel(row, text=f"{sender}   {hhmm(ts)}", font=f["small_bold"], text_color=MUTED).pack(
                anchor="w", padx=4)
        box = ctk.CTkFrame(row, fg_color=OWN_BUBBLE if own else OTHER_BUBBLE, corner_radius=14)
        box.pack(anchor="e" if own else "w")
        ctk.CTkLabel(box, text=text, font=f["body"], text_color="white" if own else TEXT, wraplength=460,
                     justify="left").pack(padx=14, pady=8)
        if own:
            ctk.CTkLabel(row, text=hhmm(ts), font=f["small"], text_color=MUTED).pack(anchor="e", padx=4)
        conv.add(row, sticky="e" if own else "w")
        if not own:
            self.notify(conv)

    def sys_line(self, conv, text, color=MUTED):
        lbl = ctk.CTkLabel(conv.frame, text=f"— {text} —", font=self.app.fonts["small"], text_color=color,
                           wraplength=560)
        conv.add(lbl, sticky="", pady=6)

    def set_users(self, users):
        self.online = users
        for w in self.user_list.winfo_children():
            w.destroy()
        f = self.app.fonts
        self.online_label.configure(text=f"ONLINE ({len(users)})")
        for u in users:
            me = u == self.conn.username
            b = ctk.CTkButton(self.user_list, text=f"{ICON['dot']}  {u}" + ("  (you)" if me else ""),
                              anchor="w", font=f["body"], height=36, fg_color="transparent",
                              text_color=GREEN if not me else MUTED, hover_color=PANEL_2,
                              command=(lambda u=u: self.open_dm(u)) if not me else None)
            b.pack(fill="x", pady=1)
            if not me:
                b.bind("<Double-Button-1>", lambda e, u=u: self.open_dm(u))

    def open_dm(self, user):
        self.open_conv(user, user)
        self.select(user)

    # ------------------------------------------------------------ actions

    def send(self):
        text = self.entry.get().strip()
        if not text or self.lost:
            return
        conv = self.convs[self.active]
        ok = self.conn.send_text(text) if conv.key == "#everyone" else self.conn.send_dm(conv.key, text)
        if ok:
            self.bubble(conv, self.conn.username, text, own=True)
            self.entry.delete(0, "end")

    def attach(self):
        if self.active == "#everyone" or self.lost:
            return
        peer = self.active
        path = filedialog.askopenfilename(title=f"Send a file to {peer}")
        if not path:
            return
        try:
            fid = self.conn.offer_file(peer, path)
        except OSError as e:
            self.sys_line(self.convs[peer], f"Cannot open file: {e}", RED)
            return
        card = FileCard(self.convs[peer], fid, Path(path).name, Path(path).stat().st_size, True, peer)
        card.set_status("Computing SHA-256…")
        self.cards[fid] = card

    def disconnect(self):
        self.conn.close()
        self.app.show_login()

    # ------------------------------------------------------------ network events

    def poll(self):
        handled = 0
        while handled < 300:
            try:
                m = self.conn.inbox.get_nowait()
            except queue.Empty:
                break
            handled += 1
            try:
                self.handle(m)
            except Exception as e:      # a rendering bug must not kill the event loop
                print("UI error handling", m.get("type"), repr(e), file=sys.stderr)
        if self.winfo_exists() and not self.lost:
            self.after(50, self.poll)

    def handle(self, m):
        t = m["type"]
        everyone = self.convs["#everyone"]
        card = self.cards.get(m.get("id")) if "id" in m else None

        if t == "msg":
            self.bubble(everyone, m["from"], m["text"], m.get("ts"))
        elif t == "dm":
            self.bubble(self.open_conv(m["from"], m["from"]), m["from"], m["text"], m.get("ts"))
        elif t == "users":
            self.set_users(m["list"])
        elif t == "sys":
            user = m.get("user")
            if m.get("error"):
                conv = self.convs.get(user) or self.convs[self.active]
                self.sys_line(conv, m["text"], RED)
            else:
                self.sys_line(everyone, m["text"])
                if user in self.convs:
                    self.sys_line(self.convs[user], m["text"])
        elif t == "file_offer":
            conv = self.open_conv(m["from"], m["from"])
            card = FileCard(conv, m["id"], m["name"], m["size"], False, m["from"])
            self.cards[m["id"]] = card
            card.set_status(f"SHA-256 {m['sha256'][:16]}…")
            fid = m["id"]
            card.button("Accept", lambda: self.accept(fid), GREEN, "#16a34a")
            card.button("Reject", lambda: self.reject(fid), PANEL, RED)
            self.notify(conv)
        elif t == "file_offered" and card:
            card.set_status(f"Waiting for {card.peer} to accept…")
            fid = m["id"]
            card.clear_buttons()
            card.button("Cancel", lambda: self.cancel(fid), PANEL, RED)
        elif t == "file_accept" and card:
            card.set_status(f"{card.peer} accepted - sending…")
        elif t == "file_reject" and card:
            card.finish(False, f"{card.peer} declined the file")
        elif t == "file_cancel" and card:
            card.finish(False, f"Cancelled: {m.get('reason', '')}")
        elif t == "file_progress" and card:
            card.set_progress(m["done"], m["total"])
        elif t == "file_sent" and card:
            card.finish(True, f"Sent {ICON['ok']}  ({card.peer} verifies the SHA-256 on arrival)")
        elif t == "file_done" and card:
            if m["ok"]:
                card.finish(True, f"{ICON['ok']}  SHA-256 verified\n{m['actual'][:32]}…")
                folder = str(Path(m["path"]).parent)
                card.button("Open folder", lambda: open_folder(folder), PANEL, BORDER)
            else:
                card.finish(False, f"{ICON['bad']}  Integrity check failed ({m['reason']})\n"
                                   f"expected {m['expected'][:16]}…  got {m['actual'][:16]}…\nFile discarded.")
        elif t == "file_failed" and card:
            card.finish(False, f"{ICON['bad']}  {m['reason']}")
        elif t == "conn_lost":
            self.connection_lost()

    def accept(self, fid):
        card = self.cards.get(fid)
        if card:
            card.clear_buttons()
            card.set_status("Accepted - waiting for data…")
        self.conn.accept_file(fid)

    def reject(self, fid):
        self.conn.reject_file(fid)
        card = self.cards.get(fid)
        if card:
            card.finish(False, "You declined this file")

    def cancel(self, fid):
        self.conn.cancel_file(fid, f"cancelled by {self.conn.username}")
        card = self.cards.get(fid)
        if card:
            card.finish(False, "You cancelled this transfer")

    def connection_lost(self):
        self.lost = True
        self.banner.grid(row=1, column=0, columnspan=2, sticky="ew")
        self.sec_label.configure(text="Disconnected", text_color=MUTED)
        self.entry.configure(state="disabled")
        self.send_btn.configure(state="disabled")
        self.update_attach()
        for card in self.cards.values():
            if card.alive() and card.buttons.winfo_children():
                card.finish(False, "Connection lost")
        self.set_users([])


# ================================================================ app shell

class App(ctk.CTk):
    def __init__(self, args):
        super().__init__(fg_color=BG)
        self.args = args
        self.title("SecureChat")
        self.geometry("1180x760")
        self.minsize(900, 600)
        # UI9: projector-friendly sizes (>= 14 pt everywhere).
        self.fonts = {
            "title": ctk.CTkFont(size=30, weight="bold"),
            "body": ctk.CTkFont(size=16),
            "bold": ctk.CTkFont(size=16, weight="bold"),
            "small": ctk.CTkFont(size=14),
            "small_bold": ctk.CTkFont(size=14, weight="bold"),
        }
        self.view = None
        self.conn = None
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.show_login()

    def _swap(self, view):
        if self.view is not None:
            self.view.destroy()
        self.view = view
        view.pack(fill="both", expand=True)

    def show_login(self, error=""):
        if self.conn:
            self.conn.close()
            self.conn = None
        self.title("SecureChat")
        self._swap(LoginView(self, self.args, error))

    def show_chat(self, conn):
        self.conn = conn
        self.args.host, self.args.port, self.args.user = conn.host, conn.port, conn.username
        self.title(f"SecureChat - {conn.username}")
        self._swap(ChatView(self, conn))

    def on_close(self):
        if self.conn:
            self.conn.close()
        self.destroy()


def main():
    p = argparse.ArgumentParser(description="SecureChat GUI client")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5555)
    p.add_argument("--user", default="")
    p.add_argument("--cafile", default=str(DEFAULT_CA), help="trusted server certificate")
    p.add_argument("--downloads", default=str(DEFAULT_DOWNLOADS))
    p.add_argument("--plain", action="store_true", help="no TLS (Wireshark comparison only)")
    p.add_argument("--corrupt-test", action="store_true", help="T6: corrupt the first chunk of files you send")
    args = p.parse_args()
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    App(args).mainloop()


if __name__ == "__main__":
    main()
