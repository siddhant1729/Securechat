# CLAUDE.md

Guidance for Claude Code (and other contributors) working in this repository.

## Project

SecureChat is a Computer Networks course project. It's a multi-client chat server with private messages and
file transfer, over TLS on TCP, written in Python 3.10+. The only dependency outside the standard library is
`customtkinter`, used by the two GUIs.

Docs: `README.md` (overview, setup, troubleshooting), `docs/walkthrough.md` (hands-on usage, LAN demo, Wireshark),
`docs/explanation.md` (design in depth: protocol, TLS, concurrency, file transfer, limitations).

## Commands

```bash
pip install -r requirements.txt                 # customtkinter
python gen_cert.py                              # REQUIRED after cloning: creates certs/server.key (gitignored) + server.crt
python -m unittest discover -s tests -v         # 23 end-to-end tests, about 10 s
python -m unittest tests.test_securechat.TestChat.test_T5_file_transfer_verified -v   # single test

python dashboard.py [--port 5555] [--plain]     # server + GUI dashboard
python server.py    [--port 5555] [--plain]     # headless server
python gui_client.py --user alice [--host IP] [--plain] [--corrupt-test]
python client.py     --user alice [--register]  # CLI client
python wire_peek.py --listen 6000 --target 127.0.0.1:5555   # print raw bytes on the wire
```

Tests fail with `FileNotFoundError` on the cert if `gen_cert.py` hasn't been run, because the key is never committed.

## Architecture

```
protocol.py   framing: send_msg / recv_msg / recv_exact, MAX_FRAME = 1 MiB, CHUNK_SIZE = 64 KB
auth.py       UserStore: salted SHA-256 in users.json (atomic writes, constant-time compare)
server.py     ChatServer: accept loop → thread per client → TLS handshake → auth → routing / file relay
net.py        ChatConnection: client TLS (pinned cert), receiver thread, inbox queue, file send and receive
client.py     CLI renderer over net.py
gui_client.py CustomTkinter renderer over net.py (LoginView, ChatView, Conversation, FileCard)
dashboard.py  runs ChatServer(events=queue) in the background and renders its events
```

Every frame is a 4-byte big-endian length followed by a UTF-8 JSON object with a `type`. The message catalogue
is in `docs/explanation.md` §3.2 and in `README.md`.

## Invariants: don't break these

1. **Only the Tk main thread touches widgets.** Network threads communicate through `queue.Queue`
   (`conn.inbox` and the server's `events`), and the UI drains it with `after()`. Never call widget methods from
   `net.py` or the server.
2. **`server.py` never imports GUI code.** Dashboard integration goes only through `_emit(event, **data)`.
3. **Every socket write from more than one thread goes through a lock**: `ClientSession.send()` on the server,
   `ChatConnection._send()` on the client. Never call `send_msg` directly on a shared socket, except in
   `_authenticate`, which already holds `send_lock`.
4. **Never send while holding `clients_lock` or `transfers_lock`.** Copy the targets under the lock, then send
   outside it. Lock order is `send_lock` → `clients_lock`, never the reverse.
5. **The server sets the identity.** Overwrite `from` with `client.user`. Never trust identity fields from the client.
6. **Never log message text.** Logs and dashboard events carry metadata only (users, sizes, ids, file names).
7. **Validate before allocating.** `recv_msg` checks the length against `MAX_FRAME` before reading the body.
   Keep size limits on any new frame type.
8. **File checks hash the file on disk.** The receiver re-reads the `.part` file, compares SHA-256 and size,
   then renames it or deletes it. Never keep a file that failed the check.
9. **Clean up through shutdown, not just close.** On Linux, `close()` doesn't wake a thread blocked in `recv()`.
   Use `ClientSession.kill()` or `shutdown(SHUT_RDWR)`.
10. **Stay standard-library only**, apart from customtkinter. Ask before adding a dependency.

## Changing the protocol

When adding or changing a message type, update all of these together:
- the route table in `server.py` `_dispatch`, plus a handler that validates every field
- `net.py` `_dispatch` (and the synthetic events, if any)
- `gui_client.py` `ChatView.handle` and `client.py` `CLI.printer`
- `README.md` protocol table and `docs/explanation.md` §3.2
- at least one end-to-end test in `tests/test_securechat.py`

## Conventions

- Error strings shown to users come from `ConnectError` / `sys` / `reason` fields. Keep them short and plain,
  and say what to do. The troubleshooting table in `README.md` quotes them exactly, so update it when a message
  changes.
- Paths resolve from `Path(__file__).resolve().parent` (`BASE`), so the scripts work from any directory.
- Fonts in the GUIs are at least 14 pt (projector readability). Colours are module-level constants at the top
  of each GUI file.
- Python 3.10 compatibility: no 3.11+ only syntax or stdlib features.

## Testing notes

- Tests start a real `ChatServer` on port 0 with `use_tls=True`, using a temporary users file and download
  folders, and connect real `ChatConnection` clients. Use the `wait_for(inbox, predicate)` helper. It skips
  unrelated events, so watch event order: a join `sys` arrives **before** the `users` list.
- To simulate a crashed client, call `sock.shutdown(socket.SHUT_RDWR)` with `_closing = True`, not
  `sock.close()` (see invariant 9).
- GUIs aren't covered by unit tests. To check them visually under WSLg/X11, drive the app programmatically
  and capture each window with ImageMagick: `import -window <app.wm_frame()> out.png`.
  `import -window root` fails on WSLg.

## Repo hygiene

- Never commit `certs/server.key`, `users.json`, `downloads/` or `.venv/` (all are in `.gitignore`).
  `certs/server.crt` is public and is committed.
- Commit or push only when asked. The remote is `origin` → `github.com/siddhant1729/Securechat`, branch `main`.
