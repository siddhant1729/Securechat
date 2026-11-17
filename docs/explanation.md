# SecureChat: how it works

A technical explanation of the design. It covers what each part does, why it was built that way, and the
trade-offs made. For hands-on steps, see [walkthrough.md](walkthrough.md).

**Contents**
1. [Goals and scope](#1-goals-and-scope)
2. [Architecture](#2-architecture)
3. [Wire protocol](#3-wire-protocol)
4. [TLS](#4-tls)
5. [Authentication](#5-authentication)
6. [Server concurrency](#6-server-concurrency)
7. [Message routing](#7-message-routing)
8. [File transfer](#8-file-transfer)
9. [Client core (net.py)](#9-client-core-netpy)
10. [GUI and dashboard](#10-gui-and-dashboard)
11. [Failure handling](#11-failure-handling)
12. [Limitations and viva answers](#12-limitations-and-viva-answers)
13. [Design decisions](#13-design-decisions)

---

## 1. Goals and scope

**The problem.** A plain-socket chat sends everything in clear text. Anyone on the same network can read the
messages with a packet sniffer and rebuild the files.

**What SecureChat does:**
- many simultaneous clients over TCP
- broadcast and private messages in real time
- file transfer between any two users, relayed in chunks and checked with SHA-256
- TLS around every byte, so Wireshark shows only ciphertext
- username and password login
- GUIs that make the security visible: the live cipher in the client, and live server state on the dashboard

**Out of scope, on purpose:**
- **End-to-end encryption:** the server can read messages (see §12).
- **Peer-to-peer transfer:** everything goes through the server.
- **Browser client:** browsers can't open raw TLS sockets, so it would need a WebSocket bridge.
- **Message history, rooms, offline delivery.**
- **A certificate from a public CA:** a self-signed certificate is enough on a LAN.

**Stack:** the Python 3.10+ standard library (`socket`, `ssl`, `threading`, `json`, `hashlib`, `queue`), plus
`customtkinter` for the two GUIs. There are no other dependencies.

---

## 2. Architecture

```
 gui_client.py ─┐                                  ┌─ gui_client.py
 client.py ─────┤   TLS 1.2+/1.3 over TCP :5555     ├─ client.py
   (net.py)     └──────────────►  server.py  ◄──────┘    (net.py)
                                     │
                                     │ queue.Queue of event dicts
                                     ▼
                                dashboard.py
```

| Module | Role | Depends on |
|---|---|---|
| `protocol.py` | Framing: `send_msg`, `recv_msg`, `recv_exact`, constants | stdlib |
| `auth.py` | `UserStore`: register and verify accounts in `users.json` | stdlib |
| `server.py` | `ChatServer`: accept loop, per-client threads, auth, routing, file relay | protocol, auth |
| `net.py` | `ChatConnection`: client TLS, receiver thread, inbox queue, file send and receive | protocol |
| `client.py` | CLI frontend | net |
| `gui_client.py` | CustomTkinter frontend | net |
| `dashboard.py` | Server GUI. Runs `ChatServer` in the background | server |
| `gen_cert.py` | Self-signed certificate via the `openssl` CLI | server (`lan_ip`) |
| `wire_peek.py` | TCP relay that prints the raw bytes (the eavesdropper's view) | stdlib |

Two rules keep this layering clean:

1. **Networking logic is written once.** Both clients are just renderers over `net.ChatConnection`.
2. **The server knows nothing about GUIs.** It pushes plain dicts onto an optional queue, and `dashboard.py`
   consumes them.

---

## 3. Wire protocol

### 3.1 Framing

TCP gives you a **byte stream**, not a stream of messages. One `send()` can arrive as several `recv()` calls,
and two sends can arrive glued together. Without framing, JSON objects would be split or merged.

Every frame is:

```
┌────────────────────┬──────────────────────────────┐
│ length: uint32 BE  │ body: UTF-8 JSON (length B)  │
└────────────────────┴──────────────────────────────┘
```

- `send_msg(sock, obj)` encodes `json.dumps(obj, separators=(",", ":"))` and sends header and body in one
  `sendall`. It returns the number of bytes written, which the server uses for its statistics.
- `recv_exact(sock, n)` loops on `recv()` until exactly *n* bytes have arrived. It returns `None` on a clean EOF
  before any byte, and raises `ProtocolError` on an EOF partway through a frame.
- `recv_msg(sock)` reads the 4-byte header, rejects lengths over `MAX_FRAME`, reads the body, and decodes it.
  It requires a JSON **object** with a string `type`.

**Limits.** `MAX_FRAME = 1 MiB`. The largest real frame is a file chunk of about 87 KB, so this leaves plenty of
room. It also stops a malicious peer from announcing a 4 GB frame and making the receiver allocate memory for
it. The receiver checks the length **before** reading the body.

**Encoding detail.** `json.dumps` escapes non-ASCII characters by default (`ensure_ascii=True`), so `é` goes on
the wire as `é`. The length always counts the bytes actually sent.

**Thread safety.** `send_msg` itself has no lock. Any socket written by more than one thread must be wrapped in
a lock, or frames from two threads could interleave and corrupt the stream. The server uses one lock per
client session (`ClientSession.send_lock`) and the client uses `ChatConnection._send_lock`.

### 3.2 Message catalogue

| type | Direction | Fields | Notes |
|---|---|---|---|
| `auth` | C→S | `user`, `pass`, `mode` (`login` \| `register`) | Must be the first frame, within 30 s |
| `auth_ok` | S→C | `user` | Guaranteed to be the first frame the client receives |
| `auth_fail` | S→C | `reason` | The server then closes the connection |
| `msg` | C→S→others | `text` (+ `from`, `ts` added by the server) | Not echoed to the sender |
| `dm` | C→S→one | `to`, `text` (+ `from`, `ts`) | |
| `users` | C→S, S→C | `list` | Also pushed to everyone on each join and leave |
| `file_offer` | C→S→one | `to`, `name`, `size`, `sha256`, `id` (+ `from`) | `id` = uuid4 hex |
| `file_accept` / `file_reject` | C→S→sender | `id` (+ `from`) | Only the named receiver may answer |
| `file_chunk` | C→S→receiver | `id`, `seq`, `data` (base64) | ≤ 64 KB raw per chunk |
| `file_end` | C→S→receiver | `id` | Receiver verifies |
| `file_cancel` | both | `id`, `reason` | Added beyond the PRD (§8.5) |
| `sys` | S→C | `text`, optional `event` (`join`/`leave`), `user`, `error` | Notices and errors |

Fields the client sends but the server sets itself (`from`, `ts`) are **overwritten**. A client can't pretend
to be someone else.

### 3.3 Example frames

```json
{"type":"auth","user":"alice","pass":"hunter22","mode":"login"}
{"type":"msg","from":"alice","text":"hey everyone","ts":1763372541.27}
{"type":"sys","text":"ghost is not online","error":true,"user":"ghost"}
{"type":"file_offer","from":"alice","to":"bob","name":"notes.pdf","size":31457280,
 "sha256":"6bf8…0f58","id":"640c177b9a2e4f1d8c3b5a6e7f801234"}
```

---

## 4. TLS

### 4.1 Server side

```python
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.load_cert_chain(certfile, keyfile)
```

The PRD says to "wrap the listening socket". Instead, the server accepts a **plain** TCP socket and runs
`wrap_socket(server_side=True)` **inside that client's handler thread**, with a 10 s timeout. Wrapping the
listening socket would run each handshake inside `accept()`, so one slow or hostile client could stall every
new connection. A failed handshake is logged (`TLS Handshake failed from …`), sent to the dashboard as a
`tls_failed` event, and the socket is closed.

In practice Python and OpenSSL negotiate **TLS 1.3** with `TLS_AES_256_GCM_SHA384`. TLS 1.2 is the minimum
allowed.

### 4.2 Client side: certificate pinning

```python
ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile="certs/server.crt")
ctx.verify_mode = ssl.CERT_REQUIRED
ctx.check_hostname = False
```

- Passing `cafile` means the system CA store is **not** loaded. The trust store holds exactly one certificate:
  ours. That's **certificate pinning**. Only a server holding `server.key` can complete the handshake.
- An unknown certificate raises `SSLCertVerificationError`, which `net.py` turns into the user-facing message
  "Certificate verification failed" (test T9).
- **Why hostname checking is off.** The certificate's CN is `localhost`, but on a LAN clients connect by IP.
  With a single pinned certificate, the hostname check adds nothing: an attacker would still need our private
  key. `gen_cert.py` also writes Subject Alternative Names for `localhost`, `127.0.0.1` and the LAN IP, so
  hostname checking can be switched back on if wanted.
- After the handshake, the client reads `sock.version()` and `sock.cipher()[0]` for the GUI status bar.

### 4.3 What TLS does and doesn't protect

| Protected (confidentiality + integrity) | Visible to an observer |
|---|---|
| Passwords, messages, usernames, file names and contents, all JSON | IP addresses and ports |
| Message types and sizes, except as hinted by record lengths | Timing and approximate sizes of records |
| The server certificate (encrypted in TLS 1.3) | The ClientHello / ServerHello: TLS version and cipher |

Every record is authenticated with AES-GCM, so tampering in transit is detected by TLS itself. The SHA-256
file check (§8) is an extra **application-level** check. It covers corruption that TLS can't see: bugs in the
sender, the relay or the receiver, disk write errors, and the deliberate corruption in the `--corrupt-test` demo.

### 4.4 Plain mode

`--plain` on the server, dashboard and clients skips TLS completely. It exists only so the demo can compare a
plain capture with a TLS one (T8). A plain client can't talk to a TLS server (the handshake bytes aren't a
valid frame), and the reverse doesn't work either. There's a test for this.

---

## 5. Authentication

### 5.1 Storage

`users.json`:

```json
{"alice": {"salt": "9f2c…(16 random bytes, hex)", "hash": "sha256(salt || password) hex"}}
```

- **Salt:** `secrets.token_hex(16)` per user. The same password gives different hashes for different users,
  and precomputed rainbow tables don't work.
- **Comparison:** `hmac.compare_digest`, which takes the same time whether or not the hashes match, so
  attackers can't learn anything from timing.
- **Writes:** written to a temporary file, then `os.replace`. That's atomic, so a crash can't leave a
  half-written `users.json`. A lock serialises concurrent registrations.
- **Rules:** usernames match `^[A-Za-z0-9_]{1,20}$`, are unique ignoring case, and passwords are at least 4 characters.
- **Same error for both:** an unknown user and a wrong password both return "Wrong username or password", so
  nobody can probe which accounts exist.

### 5.2 The login handshake

1. The handler sets a **30 s** socket timeout (FR2) and reads one frame. If it's not `auth`, the client gets
   `auth_fail`.
2. `register` creates the account and logs in. `login` verifies the password.
3. **One attempt only.** On failure: `auth_fail` with a reason, then the connection is closed (T4). The
   dashboard gets an `auth_failed` event.
4. **Joining atomically.** The handler takes the client's `send_lock`, *then* `clients_lock`. It checks for a
   duplicate (T3), adds the client, and sends `auth_ok` while still holding `send_lock`. Another thread's
   broadcast can't reach the new client before `auth_ok` does, because it has to wait for that same lock.
5. The timeout is cleared, and join notices go out (§7).

---

## 6. Server concurrency

### 6.1 Threads

| Thread | Count | Job |
|---|---|---|
| accept loop | 1 | `accept()` with a 0.5 s timeout so `stop()` is noticed on every OS, then start a handler thread |
| client handler | 1 per connection | TLS handshake → auth → `recv_msg` loop → dispatch → cleanup in `finally` |
| (dashboard main thread) | 0–1 | Only when started via `dashboard.py` |

Every handler thread is a daemon thread, so it never blocks the process from exiting.

### 6.2 Shared state and locks

| State | Lock | Rule |
|---|---|---|
| `clients: {username: ClientSession}` | `clients_lock` | Hold only to read or change the dict. **Never send while holding it.** |
| `transfers: {id: Transfer}` | `transfers_lock` | Same rule |
| `stats` | `stats_lock` | Short counter updates |
| each client's socket | `ClientSession.send_lock` | Taken by `ClientSession.send()`, so writes from any thread are safe |

**Broadcast** copies the recipient list under `clients_lock`, releases it, then sends to each client. A slow
client delays only the thread sending to it. Joins, leaves and other routing carry on.

**Lock order** is always `send_lock` → `clients_lock` (only during auth). No code takes them the other way
round, so they can't deadlock.

### 6.3 ClientSession

`send(obj)` returns the bytes written, or `0` if the client is gone. On any `OSError` it calls `kill()`, which
does `shutdown(SHUT_RDWR)` then `close()`. The shutdown is the important part: it wakes up that client's handler
thread, which is blocked in `recv()`, so the thread sees EOF and cleans up. On Linux, calling `close()` alone
while another thread is in `recv()` doesn't send a FIN.

### 6.4 Why one thread per client

It's the simplest model to reason about and to explain: each connection's code runs top to bottom, with
blocking calls. It's fine for the target of under 50 clients. The alternatives, `selectors` or `asyncio`, scale
to thousands of connections but turn the code into a state machine (see §13).

---

## 7. Message routing

`_dispatch` uses an explicit table from message type to handler. Unknown types get a `sys` error. Handlers
never trust client-provided identity: the sender is always `client.user`.

| Frame | Server action | Logged as |
|---|---|---|
| `msg` | Check it's non-empty text, trim to 4000 chars, broadcast to everyone **except** the sender with `from` and `ts` added | `MSG Broadcast from alice (27 bytes)` |
| `dm` | Look up the target. If offline, send a `sys` error with `user` set. Otherwise send to that one socket | `DM alice -> bob (21 bytes)` |
| `users` | Reply with the sorted online list | none |
| join | `sys` "alice joined" (`event: join`) to the others, then `users` to everyone | `JOIN alice connected from … (TLSv1.3, …)` |
| leave | Cancel transfers (§8.5), `sys` "alice left" (`event: leave`), then `users` | `LEAVE alice disconnected` |

The sender isn't sent its own broadcast back. Its GUI draws the bubble straight away, and TCP keeps each
sender's messages in order (T1).

**Privacy rule (FR7):** logs and dashboard events contain metadata only (who, to whom, size), **never message
text**.

---

## 8. File transfer

### 8.1 Sequence

```
alice (sender)              server                     bob (receiver)
  │ sha256(file) [bg thread]   │                           │
  │── file_offer ─────────────►│ register Transfer          │
  │                            │── file_offer ─────────────►│ Accept / Reject card
  │                            │◄──────────── file_accept ──│ open notes.pdf.part
  │◄────────────── file_accept │ state = active             │
  │── file_chunk seq 0 ───────►│── relay immediately ──────►│ check seq, decode, write
  │── …                        │── …                        │
  │── file_end ───────────────►│ remove Transfer, files++   │
  │                            │── file_end ───────────────►│ re-hash the file on disk, compare
```

### 8.2 Server-side state

```
offered ──accept──► active ──end──► (removed, files_completed++)
   │                  │
   └─reject/cancel────┴─cancel/disconnect──► (removed)
```

The server checks every transfer frame against the `Transfer` record:
- `file_offer`: `id` ≤ 64 chars and unique, a non-empty `name`, `0 ≤ size ≤ 4 GiB`, `sha256` of 64 characters,
  a target that is online and isn't the sender
- `file_accept` / `file_reject`: only the transfer's **receiver** may send these
- `file_chunk` / `file_end`: only the **sender** may send these, and chunks are accepted only while `active`
- `file_cancel`: either party

Frames that don't match are dropped, so a third client can't inject chunks into someone else's transfer.

### 8.3 Chunking and relaying

- **Chunk size:** 64 KB raw = 65,536 bytes → 87,384 base64 characters → about 87.4 KB per frame. That's small
  enough to keep chat responsive, and large enough that per-frame overhead stays low.
- **Base64 inside JSON** reuses the one message pipe: no second socket, no binary frame type. It costs about
  33% extra bandwidth.
- **Relay, don't buffer.** Each chunk goes to the receiver as soon as it's read, so server memory stays flat
  whatever the file size. The server counts relayed bytes from the base64 length and sends a
  `transfer_progress` event only when the whole-number percentage changes.
- **Chat keeps flowing.** The sender's file thread takes `_send_lock` once per chunk, and chat frames from the
  UI slot in between. Test T10 measures a DM round-trip during a 50 MB transfer: under 2 s.

### 8.4 Receiver-side verification

1. On accept: pick a free name in `downloads/` (`notes (1).pdf` if the name is taken) and open `<name>.part`.
   The incoming name is cleaned: folder parts, leading dots and characters not allowed in file names are
   stripped, and it's capped at 150 characters. A malicious name like `../../x` can't write outside `downloads/`.
2. Each chunk: check `seq == expected` (TCP keeps order, so a mismatch means a bug or tampering), then
   base64-decode with `validate=True` and write.
3. On `file_end`: close the file, **re-read it from disk**, and compute its SHA-256. Compare both the hash and
   the byte count with the offer.
4. Match → rename `.part` to the final name and emit `file_done ok=True`. Mismatch → delete the `.part` file
   and emit `file_done ok=False` with both hashes.

Hashing the file on disk, rather than the bytes as they came off the network, means the check also catches
disk write problems. The cost is one extra read: about 0.1 s for 50 MB.

### 8.5 Cancellation (`file_cancel`, added beyond the PRD)

The PRD's message list has no way to abort a transfer, but T7 needs one. `file_cancel {id, reason}` is sent:

| Trigger | Sent by | To |
|---|---|---|
| Target offline or duplicate id at offer time | server | sender |
| Sender or receiver disconnects mid-transfer | server (`_on_leave`) | the other party, plus a `sys` notice |
| User clicks Cancel | client | server → other party |
| Sender can't read the file, or receiver can't write it | client | server → other party |

A receiver that gets a cancel closes and deletes its `.part` file. A sender stops its send thread through a
`threading.Event`.

### 8.6 The corruption demo (`--corrupt-test`)

The sender flips the first byte of chunk 0 (`b ^ 0xFF`) **after** hashing the original. The offer carries the
correct hash, so the receiver's check fails and the file is discarded (T6). It's the same code path that would
catch real corruption.

---

## 9. Client core (`net.py`)

`ChatConnection(host, port, cafile, use_tls, download_dir, corrupt_test)`

**connect(user, password, mode)**:
1. `create_connection` with a 10 s timeout.
2. TLS wrap with the pinned context (§4.2).
3. Send `auth` and wait for `auth_ok` or `auth_fail`.
4. Start the receiver thread.

Every failure becomes a `ConnectError` with a short message the GUI can show as-is: "Connection refused - is
the server running?", "Certificate verification failed", "Wrong username or password", "'alice' is already
logged in", and so on.

**Sending:** `send_text`, `send_dm`, `request_users`, `offer_file` (returns an id at once and hashes on a
background thread), `accept_file`, `reject_file`, `cancel_file`. All of them go through `_send()`, which holds
`_send_lock` and returns `False` instead of raising if the socket is dead.

**Receiving:** the receiver thread runs `recv_msg` → `_dispatch`. File chunks and `file_end` are handled
**on this thread**, by writing to disk and hashing, so file data never reaches the UI. Everything else, plus a
few events the client generates itself, is put on `inbox: queue.Queue`:

| Event | Meaning |
|---|---|
| any server frame | `msg`, `dm`, `users`, `sys`, `file_offer`, `file_accept`, `file_reject`, `file_cancel` |
| `file_offered` | Our offer finished hashing and was sent |
| `file_progress` | `{id, done, total, direction}`, at most about 10/s per transfer |
| `file_sent` | Last chunk and `file_end` sent |
| `file_done` | `{ok, path, expected, actual, reason}` after verification |
| `file_failed` | Local I/O error or a bad chunk |
| `conn_lost` | The socket died and `close()` wasn't called |

When the receiver loop exits, it deletes partial incoming files and stops any outgoing sends.

---

## 10. GUI and dashboard

### 10.1 The threading rule

Tkinter isn't thread-safe: touching a widget from a non-main thread can crash or corrupt the UI. So:

```
network thread ──► conn.inbox (queue.Queue) ──► main thread polls with after(50) ──► widgets
```

`ChatView.poll()` handles up to 300 events per tick, so a burst can't freeze the window, and each handler is
wrapped in try/except so one rendering bug can't stop the polling loop. The login screen does its blocking
`connect()` on a worker thread and passes the result back through a queue the same way.

### 10.2 Client structure (`gui_client.py`)

- `App`: the window shell. It switches between `LoginView` and `ChatView` and closes the connection on exit.
- `LoginView`: server, port, username and password fields, a Login/Register toggle, a spinner while
  connecting, and errors shown inline in red.
- `ChatView`: status bar (UI1), connection-lost banner (UI8), online sidebar (UI2), tab bar, conversation area
  and message input.
- `Conversation`: one tab and its scrollable list of messages. It tracks unread counts and keeps the view
  scrolled to the bottom.
- `FileCard`: caption, name and size, progress bar, status line, and buttons (Accept/Reject, Cancel, Open
  folder). The bar turns green or red when the transfer ends.

Styling: dark theme and fonts of at least 14 pt for projectors (UI9). Some Linux Tk builds crash on colour
emoji, so on Linux the icons fall back to plain symbols unless `SECURECHAT_EMOJI=1` is set.

### 10.3 Dashboard (`dashboard.py`)

It creates `ChatServer(events=queue)`, starts it in the background, and drains the queue every 100 ms.

| Event | Panel |
|---|---|
| `server_started` | Header: address, TLS on/off, cert CN |
| `client_joined` / `client_left` | Connected clients table and count |
| `transfer_started` / `transfer_progress` / `transfer_finished` | Active transfers (rows clear after 6 s) |
| `log` | Event log, colour-coded by kind, capped at about 2000 lines |
| `auth_failed`, `tls_failed`, `dm_routed` | Available for display. Each is also logged |

The stats tiles read `server.stats` directly on each poll. They're simple integers updated under a lock.

---

## 11. Failure handling

| Situation | What happens | Covered by |
|---|---|---|
| Client sends garbage or an oversized frame | `ProtocolError`. That handler cleans up, others are unaffected | `test_garbage_does_not_crash_server` |
| Unexpected exception in a handler | Caught by the catch-all in `_handle`, logged, then normal cleanup | FR6 |
| Client process killed | Kernel sends FIN/RST → `recv` returns EOF → `_on_leave` | T7 |
| Client killed mid-transfer | Transfer removed, other party gets `file_cancel` + `sys`, partial file deleted | T7 |
| Write to a dead client | `send()` returns 0 and kills that session. Its own thread cleans up | |
| No auth within 30 s | Timeout → connection dropped | FR2 |
| Wrong certificate | Handshake fails on both ends. GUI shows "Certificate verification failed" | T9 |
| Server stops | All sessions killed → clients get EOF → `conn_lost` → banner | T11 |
| Stale session on leave | `_on_leave` removes the dict entry only if it's still *this* session object | |
| Dashboard can't bind (port in use, cert missing) | Header shows NOT RUNNING, and the log explains why | |

---

## 12. Limitations and viva answers

**"Is this end-to-end encrypted?"** No. TLS protects each hop: client to server, and server to client. The
server decrypts every frame to route it, so whoever runs the server can read everything. E2EE would need key
pairs on each client (for example X25519), encryption done on the client, and the server relaying only
ciphertext. That's future work.

**"Why is SHA-256 needed if TLS already guarantees integrity?"** TLS guarantees the bytes weren't changed *on
the wire*. The file hash guarantees the file *on the receiver's disk* is identical to the sender's original. It
catches application bugs, disk errors, and the corruption demo.

**"Why salted SHA-256 rather than bcrypt?"** The PRD allowed it, and it keeps the project standard-library only.
Its weakness is speed: GPUs try billions of SHA-256 guesses per second if `users.json` leaks. bcrypt, scrypt or
Argon2 are deliberately slow and would be used in production.

**"Why is hostname verification off?"** See §4.2. The client trusts exactly one certificate, so a hostname check
adds nothing in this setup.

**"What happens with 1000 clients?"** About 1000 threads, each with its own memory, plus lock contention on
broadcasts. It would work but wouldn't scale well. `selectors` or `asyncio` would be the next step.

Other known limitations:
- **Slow receivers:** a client that stops reading will eventually block whichever thread is sending to it.
  The fix is send timeouts or per-client outgoing queues.
- **No login rate limiting:** one attempt per connection slows guessing but doesn't stop it.
- **Base64 overhead:** about 33% extra on file transfers.
- **No resuming:** a broken transfer starts again from zero.
- **Online only:** no history, no offline delivery, no rooms.

---

## 13. Design decisions

| Decision | Chosen | Alternatives | Why |
|---|---|---|---|
| Encryption | stdlib `ssl`, TLS ≥ 1.2 | Hand-rolled AES | Proven, one call to wrap a socket. Home-made crypto is more code and weaker |
| Concurrency | Thread per client | `select` / `asyncio` | Simplest to reason about. Fine under 50 clients |
| Framing | 4-byte length + JSON | Newline-delimited, binary TLV | Handles any content, easy to debug, cheap to parse |
| File transport | Relay through server, 64 KB base64 chunks | P2P, second socket, binary frames | Reuses one secured pipe and works through NAT and firewalls |
| Integrity | SHA-256 of the whole file, checked on disk | Per-chunk hashes | One clear check, easy to demonstrate |
| Trust | Pinned self-signed cert | Public CA | Right for a LAN, and stronger than trusting every CA |
| GUI | CustomTkinter + queue | Web UI via a bridge | Real TLS sockets in every client. No JS, no extra network hop |
| Dashboard coupling | Event queue | Server calls GUI code | Server stays headless and testable |

**Changes from the PRD:**
- the `file_cancel` message (§8.5)
- the TLS handshake runs in the handler thread instead of on the listening socket (§4.1)
- hostname checking is off because the certificate is pinned (§4.2)
- broadcasts aren't echoed to the sender
- extra optional fields on `sys` frames (`event`, `user`, `error`)
- `wire_peek.py` added as a fallback when Wireshark isn't available
