# SecureChat walkthrough

A hands-on guide, step by step. It covers installing, running everything on one machine, setting up the
three-laptop LAN demo, capturing traffic with Wireshark, running the tests, and presenting. Each step says what
to do and what you should see. For *why* things work the way they do, read [explanation.md](explanation.md).

---

## 0. Prerequisites

| Need | Check | Install |
|---|---|---|
| Python 3.10+ | `python --version` | python.org, or your package manager |
| Tkinter | `python -c "import tkinter"` | Bundled on Windows and macOS. On Debian/Ubuntu: `sudo apt install python3-tk` |
| OpenSSL CLI | `openssl version` | Bundled with Git for Windows. Preinstalled on macOS and Linux |
| CustomTkinter | `python -c "import customtkinter"` | `pip install -r requirements.txt` |

A virtual environment is recommended:

```bash
git clone https://github.com/siddhant1729/Securechat.git
cd Securechat
python -m venv .venv
# Windows: .venv\Scripts\activate      macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

## 1. Generate the server certificate

The private key is **not** in the repo, on purpose. Generate a fresh key pair on the machine that will run the server:

```bash
python gen_cert.py
```

Expected output:

```
Wrote .../certs/server.crt and server.key  (SAN: DNS:localhost, IP:127.0.0.1, IP:192.168.1.10)
Give server.crt to clients; keep server.key on the server only.
```

- `certs/server.key` is the server's secret and never leaves this machine.
- `certs/server.crt` is public. Every client needs a copy, because it's the **only** certificate clients trust.
- If you regenerate, copy the new `server.crt` to every client again. Old copies will fail with "Certificate
  verification failed".

The test suite needs both files too. Run `gen_cert.py` once after cloning, even if you only want to run the tests.

---

## 2. Single-machine tour (about 10 minutes)

Open three terminals in the project folder.

### 2.1 Start the server dashboard

```bash
python dashboard.py
```

What you should see:

- **Header:** `Listening on <your-LAN-IP>:5555`, a green `TLS enabled · cert CN=localhost`, and an uptime counter.
- **Stats tiles:** Clients online 0, Messages routed 0, Bytes relayed 0 B, Files completed 0.
- **Event log:** `START  Listening on …:5555 - TLS enabled (CN=localhost)`.

Prefer the terminal? `python server.py` runs the same server headless and prints the same log lines.

### 2.2 Register two users

Terminal 2: `python gui_client.py --user alice`
Terminal 3: `python gui_client.py --user bob`

In each login window:

1. Click **Register**. The button changes to *Create account & connect*.
2. Type a password of at least 4 characters and press Enter.
3. A spinner shows "TLS handshake…" and the chat window opens.

What you should see:

- **Client status bar:** `🔒 TLSv1.3 · TLS_AES_256_GCM_SHA384 · cert verified`. These values come live from the
  socket, not from fixed text.
- **Sidebar:** `ONLINE (2)` lists both users, and yours is marked *(you)*.
- **# Everyone tab:** a green line saying "Connected securely…", then "bob joined" in alice's window.
- **Dashboard:** two rows in *Connected clients* with IP:port, connect time, TLS version and cipher. The log shows
  `AUTH New account registered` and `JOIN alice connected from 127.0.0.1:… (TLSv1.3, …)`.

Next time, use **Login** with the same password. Accounts are stored in `users.json` next to the server.

### 2.3 Broadcast

Type in alice's **# Everyone** tab and press Enter.

- **Alice:** a blue bubble on the right with a timestamp.
- **Bob:** a grey bubble on the left labelled `alice  10:42`.
- **Dashboard:** `MSG Broadcast from alice (N bytes)`, and *Messages routed* goes up. The text itself is never logged.

### 2.4 Direct message

In alice's sidebar, click **bob**. A `bob` tab opens and becomes active. Send a message.

- **Bob:** if he's looking at another tab, an `alice ● 1` unread badge appears in amber. Clicking the tab clears it.
- **Dashboard:** `DM alice -> bob (N bytes)`.

DM someone who isn't online. In the CLI client that's `/dm ghost hi`; in the GUI, open a DM tab with a user and
then disconnect that user. You should see a red notice: "ghost is not online".

### 2.5 Send a file

1. In alice's `bob` tab, click **📎**. It's greyed out in # Everyone because files go to one person.
2. Pick any file, ideally a few MB.
3. **Alice's card:** "Computing SHA-256…", then "Waiting for bob to accept…" with a Cancel button.
4. **Bob's card:** the file name, size, the first 16 hex characters of the SHA-256, and **Accept** / **Reject**.
5. Bob clicks **Accept**. Both progress bars move, and the dashboard's *Active transfers* panel shows
   `alice → bob` with its own bar.
6. **Bob:** `✅ SHA-256 verified` plus the hash and an **Open folder** button. The file is in `downloads/`.
7. **Alice:** `Sent ✅ (bob verifies the SHA-256 on arrival)`.
8. **Dashboard:** `Relayed ✔`, *Files completed* goes up, and the row disappears after about 6 seconds.

Also try **Reject**: alice sees "bob declined the file". Try **Cancel** during a transfer: both cards turn red.

### 2.6 Watch an integrity failure (T6)

Close alice's window and restart her with a deliberately corrupting sender:

```bash
python gui_client.py --user alice --corrupt-test
```

Send bob a file again. The sender flips one byte in the first 64 KB chunk but sends the hash of the *original* file.

- **Bob:** `❌ Integrity check failed (SHA-256 mismatch)`, with the expected and actual hash prefixes, and
  "File discarded". Nothing is saved to `downloads/`.

### 2.7 Authentication failures

- **Wrong password (T4):** log in as alice with a wrong password. The login screen shows "Wrong username or
  password" in red. The dashboard logs `AUTH Auth FAILED for 'alice' …`.
- **Duplicate login (T3):** while alice is online, log in as alice from another window. You get "'alice' is
  already logged in".
- **Bad username:** register `bad name!`. You get "Username must be 1-20 letters, digits or _".

### 2.8 Disconnects

- **Close bob's window:** alice sees "— bob left —", the sidebar updates, and the dashboard removes bob's row
  and logs `LEAVE`.
- **Close bob mid-transfer (T7):** alice's card shows "Cancelled: bob disconnected". The server keeps running.
- **Stop the server (T11):** close the dashboard. Every client shows the red banner "Connection lost - the server
  is unreachable", typing is disabled, and **Back to login** returns to the login screen. Nothing crashes.

---

## 3. CLI client

The CLI client uses the same `net.py` core as the GUI, which makes it handy for debugging or scripting.

```bash
python client.py --user carol --register      # prompts for a password
```

Example session:

```
🔒 TLSv1.3 · TLS_AES_256_GCM_SHA384 · cert verified
Logged in as carol. Type /help for commands.
> Online (3): alice, bob, carol
> hello all
[10:42] you: hello all
> /dm alice did you get the slides?
[10:42] (DM to alice) you: did you get the slides?
> [10:43] (DM) alice: yes thanks
> /send bob ./report.pdf
Hashing './report.pdf' (id 3fa9c2e1)…
Offer 3fa9c2e1 sent, waiting for the receiver…
bob accepted 3fa9c2e1, sending…
  3fa9c2e1 send 25%
  …
Transfer 3fa9c2e1 sent ✓
```

Receiving: `📄 alice wants to send 'notes.pdf' (2.1 MB). /accept 640c177b  or  /reject 640c177b`.
The first few characters of the id are enough.

| Command | Action |
|---|---|
| `<text>` | Broadcast |
| `/dm <user> <text>` | Private message |
| `/users` | List online users |
| `/send <user> <path>` | Offer a file |
| `/accept <id>` / `/reject <id>` | Answer an offer |
| `/quit` | Disconnect |

`--password` exists for scripted runs, but it puts the password in your shell history. Prefer the prompt.

---

## 4. LAN demo setup (three laptops plus the projector)

1. **Pick the server laptop** and connect every machine to the same network.
2. **On the server laptop:** run `python gen_cert.py`. It adds the LAN IP to the certificate. Then start
   `python dashboard.py` and note the IP in the header.
3. **Copy the project to each client laptop** (`git clone` works), then copy the server's `certs/server.crt` over
   the client's. Make sure no client has `server.key`.
4. **Open the firewall on the server.**
   - Windows: allow Python when Defender asks, or add an inbound rule for TCP 5555.
   - Linux: `sudo ufw allow 5555/tcp`.
   - macOS: allow incoming connections for Python when prompted.
5. **On each client:** `python gui_client.py --host <server-ip> --user alice` (then bob, charlie).
6. **Check connectivity before the day.** Lab networks often block ports or isolate clients from each other.
   Keep a phone hotspot as a fallback, and do a full run-through on the real network a day early.

If a client shows "Timed out connecting", it's the network or firewall. If it shows "Certificate verification
failed", the client has the wrong `server.crt`.

---

## 5. Wireshark capture (T8)

The goal is two captures side by side: one where every message can be read, and one that's only ciphertext.

### 5.1 Plain capture

```bash
python dashboard.py --plain
python gui_client.py --plain --user alice      # and a second client for bob
```

The header turns red ("PLAINTEXT MODE") and the client status bar warns "UNENCRYPTED". Start Wireshark on the
interface carrying the traffic. For one machine that's *Npcap Loopback Adapter* on Windows or `lo` on Linux.
Use the display filter:

```
tcp.port == 5555
```

Log in, chat, and send a small file. Right-click any packet → **Follow → TCP Stream**. You'll see
`{"type":"auth","user":"alice","pass":"…"}` with the password in clear text, every message, and the base64 file
data. Save the capture.

### 5.2 TLS capture

Restart everything **without** `--plain` and repeat. Now you'll see:

- the TCP handshake, then **Client Hello** and **Server Hello** (TLS version and cipher are visible)
- after that, only **Application Data** records. Follow TCP Stream shows noise.
- in TLS 1.3, even the certificate is sent encrypted

### 5.3 No Wireshark? Use the relay

```bash
python wire_peek.py --listen 6000 --target 127.0.0.1:5555
python gui_client.py --port 6000 --user alice
```

Every byte passing through the relay is printed (`C>S` = client to server, `S>C` = server to client). With TLS
it's unreadable. In `--plain` mode you can read the JSON. Certificate checks still pass through the relay,
because it only copies bytes and can't decrypt them or pretend to be the server.

---

## 6. Running the tests

```bash
python -m unittest discover -s tests -v
```

It runs 23 tests in about 10 seconds. Each test starts a real TLS server on a free port and connects real
`ChatConnection` clients over loopback.

| PRD case | Test | What it proves |
|---|---|---|
| T1 | `test_T1_broadcast_order` | 3 clients × 30 concurrent messages, all delivered, in order per sender |
| T2 | `test_dm_and_T2_offline` | DM delivered to one client only. DM to an offline user gives a `sys` error |
| T3 | `test_T3_duplicate_login` | Second login as the same user is rejected |
| T4 | `test_T4_wrong_password_closes` | `auth_fail`, then the server really closes the socket |
| T5 | `test_T5_file_transfer_verified` | 10 MB file arrives with a matching hash |
| T6 | `test_T6_corrupt_chunk_detected` | Mismatch detected, and the bad file isn't kept |
| T7 | `test_T7_sender_dies_mid_transfer` | Receiver gets cancel + notice, server keeps serving, partial file removed |
| T9 | `test_T9_wrong_cert_rejected` | Unknown cert gives "Certificate verification failed" |
| T10 | `test_chat_flows_during_big_transfer` | DM round-trip under 2 s during a 50 MB transfer |
| T11 | `test_T11_server_stop_notifies_clients` | Clients get `conn_lost` when the server stops |
| T12 | `test_dashboard_events` | `client_joined` / `client_left` events carry TLS details |

Other tests cover framing (split and merged frames), spoofed senders, registration rules, plaintext passwords
on disk, rejection, empty files, offers to offline users, garbage input, plain mode, and a plain client
connecting to a TLS server.

Run one test with `python -m unittest tests.test_securechat.TestChat.test_T5_file_transfer_verified -v`.

**Check by hand:** T8 (section 5), plus how smooth the GUI feels during T10 (send a 50 MB file while chatting in
another tab, and check the window never freezes) and the dashboard updating live during T12.

---

## 7. Five-minute demo script

| Time | Do | Say |
|---|---|---|
| 0:00 | Projector on the dashboard. Point at the header | "The server is listening on TCP 5555 with TLS. This is a self-signed certificate we generated." |
| 0:30 | Three laptops log in as alice, bob, charlie | "Each login is a TCP connection, then a TLS 1.3 handshake, then an auth frame. Watch the table fill in." |
| 1:00 | Point at a client's status bar | "TLS version and cipher, read live from the socket. The client only trusts our certificate." |
| 1:30 | Broadcast in # Everyone. Alice opens a DM with bob | "Same connection, different frame type. The server routes by username and stamps the sender itself." |
| 2:15 | Alice sends a PDF, bob accepts | "64 KB chunks relayed straight through, never stored on the server. Bob re-hashes the file and compares SHA-256." |
| 3:15 | Wireshark: plain vs TLS captures | "Without TLS you can read the password and every message. With TLS it's Application Data only." |
| 4:00 | Close charlie's window | "The server notices the disconnect, cleans up, tells everyone, and keeps running." |
| 4:30 | Wrong-password login | "Rejected, connection closed, logged on the dashboard. Passwords are stored salted and hashed." |

Have the "is it end-to-end encrypted?" answer ready. It's in [explanation.md § Limitations](explanation.md#12-limitations-and-viva-answers).

---

## 8. Resetting

| To reset | Delete |
|---|---|
| All accounts | `users.json` (next to the server) |
| Received files | the contents of `downloads/` |
| Certificates | `certs/server.*`, then run `python gen_cert.py` and redistribute `server.crt` |

For specific error messages, see the troubleshooting table in the [README](../README.md#troubleshooting).
