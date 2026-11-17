"""Eavesdropper's view: a TCP relay that prints every byte passing through it.

A backup for the Wireshark demo (T8), e.g. when loopback capture isn't available.

    python wire_peek.py --listen 6000 --target 127.0.0.1:5555
    python gui_client.py --port 6000          # connect THROUGH the relay

With TLS you'll see random bytes; with `server.py --plain` + `--plain` clients you'll
read every message and password. (Certificate checks still pass because the relay
only forwards bytes - it can't decrypt or impersonate the server without server.key.)
"""

import argparse
import socket
import string
import threading

PRINTABLE = set(string.printable.encode()) - set(b"\t\n\r\x0b\x0c")


def preview(data, limit=160):
    text = "".join(chr(b) if b in PRINTABLE else "·" for b in data[:limit])
    return text + ("…" if len(data) > limit else "")


def pipe(src, dst, label, log=None):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
            print(f"{label} {len(data):6d} B | {preview(data)}", flush=True)
            if log is not None:
                log.append(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def serve(listen_port, target, log=None, ready=None):
    host, port = target
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", listen_port))
    srv.listen(16)
    if ready:
        ready.set()
    print(f"Relaying :{listen_port} -> {host}:{port}  (C>S = client to server, S>C = server to client)")
    while True:
        client, addr = srv.accept()
        upstream = socket.create_connection((host, port))
        threading.Thread(target=pipe, args=(client, upstream, "C>S", log), daemon=True).start()
        threading.Thread(target=pipe, args=(upstream, client, "S>C", log), daemon=True).start()


def main():
    p = argparse.ArgumentParser(description="Show what an eavesdropper sees on the wire")
    p.add_argument("--listen", type=int, default=6000)
    p.add_argument("--target", default="127.0.0.1:5555")
    a = p.parse_args()
    host, port = a.target.rsplit(":", 1)
    try:
        serve(a.listen, (host, int(port)))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
