"""Generate the self-signed server certificate in certs/.

    python gen_cert.py            # CN=localhost, SANs: localhost, 127.0.0.1, this machine's LAN IP
    python gen_cert.py 10.0.0.42  # add extra IPs/hostnames to the SAN list

Needs the `openssl` command (bundled with Git for Windows; preinstalled on macOS/Linux).
Equivalent to the PRD one-liner:
    openssl req -x509 -newkey rsa:2048 -nodes -keyout certs/server.key -out certs/server.crt \
        -days 365 -subj "/CN=localhost"

Copy certs/server.crt (NOT server.key) to every client machine.
"""

import ipaddress
import shutil
import subprocess
import sys
from pathlib import Path

from server import lan_ip

CERTS = Path(__file__).resolve().parent / "certs"


def main():
    if not shutil.which("openssl"):
        raise SystemExit("openssl not found on PATH. Install it (or Git for Windows) and retry.")
    CERTS.mkdir(exist_ok=True)
    names = ["localhost", "127.0.0.1", lan_ip(), *sys.argv[1:]]
    san = []
    for n in dict.fromkeys(names):
        try:
            ipaddress.ip_address(n)
            san.append(f"IP:{n}")
        except ValueError:
            san.append(f"DNS:{n}")
    cmd = ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
           "-keyout", str(CERTS / "server.key"), "-out", str(CERTS / "server.crt"),
           "-days", "365", "-subj", "/CN=localhost", "-addext", "subjectAltName=" + ",".join(san)]
    subprocess.run(cmd, check=True, capture_output=True)
    print(f"Wrote {CERTS / 'server.crt'} and server.key  (SAN: {', '.join(san)})")
    print("Give server.crt to clients; keep server.key on the server only.")


if __name__ == "__main__":
    main()
