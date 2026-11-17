"""Wire protocol: every frame is a 4-byte big-endian length followed by a UTF-8 JSON object.

TCP is a byte stream, not a message stream: one send() may arrive as several
recv()s, or two sends may arrive merged. The length prefix tells the receiver
exactly where each message ends.
"""

import json
import struct

HEADER = struct.Struct(">I")      # 4-byte unsigned big-endian length
MAX_FRAME = 1 * 1024 * 1024       # 1 MiB: a 64 KB file chunk is ~88 KB once base64'd
CHUNK_SIZE = 64 * 1024            # raw file bytes per file_chunk frame


class ProtocolError(Exception):
    """Peer sent something that isn't a valid frame."""


def send_msg(sock, obj):
    """Serialise obj and send it as one frame. Returns the number of bytes written.

    Callers that share a socket between threads must hold a lock around this,
    otherwise two frames can interleave on the wire.
    """
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_FRAME:
        raise ProtocolError(f"frame too large ({len(body)} bytes)")
    sock.sendall(HEADER.pack(len(body)) + body)
    return HEADER.size + len(body)


def recv_exact(sock, n):
    """Read exactly n bytes, looping over short reads. Returns None on clean EOF."""
    buf = bytearray()
    while len(buf) < n:
        part = sock.recv(n - len(buf))
        if not part:
            if buf:
                raise ProtocolError("connection closed mid-frame")
            return None
        buf.extend(part)
    return bytes(buf)


def recv_msg(sock):
    """Read one frame and return the decoded dict, or None if the peer closed the connection."""
    header = recv_exact(sock, HEADER.size)
    if header is None:
        return None
    (length,) = HEADER.unpack(header)
    if length > MAX_FRAME:
        raise ProtocolError(f"frame too large ({length} bytes)")
    body = recv_exact(sock, length)
    if body is None:
        raise ProtocolError("connection closed mid-frame")
    try:
        obj = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ProtocolError(f"bad JSON: {e}") from None
    if not isinstance(obj, dict) or not isinstance(obj.get("type"), str):
        raise ProtocolError("frame is not an object with a 'type'")
    return obj
