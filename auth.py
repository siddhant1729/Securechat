"""User accounts stored in users.json as salted SHA-256 hashes.

Format: {"alice": {"salt": "<hex>", "hash": "<hex sha256(salt + password)>"}}

Plain salted SHA-256 is fast, which makes offline brute force cheap if the file
leaks. bcrypt/scrypt/argon2 would be the production choice (future work).
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
from pathlib import Path

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{1,20}$")
MIN_PASSWORD = 4


class UserStore:
    def __init__(self, path):
        self.path = Path(path)
        self._lock = threading.Lock()

    @staticmethod
    def _hash(salt_hex, password):
        return hashlib.sha256(bytes.fromhex(salt_hex) + password.encode("utf-8")).hexdigest()

    def _load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def _save(self, users):
        tmp = self.path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(users, f, indent=2)
        os.replace(tmp, self.path)   # atomic: never leaves a half-written users.json

    def register(self, username, password):
        """Create an account. Returns (ok, reason)."""
        if not USERNAME_RE.match(username or ""):
            return False, "Username must be 1-20 letters, digits or _"
        if len(password or "") < MIN_PASSWORD:
            return False, f"Password must be at least {MIN_PASSWORD} characters"
        with self._lock:
            users = self._load()
            if username.lower() in (u.lower() for u in users):
                return False, "Username already registered"
            salt = secrets.token_hex(16)
            users[username] = {"salt": salt, "hash": self._hash(salt, password)}
            self._save(users)
        return True, ""

    def verify(self, username, password):
        """Check a login. Returns (ok, reason)."""
        with self._lock:
            rec = self._load().get(username or "")
        if rec is None:
            # Same message as a bad password so attackers can't probe which usernames exist.
            return False, "Wrong username or password"
        if hmac.compare_digest(self._hash(rec["salt"], password or ""), rec["hash"]):
            return True, ""
        return False, "Wrong username or password"
