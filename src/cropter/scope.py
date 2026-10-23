"""Conservative scope checks for future network-enabled adapters.

This module deliberately fails closed. It is not a substitute for reading the
program policy; users must include only assets they are authorized to test.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Scope:
    """Explicit host allowlist and optional deny patterns."""

    allowed_hosts: tuple[str, ...]
    denied_hosts: tuple[str, ...] = ()

    def allows_url(self, url: str) -> bool:
        """Return True only for HTTP(S) URLs whose host matches the allowlist."""
        try:
            parsed = urlsplit(url)
            if parsed.scheme.lower() not in {"http", "https"}:
                return False
            if not parsed.hostname or parsed.username or parsed.password:
                return False
            host = parsed.hostname.rstrip(".").lower()
        except (TypeError, ValueError):
            return False

        if any(fnmatch(host, pattern.lower()) for pattern in self.denied_hosts):
            return False
        return any(fnmatch(host, pattern.lower()) for pattern in self.allowed_hosts)


def load_scope(path: str) -> Scope:
    """Load a simple scope file with `allow=host` and `deny=host` lines."""
    allowed: list[str] = []
    denied: list[str] = []
    with open(path, encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.partition("#")[0].strip()
            if not line:
                continue
            key, separator, value = line.partition("=")
            value = value.strip().lower().rstrip(".")
            if not separator or not value:
                raise ValueError(f"Invalid scope entry: {raw_line.rstrip()!r}")
            if key.strip().lower() == "allow":
                allowed.append(value)
            elif key.strip().lower() == "deny":
                denied.append(value)
            else:
                raise ValueError(f"Unknown scope directive: {key.strip()!r}")
    if not allowed:
        raise ValueError("Scope must contain at least one allow=host entry")
    return Scope(tuple(allowed), tuple(denied))
