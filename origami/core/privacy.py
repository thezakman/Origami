"""Conservative origin identity and safe diagnostic labels."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit


def origin(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("expected an HTTP(S) origin")
    host = parsed.hostname
    try:
        host = ipaddress.ip_address(host).compressed
    except ValueError:
        host = host.encode("idna").decode("ascii").lower()
    port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
    return parsed.scheme.lower(), host, port


def proxy_label(url: str) -> str:
    """Never expose proxy userinfo, path or query in console diagnostics."""
    try:
        scheme, host, port = origin(url)
        host = f"[{host}]" if ":" in host else host
        return f"{scheme}://{host}:{port}"
    except (ValueError, UnicodeError):
        return "[invalid proxy]"


def sensitive_header(name: str) -> bool:
    name = name.lower().replace("_", "-")
    return (name in {"authorization", "proxy-authorization", "cookie", "set-cookie"}
            or any(part in name for part in ("token", "secret", "api-key", "apikey", "session")))
