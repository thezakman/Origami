"""Passive Set-Cookie telemetry; never stores values or changes the cookie jar."""

from __future__ import annotations

import re
from collections.abc import Callable
from urllib.parse import urlsplit

_NAME = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")


def cookie_metadata(headers: list[str]) -> tuple[list[dict], int]:
    """Parse each separate field, without splitting Expires dates on commas.

    This is header observation, not browser acceptance or security validation.
    Unknown/ambiguous syntax is counted explicitly, never exported verbatim.
    """
    cookies = []
    unparsed = 0
    for header in headers:
        pair, _, attributes = header.partition(";")
        name, equals, value = pair.strip().partition("=")
        if not equals or not _NAME.fullmatch(name) or "," in value:
            unparsed += 1
            continue
        attrs = {}
        for attribute in attributes.split(";"):
            key, _, val = attribute.strip().partition("=")
            attrs[key.lower()] = val.strip()
        same_site = attrs.get("samesite", "").lower()
        cookies.append({"name": name, "secure": "secure" in attrs,
                        "httponly": "httponly" in attrs,
                        "samesite": same_site if same_site in {"strict", "lax", "none"} else None})
    return cookies, unparsed


class CookieRecorder:
    """Aggregate metadata-identical observations; bound only live notifications."""

    def __init__(self, records: list[dict] | None = None,
                 notify: Callable[[dict], None] | None = None, notice_limit: int = 20,
                 notify_limit: Callable[[], None] | None = None):
        self.records = records if records is not None else []
        self.notify = notify
        self.notice_limit = notice_limit
        self.notify_limit = notify_limit
        self.suppressed_notices = 0
        self._indices: dict[tuple, int] = {}
        self._notices: set[tuple] = set()

    def record(self, url: str, status: int, headers: list[str]) -> None:
        if not headers:
            return
        cookies, unparsed = cookie_metadata(headers)
        signature = tuple((c["name"], c["secure"], c["httponly"], c["samesite"]) for c in cookies)
        key = url, status, signature, len(headers), unparsed
        if key in self._indices:
            self.records[self._indices[key]]["response_count"] += 1
        else:
            self._indices[key] = len(self.records)
            self.records.append({"url": url, "status": status, "cookies": cookies,
                                 "set_cookie_header_count": len(headers),
                                 "unparsed_header_count": unparsed, "response_count": 1})
        # Same cookie shape on thousands of wordlist paths is not thousands of
        # terminal notices. The complete per-URL metadata remains in records.
        notice = urlsplit(url).netloc, signature, len(headers), unparsed
        if notice not in self._notices:
            if self.notify is not None and len(self._notices) < self.notice_limit:
                self.notify(self.records[self._indices[key]])
            elif self.notify is not None:
                self.suppressed_notices += 1
                if self.suppressed_notices == 1 and self.notify_limit is not None:
                    self.notify_limit()
            self._notices.add(notice)


def attach_cookie_recorder(engine, result, observer) -> None:
    def notify(record):
        names = ", ".join(cookie["name"] for cookie in record["cookies"]) or "unparsed names"
        metadata = []
        for cookie in record["cookies"]:
            flags = [flag for field, flag in (("secure", "Secure"), ("httponly", "HttpOnly"))
                     if cookie[field]]
            if cookie["samesite"] is not None:
                flags.append(f"SameSite={cookie['samesite']}")
            metadata.append(f"{cookie['name']}: {', '.join(flags) or 'selected attributes absent'}")
        details = "; ".join(metadata) or f"unparsed fields: {record['unparsed_header_count']}"
        observer.log(f"Set-Cookie: {names} · {details} · HTTP {record['status']} · {record['url']} "
                     "(header observed; values omitted, browser acceptance not established)",
                     0, style="cyan")

    def notify_limit():
        observer.log("Set-Cookie: live preview limited to 20 distinct metadata signatures; "
                     "per-URL header observations remain in JSON/HTML (values omitted).",
                     0, style="yellow")

    engine.cookie_recorder = CookieRecorder(result.cookie_observations, notify,
                                            notify_limit=notify_limit)
    result.cookie_observations_tracked = True
