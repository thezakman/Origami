"""Conservative response fingerprints for presentation, independent of calibration."""

from __future__ import annotations

from hashlib import sha256
from html import escape
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlsplit, urlunsplit

if TYPE_CHECKING:
    from origami.core.response_classifier import Finding


def body_digests(body: bytes, url: str, location: str = "") -> tuple[str, str]:
    """Hash captured bytes; for redirects also mask only the echoed destination.

    Unlike the calibration simhash, these digests preserve HTML attributes,
    numbers, case and tokens. No near-hash or size-only equivalence is inferred.
    The redirect digest allows a boilerplate page echoing its Location to compare
    equal; the destination itself must still match the separate redirect key.
    """
    raw = sha256(body).hexdigest()
    if not location:
        return raw, ""
    try:
        absolute = urljoin(url, location)
        parts = urlsplit(absolute)
    except ValueError:
        return raw, ""                    # malformed server Location cannot crash a fetch
    relative = urlunsplit(("", "", parts.path, parts.query, parts.fragment))
    echoes = {location, absolute, relative}
    echoes |= {escape(value, quote=True) for value in echoes}
    normalized = body
    for value in sorted(echoes, key=len, reverse=True):
        if value:
            normalized = normalized.replace(value.encode("utf-8"), b"{redirect-destination}")
    return raw, sha256(normalized).hexdigest()


def presentation_key(finding: Finding) -> tuple | None:
    """A grouping key, or None when evidence is insufficient or needs its own row.

    Only plain discovery observations can be muted. Explicit contract endpoints,
    reproduction-bearing results and content/behavior alerts remain visible.
    Truncated and legacy bodies cannot establish complete-body equivalence.
    """
    digest = finding.body_digest
    if not digest or finding.truncated:
        return None
    if finding.origin not in {
        "target", "js", "wordlist", "priority", "memory", "backup", "recursion", "harvest",
    } or finding.repro:
        return None
    if set(finding.tags) - {"admin", "auth", "api", "config", "source", "disclosure", "upload", "debug"}:
        return None
    try:
        source = urlsplit(finding.url)
    except ValueError:
        return None
    media = finding.content_type.strip().lower()
    location = finding.location
    redirect: tuple = ()
    route = ""
    if 300 <= finding.status < 400:
        if not location or not finding.redirect_digest:
            return None
        try:
            destination = urlsplit(urljoin(finding.url, location))
        except ValueError:
            return None
        # Group slash/case-query variants only on the same source route. Different
        # directory names are useful finds even when their redirect boilerplate matches.
        route = source.path.rstrip("/")
        query = "{request-query}" if destination.query == source.query else destination.query
        redirect = (destination.scheme, destination.netloc, destination.path, query,
                    destination.fragment)
        digest = finding.redirect_digest
    return (source.scheme, source.netloc, route, finding.status, media, redirect, digest,
            finding.header_digest, tuple(sorted(finding.tags)), finding.note)
