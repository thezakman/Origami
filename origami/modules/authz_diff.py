"""Multi-identity authorization differential — the bridge from discovery to
access-control bugs (BOLA / BFLA / broken authentication; OWASP API #1/#3/#5).

Origami already maps the endpoint surface better than a blind fuzzer. This
module re-requests each discovered endpoint under several IDENTITIES and diffs
the responses. The low-false-positive signal is CONVERGENCE where the identities
should DIVERGE: a lower-or-unauthenticated identity that reaches the SAME
successful content as the privileged session the scan ran as — a missing
object/function-level authorization check. It also flags the inverse anomaly
(the privileged session is DENIED where a lesser identity is served).

Identities:
  * ``primary`` — the session the scan itself ran as (its ``-H`` headers; the
    privileged/reference identity, which may also be anonymous);
  * ``--as``    — extra labelled identities, each a set of auth headers, replayed
    against the same surface (the lower/other users to test);
  * ``anon``    — an implicit unauthenticated identity (auth headers stripped),
    added when the primary carries a credential so there's always a free
    anon-vs-authed diff. Suppressed with ``--no-anon``.

Read-only: every probe is a GET. Nothing is written, forged, or replayed onward.
This is the Autorize/Auth-Analyzer idea, native to the discovery engine and
anchored on the surface it already found.
"""

from __future__ import annotations

from dataclasses import dataclass

from origami.core.normalize import hamming
from origami.modules.session import _AUTH_HEADERS as AUTH_HEADER_NAMES

# Bodies within this simhash Hamming distance are "the same page" — the same
# threshold the classifier/baseline use for soft-404 sameness.
SIM_DISTANCE = 3


@dataclass(slots=True)
class Identity:
    """One request identity: a label + the COMPLETE headers to send for it."""
    label: str
    headers: dict[str, str]
    authed: bool                      # carries a session/credential header


@dataclass(slots=True)
class Obs:
    """One identity's observation of one URL."""
    label: str
    status: int
    simhash: int
    length: int
    ok: bool
    authed: bool


def _has_auth(headers: dict[str, str]) -> bool:
    return any(k.lower() in AUTH_HEADER_NAMES for k in (headers or {}))


def _strip_auth(headers: dict[str, str]) -> dict[str, str]:
    return {k: v for k, v in (headers or {}).items() if k.lower() not in AUTH_HEADER_NAMES}


def parse_as_specs(specs) -> dict[str, dict[str, str]]:
    """``--as 'label: Header: value'`` (repeatable) → ``{label: {Header: value}}``.

    Repeating the same label merges its headers, so a multi-header identity is
    ``--as 'admin: Cookie: sid=1' --as 'admin: X-Api-Key: k'``. Raises ValueError
    on a malformed spec (missing label or header).
    """
    out: dict[str, dict[str, str]] = {}
    for raw in specs or []:
        label, sep, rest = raw.partition(":")
        label = label.strip()
        if not sep or not label or ":" not in rest:
            raise ValueError(f"bad --as (need 'label: Header: value'): {raw!r}")
        name, _, value = rest.partition(":")
        name = name.strip()
        if not name:
            raise ValueError(f"bad --as (empty header name): {raw!r}")
        out.setdefault(label, {})[name] = value.strip()
    return out


def build_identities(base_headers: dict[str, str],
                     as_specs: dict[str, dict[str, str]],
                     include_anon: bool = True) -> list[Identity]:
    """Assemble the identity set from the scan's base headers + the ``--as`` map.

    Each ``--as`` identity sends the base NON-auth headers (User-Agent, custom
    ``-H`` that aren't credentials) plus its own auth headers — so it replaces the
    primary's credential rather than inheriting it. An implicit ``anon`` identity
    (auth stripped) is appended when some identity is authed and none is already
    anonymous, giving a free anon-vs-authed diff.
    """
    base_headers = base_headers or {}
    base_nonauth = _strip_auth(base_headers)
    ids = [Identity("primary", dict(base_headers), _has_auth(base_headers))]
    for label, hdrs in (as_specs or {}).items():
        if label == "primary":
            continue                      # reserved for the scan session
        ids.append(Identity(label, {**base_nonauth, **hdrs}, _has_auth(hdrs)))
    if include_anon and any(i.authed for i in ids) and not any(not i.authed for i in ids):
        ids.append(Identity("anon", dict(base_nonauth), False))
    return ids


def _reached(o: Obs) -> bool:
    """Served real content: a 2xx with a non-empty body."""
    return o.ok and 200 <= o.status < 300 and o.length > 0


def _blocked(o: Obs) -> bool:
    """Explicitly denied — an auth wall, not merely a soft miss."""
    return o.ok and o.status in (401, 403)


def diff_verdict(obs: dict[str, Obs], *, sensitive: bool) -> dict | None:
    """Classify one endpoint's per-identity observations into an access-control
    finding, or None. ``primary`` is the privileged reference; ``sensitive`` gates
    the convergence signal so legitimately-public content isn't flagged.

    Returns a dict ``{kind, confidence, tags, note}``:
      * ``authz-diff``  — the privileged primary is DENIED where a lesser identity
        is served (an access-control inconsistency; needs no sensitivity gate);
      * ``broken-auth`` — the anonymous identity reaches the SAME content as the
        authenticated session (missing authn/authz);
      * ``bola-lead``   — a distinct authed identity sees the SAME content as the
        primary (possible broken object/function-level authz — verify ownership).
    """
    primary = obs.get("primary")
    if primary is None:
        return None
    others = [o for o in obs.values() if o.label != "primary"]

    # (1) Inversion — the privileged session is walled off but a lesser identity
    # is served. Inherently anomalous, so no sensitivity gate.
    if _blocked(primary):
        got = sorted(o.label for o in others if _reached(o))
        if got:
            who = ", ".join(f"'{x}'" for x in got)
            return {"kind": "authz-diff", "confidence": 0.55, "tags": ["authz", "authz-diff"],
                    "repro_label": got[0],
                    "note": f"{who} reach content the primary session is DENIED "
                            f"({primary.status}) — access-control inconsistency"}
        return None

    # (2) Convergence — the privileged primary reached content and a LOWER identity
    # sees the same body. Only meaningful on non-public resources.
    if not _reached(primary) or not sensitive:
        return None
    same = [o for o in others if _reached(o)
            and hamming(o.simhash, primary.simhash) <= SIM_DISTANCE]
    if not same:
        return None
    anon = [o for o in same if not o.authed]
    if anon:
        return {"kind": "broken-auth", "confidence": 0.65,
                "tags": ["authz", "broken-auth", "disclosure"], "repro_label": anon[0].label,
                "note": f"unauthenticated ('{anon[0].label}') reaches the SAME content as the "
                        f"authenticated session — likely missing authentication/authorization"}
    labels = sorted(o.label for o in same)
    who = ", ".join(f"'{x}'" for x in labels)
    return {"kind": "bola-lead", "confidence": 0.5, "tags": ["authz", "bola-lead"],
            "repro_label": labels[0],
            "note": f"identit{'y' if len(labels) == 1 else 'ies'} {who} see the SAME content as "
                    f"'primary' — possible broken object/function-level authz (verify ownership)"}
