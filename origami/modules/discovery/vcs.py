"""VCS / metadata tree reconstruction (§3.7 — discovery that compounds).

Origami already PROBES for `.git/`, `.svn/`, `.DS_Store` (backups.VCS_PROBES) and
reports them as findings. This turns each leak into an ENUMERATION: a served
`.git/index` lists every tracked file, a `.DS_Store` lists a directory's entries,
a `.svn/wc.db` lists the working copy — so one leak becomes the whole tree,
fetched from the webroot. Pure parsers here; the scanner fold does the fetching.
"""

from __future__ import annotations

import struct


# ---- .git/index (DIRC) --------------------------------------------------------

def _read_varint(body: bytes, off: int) -> tuple[int, int]:
    """Git's offset-encoding varint (v4 index path compression)."""
    val = 0
    while off < len(body):
        b = body[off]
        off += 1
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            break
        val += 1
    return val, off


def parse_git_index(body: bytes) -> list[str]:
    """Tracked file paths from a Git index (`.git/index`, DIRC v2–v4).

    Best-effort and defensive: returns whatever entries parse, `[]` on a body
    that isn't a recognizable index. Each entry has a 62-byte fixed head (stat +
    SHA-1 + flags); v2/v3 store the exact name length in the flags and NUL-pad to
    8-byte alignment; v4 prefix-compresses the path against the previous entry."""
    if len(body) < 12 or body[:4] != b"DIRC":
        return []
    try:
        version, count = struct.unpack(">II", body[4:12])
    except struct.error:
        return []
    if version not in (2, 3, 4) or count > 500_000:
        return []
    out: list[str] = []
    seen: set[str] = set()
    off, prev = 12, b""
    for _ in range(count):
        start = off
        if off + 62 > len(body):
            break
        try:
            flags = struct.unpack(">H", body[off + 60:off + 62])[0]
        except struct.error:
            break
        off += 62
        name_len = flags & 0x0FFF
        if version >= 3 and (flags & 0x4000):          # extended flag → 2 more bytes
            off += 2
        if version == 4:
            strip, off = _read_varint(body, off)
            end = body.find(b"\x00", off)
            if end == -1:
                break
            suffix = body[off:end]
            name = (prev[:len(prev) - strip] if 0 <= strip <= len(prev) else b"") + suffix
            off, prev = end + 1, name
        else:
            if name_len < 0x0FFF:
                name = body[off:off + name_len]
                off += name_len
            else:                                      # 0xFFF sentinel → read to NUL
                end = body.find(b"\x00", off)
                if end == -1:
                    break
                name, off = body[off:end], end
            off += 8 - ((off - start) % 8)             # NUL padding to 8-byte alignment
        p = name.decode("utf-8", "replace").strip().strip("\x00")
        if p and not p.startswith("/") and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def parse_git_config(body: bytes) -> list[str]:
    """Remote URLs declared in a `.git/config` — context (where the repo lives)."""
    out = []
    for line in body.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if line.lower().startswith("url ") or line.lower().startswith("url="):
            url = line.split("=", 1)[-1].strip()
            if url:
                out.append(url)
    return out


# ---- .DS_Store ----------------------------------------------------------------

# The data-type codes that terminate a .DS_Store record (validates a candidate).
_DS_TYPES = frozenset({b"bool", b"long", b"shor", b"type", b"blob", b"ustr",
                       b"comp", b"dutc"})


def parse_ds_store(body: bytes) -> list[str]:
    """Directory entry names from a macOS `.DS_Store`.

    Heuristic scan for the record shape — u32 name length, UTF-16BE name, 4-byte
    structure id, 4-byte data type — validated by the known data-type codes, which
    makes false matches vanishingly unlikely. Dedups; drops the `.` self entry."""
    out: list[str] = []
    seen: set[str] = set()
    n, off = len(body), 0
    while off + 8 < n:
        try:
            nlen = struct.unpack(">I", body[off:off + 4])[0]
        except struct.error:
            break
        rec_end = off + 4 + nlen * 2 + 8
        if 1 <= nlen <= 255 and rec_end <= n and body[rec_end - 4:rec_end] in _DS_TYPES:
            try:
                name = body[off + 4:off + 4 + nlen * 2].decode("utf-16-be")
            except UnicodeDecodeError:
                name = ""
            if name and name != "." and name not in seen:
                seen.add(name)
                out.append(name)
            off = rec_end
        else:
            off += 1
    return out


# ---- .svn/wc.db (SQLite) ------------------------------------------------------

def parse_svn(body: bytes) -> list[str]:
    """Working-copy file paths from a modern `.svn/wc.db` (SQLite ≥1.7). Uses
    in-memory deserialize (Python 3.11+) — no temp file. `[]` on anything else."""
    if not body.startswith(b"SQLite format 3\x00"):
        return []
    import sqlite3
    try:
        con = sqlite3.connect(":memory:")
        con.deserialize(body)
        try:
            rows = con.execute(
                "SELECT DISTINCT local_relpath FROM nodes "
                "WHERE local_relpath IS NOT NULL AND local_relpath != ''").fetchall()
        finally:
            con.close()
        return [r[0] for r in rows if r[0]]
    except Exception:                                  # noqa: BLE001 — malformed/foreign schema
        return []
