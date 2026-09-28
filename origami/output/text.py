"""Escape terminal controls at presentation boundaries, preserving raw evidence."""

from __future__ import annotations

import unicodedata


def terminal_text(value: str, *, multiline: bool = False) -> str:
    parts = []
    for char in value:
        if char == "\n" and multiline:
            parts.append(char)
        elif unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"}:
            code = ord(char)
            parts.append(f"\\x{code:02x}" if code <= 255 else f"\\u{code:04x}")
        else:
            parts.append(char)
    return "".join(parts)
