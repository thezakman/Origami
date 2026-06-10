"""Interactive keyboard control (dirb-style).

Puts the terminal in cbreak mode and watches stdin for single keypresses
while a scan runs, flipping flags on a shared ScanControl:

  * `n` — skip the rest of the current directory (next)
  * `q` — stop the scan early

No-op when stdin isn't a TTY (piped / headless), so it never interferes with
non-interactive runs.
"""

from __future__ import annotations

import asyncio
import contextlib
import sys

try:
    import termios
    import tty
    _HAS_TTY = True
except ImportError:  # non-POSIX
    _HAS_TTY = False


@contextlib.asynccontextmanager
async def keyboard_control(control):
    if not (_HAS_TTY and sys.stdin.isatty()):
        yield
        return

    loop = asyncio.get_event_loop()
    fd = sys.stdin.fileno()
    try:
        old = termios.tcgetattr(fd)
        tty.setcbreak(fd)
    except (termios.error, OSError):
        yield
        return

    def on_key() -> None:
        try:
            ch = sys.stdin.read(1)
        except (OSError, ValueError):
            return
        if ch in ("n", "N"):
            control.skip_prefix = True
        elif ch in ("q", "Q"):
            control.quit = True

    try:
        loop.add_reader(fd, on_key)
        yield
    finally:
        with contextlib.suppress(Exception):
            loop.remove_reader(fd)
        with contextlib.suppress(Exception):
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
