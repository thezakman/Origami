"""ASCII banner. Kept deliberately tiny and dependency-free."""

import sys

from origami import __version__

_ART = r"""
     /\                                 .
    /  \        .     TheZakMan - 2025 /_\
   / /\ \  _ __ _  __ _  __ _ _ __ ___  _
  /_/  \_\| '__| |/ _` |/ _` | '_ ` _ \| |
  \ \  / /| |  | | (_| | (_| | | | | | | |
   \ \/ / |_|  |_|\__, |\__,_|_| |_| |_|_|
    \  / adaptive |___/ content discovery
     \/
"""

_YELLOW = "\x1b[93m"   # bright yellow (the folded paper)
_DIM = "\x1b[2m"
_RESET = "\x1b[0m"


def show() -> None:
    if sys.stdout.isatty():
        print(f"{_YELLOW}{_ART}{_RESET}")
        print(f"  {_DIM}folds its strategy around the target{_RESET} "
              f"{_YELLOW}v{__version__}{_RESET}\n")
    else:
        print(_ART)
        print(f"  folds its strategy around the target - v{__version__}\n")
