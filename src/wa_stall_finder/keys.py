"""Reading and validating the 64-digit end-to-end backup key.

The key is only ever taken from a hidden prompt or a file. It is never accepted
on the command line or from the environment, and no message produced here
contains any part of it.
"""

from __future__ import annotations

import getpass
import re
import stat
import sys
from pathlib import Path

_KEY_RE = re.compile(r"[0-9a-f]{64}")


class KeyFormatError(ValueError):
    """The supplied key is not 64 hex digits. The message never echoes the key."""


def normalise_key(raw: str) -> str:
    """Strip all whitespace, lowercase, and validate. Returns 64 lowercase hex digits."""
    cleaned = "".join(raw.split()).lower()
    if not _KEY_RE.fullmatch(cleaned):
        raise KeyFormatError(
            f"the key must be exactly 64 hex digits (0-9, a-f); got {len(cleaned)} "
            "characters after removing whitespace"
            + ("" if len(cleaned) != 64 else ", some of which are not hex digits")
        )
    return cleaned


def read_key(key_file: Path | None) -> str:
    """Read the key from ``key_file`` if given, otherwise from a hidden prompt."""
    if key_file is not None:
        try:
            mode = key_file.stat().st_mode
            raw = key_file.read_text(encoding="utf-8", errors="strict")
        except UnicodeDecodeError:
            raise KeyFormatError(
                "the key file is not text. It should contain the 64-digit key shown by "
                "WhatsApp, not an encrypted_backup.key binary file"
            ) from None
        if stat.S_IMODE(mode) & 0o077:
            print(
                "warning: the key file is readable by other users; consider chmod 600",
                file=sys.stderr,
            )
        return normalise_key(raw)
    return normalise_key(getpass.getpass("64-digit backup key (input hidden): "))
