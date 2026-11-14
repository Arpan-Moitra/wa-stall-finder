"""Command-line entry point.

Exit codes: 0 the checks ran (whatever they found), 1 error, 2 usage.
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .checks import MEDIA_TYPES, VIEW_ONCE_TYPES, Options, run_all
from .db import Schema, open_bytes, open_plain
from .decrypt import DecryptError, decrypt_backup, is_sqlite_file
from .keys import KeyFormatError, read_key
from .report import prepare_out_dir, render_terminal, write_outputs

KEPT_NAME = "msgstore.decrypted.db"


def _non_negative(value: str) -> int:
    n = int(value)
    if n < 0:
        raise argparse.ArgumentTypeError("must be 0 or more")
    return n


def _positive(value: str) -> int:
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError("must be 1 or more")
    return n


def _pct(value: str) -> float:
    n = float(value.rstrip("%"))
    if not 0 <= n <= 100:
        raise argparse.ArgumentTypeError("must be between 0 and 100")
    return n


def _gb(value: str) -> float:
    n = float(value)
    if n <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return n


def _types(value: str) -> frozenset[int]:
    try:
        return frozenset(int(x) for x in value.split(",") if x.strip())
    except ValueError:
        raise argparse.ArgumentTypeError("expected comma-separated integers, e.g. 1,2,3") from None


def build_parser() -> argparse.ArgumentParser:
    default_types = sorted({**MEDIA_TYPES, **VIEW_ONCE_TYPES})
    p = argparse.ArgumentParser(
        prog="wa-stall-finder",
        # Without this, argparse would accept "--key <hex>" as a prefix of --key-file.
        allow_abbrev=False,
        description="Find the WhatsApp Android records likely to stall a Move to iOS transfer. "
        "Read-only: the backup is decrypted in memory and never modified.",
        epilog="The 64-digit key is asked for with a hidden prompt, or read from --key-file. "
        "It is never accepted as an argument.",
    )
    p.add_argument("input", type=Path, help="msgstore.db.crypt15, or an already-decrypted .db")
    p.add_argument("--key-file", type=Path, help="text file holding the 64-digit key")
    p.add_argument("--out", type=Path, default=Path("wa_report"), help="report directory (default ./wa_report, mode 0700)")
    p.add_argument("--context", type=_non_negative, default=3, metavar="N", help="neighbouring messages shown before and after each suspect (default 3)")
    p.add_argument("--redact", action="store_true", help="no message text; mask phone numbers and group names in every output")
    p.add_argument("--full-integrity", action="store_true", help="run PRAGMA integrity_check instead of quick_check (slower)")
    p.add_argument("--stall-pct", type=_pct, metavar="N", help="percentage where the transfer stalls; enables the experimental stall_hint")
    p.add_argument("--big-chat-messages", type=_positive, default=100_000, metavar="N", help="flag chats with at least N messages (default 100000)")
    p.add_argument("--big-chat-gb", type=_gb, default=2.0, metavar="GB", help="flag chats with at least this much media (default 2)")
    p.add_argument("--top", type=_positive, default=10, metavar="N", help="always list the N largest chats (default 10)")
    p.add_argument("--limit", type=_positive, default=200, metavar="N", help="detailed findings per check (default 200); totals are always exact")
    p.add_argument("--media-types", type=_types, default=frozenset(default_types), metavar="CODES", help=f"message_type codes treated as media (default {','.join(map(str, default_types))})")
    p.add_argument("--keep-decrypted", action="store_true", help=f"opt in to writing the decrypted database to <out>/{KEPT_NAME} (mode 0600)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _run(args: argparse.Namespace) -> int:
    src: Path = args.input
    if not src.is_file():
        print(f"error: {src} is not a file", file=sys.stderr)
        return 1
    opts = Options(
        context=args.context, redact=args.redact, full_integrity=args.full_integrity,
        stall_pct=args.stall_pct, big_chat_messages=args.big_chat_messages,
        big_chat_bytes=int(args.big_chat_gb * 1024**3), top=args.top, limit=args.limit,
        media_types=args.media_types,
    )
    plain = is_sqlite_file(src)
    warnings: list[str] = []
    data: bytes | None = None
    if not plain:
        key = read_key(args.key_file)
        try:
            data, warnings = decrypt_backup(src, key)
        finally:
            del key

    out: Path = args.out
    prepare_out_dir(out)
    if args.keep_decrypted:
        if data is None:
            warnings.append("--keep-decrypted ignored: the input is already a decrypted database.")
        else:
            kept = out / KEPT_NAME
            fd = os.open(kept, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            warnings.append(f"--keep-decrypted: your full message history is now in plain text at {kept}. Delete it when done.")

    opener = open_plain(src) if data is None else open_bytes(data)
    del data
    with opener as conn:
        schema = Schema(conn)
        if "message" not in schema.tables:
            print(
                "error: no 'message' table found. This is not a current WhatsApp message "
                "database (very old backups use a 'messages' table and are not supported).",
                file=sys.stderr,
            )
            return 1
        results = run_all(conn, schema, opts)

    meta = {
        "input_name": src.name,
        "input_kind": "decrypted SQLite file" if plain else "crypt15 backup, decrypted in memory",
        "redact": opts.redact,
        "tables_found": {
            t: schema.tables[t] for t in ("message", "chat", "jid", "message_media") if t in schema.tables
        },
        "options": {
            "context": opts.context, "full_integrity": opts.full_integrity, "stall_pct": opts.stall_pct,
            "big_chat_messages": opts.big_chat_messages, "big_chat_bytes": opts.big_chat_bytes,
            "top": opts.top, "limit": opts.limit, "media_types": sorted(opts.media_types),
        },
    }
    write_outputs(results, meta, warnings, out)
    print(render_terminal(results, meta, warnings, out))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)  # argparse exits with 2 on usage errors
    try:
        return _run(args)
    except KeyFormatError as e:
        print(f"usage error: {e}", file=sys.stderr)
        return 2
    except DecryptError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except (OSError, sqlite3.Error, MemoryError) as e:
        print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 1


def entry_point() -> None:
    sys.exit(main())
