"""Synthetic msgstore generator. Everything here is invented test data.

Builds a small database in the modern WhatsApp Android layout with exactly one
planted defect (or one small group of defects) per check, the sentinel row, and
healthy control rows that sit right next to each defect. ``clean=True`` builds
the same database with no defects.

Run directly to get a fixture to try the CLI on:
    python tests/synth.py /tmp/synthetic.db
"""

from __future__ import annotations

import sqlite3
import sys
import time
import zlib
from dataclasses import dataclass, field
from pathlib import Path

SECRET = "SECRET-TEXT"
GROUP_SUBJECT = "Family Reunion Planning"
PHONES = ["919876543210", "447700900123", "15551234567", "4915112345678"]
BASE_TS = 1_700_000_000_000  # ms

SCHEMA = """
CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string TEXT);
CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER, subject TEXT);
CREATE TABLE message (
    _id INTEGER PRIMARY KEY, chat_row_id INTEGER, key_id TEXT, from_me INTEGER,
    timestamp INTEGER, message_type INTEGER, text_data TEXT);
CREATE TABLE message_media (
    message_row_id INTEGER PRIMARY KEY, chat_row_id INTEGER,
    file_size INTEGER, file_length INTEGER, file_path TEXT);
CREATE TABLE receipt_user (_id INTEGER PRIMARY KEY, message_row_id INTEGER, receipt_timestamp INTEGER);
CREATE TABLE message_add_on (_id INTEGER PRIMARY KEY, parent_message_row_id INTEGER, add_on_type INTEGER);
CREATE TABLE message_thumbnail (message_row_id INTEGER PRIMARY KEY, thumbnail BLOB);
CREATE TABLE props (_id INTEGER PRIMARY KEY, key TEXT, value TEXT);
"""


@dataclass
class Planted:
    empty_text: list[int] = field(default_factory=list)
    media_without_record: list[int] = field(default_factory=list)
    orphan_messages: list[int] = field(default_factory=list)
    dangling_children: list[tuple[str, str, int]] = field(default_factory=list)
    bad_timestamps: list[int] = field(default_factory=list)
    big_message_chat: int = 4
    big_media_chat: int = 5
    total_messages: int = 0  # excluding the sentinel
    message_ids: list[int] = field(default_factory=list)


def build(path: Path, *, clean: bool = False, drop: tuple[str, ...] = ()) -> Planted:
    """Create the database at ``path``. ``drop`` removes tables or 'table.column'."""
    planted = Planted()
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    conn.executemany(
        "INSERT INTO jid VALUES (?, ?)",
        [
            (1, f"{PHONES[0]}@s.whatsapp.net"),
            (2, f"{PHONES[0]}-1500000000@g.us"),
            (3, f"{PHONES[1]}@s.whatsapp.net"),
            (4, f"{PHONES[2]}@s.whatsapp.net"),
            (5, f"{PHONES[3]}@s.whatsapp.net"),
        ],
    )
    conn.executemany(
        "INSERT INTO chat VALUES (?, ?, ?)",
        [(1, 1, None), (2, 2, GROUP_SUBJECT), (3, 3, None), (4, 4, None), (5, 5, None)],
    )
    # The sentinel is built to trip empty_text, bad_timestamps and orphan_messages
    # if a check ever forgets to exclude it.
    conn.execute("INSERT INTO message VALUES (1, -1, '-1', 0, 0, 0, NULL)")

    next_id = 2
    AUTO = object()

    def add(chat: int, mtype: int = 0, text: object = AUTO, ts: object = AUTO, media: int | None = None) -> int:
        nonlocal next_id
        mid = next_id
        next_id += 1
        body = f"{SECRET}-{mid} hello" if text is AUTO and mtype == 0 else (None if text is AUTO else text)
        stamp = BASE_TS + mid * 60_000 if ts is AUTO else ts
        conn.execute(
            "INSERT INTO message VALUES (?, ?, ?, ?, ?, ?, ?)",
            (mid, chat, f"KEY{mid:06d}", mid % 2, stamp, mtype, body),
        )
        if media is not None:
            # like current schemas: the real size lives in file_length
            conn.execute(
                "INSERT INTO message_media VALUES (?, ?, 0, ?, ?)",
                (mid, chat, media, f"Media/{SECRET}-file-{mid}.bin"),
            )
        planted.message_ids.append(mid)
        return mid

    # chat 1: empty_text, surrounded by healthy rows and look-alike controls
    for _ in range(10):
        add(1)
    add(1, mtype=7, text=None)   # system message: NULL text is normal
    add(1, mtype=15, text=None)  # deleted message: NULL text is normal
    add(1, mtype=0, text="")     # empty string is not NULL
    planted.empty_text.append(add(1) if clean else add(1, mtype=0, text=None))
    for _ in range(5):
        add(1)

    # chat 2 (group): media_without_record
    for _ in range(8):
        add(2)
    add(2, mtype=1, text=f"{SECRET} caption", media=40_000)
    planted.media_without_record.append(add(2, mtype=1, media=1000) if clean else add(2, mtype=1))
    planted.media_without_record.append(add(2, mtype=42, media=1000) if clean else add(2, mtype=42))
    add(2, mtype=3, media=90_000)
    add(2, mtype=5)  # location: not a media type, has no media row by design
    for _ in range(4):
        add(2)

    # chat 3: bad_timestamps
    for _ in range(6):
        add(3)
    future = int(time.time() * 1000) + 400 * 86_400_000
    for bad in (None, 0, future):
        planted.bad_timestamps.append(add(3) if clean else add(3, ts=bad))
    for _ in range(6):
        add(3)

    # orphan message: its chat does not exist
    planted.orphan_messages.append(add(3) if clean else add(999))

    # chat 4: many messages
    for _ in range(60):
        add(4)

    # chat 5: heavy media
    for _ in range(3):
        add(5, mtype=9, media=2 * 1024 * 1024)
    for _ in range(2):
        add(5)

    # child tables: valid rows plus one dangling row each
    conn.executemany("INSERT INTO receipt_user VALUES (?, ?, ?)", [(i, i + 1, BASE_TS) for i in range(1, 6)])
    conn.executemany("INSERT INTO message_add_on VALUES (?, ?, 1)", [(i, i + 10) for i in range(1, 4)])
    conn.execute("INSERT INTO message_thumbnail VALUES (5, x'00ff')")
    conn.execute("INSERT INTO receipt_user VALUES (50, 1, ?)", (BASE_TS,))  # points at the sentinel: fine
    if not clean:
        conn.execute("INSERT INTO receipt_user VALUES (99, 99999, ?)", (BASE_TS,))
        conn.execute("INSERT INTO message_add_on VALUES (77, 88888, 1)")
        planted.dangling_children = [("message_add_on", "parent_message_row_id", 88888),
                                     ("receipt_user", "message_row_id", 99999)]

    for item in drop:
        table, _, column = item.partition(".")
        conn.execute(f"ALTER TABLE {table} DROP COLUMN {column}" if column else f"DROP TABLE {table}")
    if clean:
        for name in ("empty_text", "media_without_record", "orphan_messages", "bad_timestamps"):
            getattr(planted, name).clear()
    planted.total_messages = len(planted.message_ids)
    conn.commit()
    conn.execute("VACUUM")
    conn.close()
    return planted


def encrypt_crypt15(db_bytes: bytes, key_hex: str) -> bytes:
    """Wrap a database the way WhatsApp does: zlib, then AES-GCM in a crypt15 container."""
    from wa_crypt_tools.lib.db.db15 import Database15
    from wa_crypt_tools.lib.key.keyfactory import KeyFactory
    from wa_crypt_tools.lib.props import Props

    key = KeyFactory.from_hex(key_hex)
    return Database15(key=key).encrypt(key, Props(), zlib.compress(db_bytes, 1))


if __name__ == "__main__":
    target = Path(sys.argv[1])
    info = build(target)
    print(f"wrote {target} with {info.total_messages} synthetic messages")
