"""The diagnostic checks. Every query here is a SELECT or a read-only PRAGMA."""

from __future__ import annotations

import re
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .db import Schema, quote_ident

# --------------------------------------------------------------------------
# message.message_type codes.
#
# WhatsApp does not document these. The map is deliberately small: only codes
# a check depends on, plus a few labels that make the report readable.
# Cross-checked (Nov 2026) against KnugiHK/WhatsApp-Chat-Exporter's
# android_handler.py and faloppad/wa-transfer-doctor:
#   agreed by both sources : 0 text, 2 audio, 5 location, 15 deleted, 20 sticker
#   single source only     : 1 image, 3 video, 7 system, 9 document, 13 gif,
#                            42/43 view-once image/video, 82 view-once voice
# Because the media list rests partly on one source, media_without_record is a
# "suspect" check and the list can be replaced with --media-types.
# --------------------------------------------------------------------------
TEXT_TYPE = 0
MEDIA_TYPES: dict[int, str] = {
    1: "image",
    2: "audio/voice",
    3: "video",
    9: "document",
    13: "gif",
    20: "sticker",
}
VIEW_ONCE_TYPES: dict[int, str] = {
    42: "view-once image",
    43: "view-once video",
    82: "view-once voice",
}
OTHER_LABELS: dict[int, str] = {0: "text", 5: "location", 7: "system", 15: "deleted"}
TYPE_LABELS: dict[int, str] = {**OTHER_LABELS, **MEDIA_TYPES, **VIEW_ONCE_TYPES}

FUTURE_SLACK_MS = 24 * 3600 * 1000  # tolerate a day of clock or timezone skew
PREVIEW_CHARS = 80
STALL_NEIGHBOURS = 10

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f  ]+")


@dataclass
class Options:
    context: int = 3
    redact: bool = False
    full_integrity: bool = False
    stall_pct: float | None = None
    big_chat_messages: int = 100_000
    big_chat_bytes: int = 2 * 1024**3
    top: int = 10
    limit: int = 200
    media_types: frozenset[int] = frozenset(MEDIA_TYPES) | frozenset(VIEW_ONCE_TYPES)


@dataclass
class CheckResult:
    number: int
    name: str
    severity: str  # problem | suspect | experimental
    title: str
    status: str = "ok"  # ok | flagged | skipped | error | info
    count: int = 0  # how many rows were flagged in total
    findings: list[dict[str, Any]] = field(default_factory=list)  # detailed, capped at --limit
    truncated: bool = False
    notes: list[str] = field(default_factory=list)
    columns: list[str] = field(default_factory=list)  # CSV column order
    extra: dict[str, Any] = field(default_factory=dict)

    def skip(self, why: str) -> "CheckResult":
        self.status = "skipped"
        self.notes.append(why)
        return self

    def to_json(self) -> dict[str, Any]:
        return {
            "number": self.number,
            "name": self.name,
            "severity": self.severity,
            "title": self.title,
            "status": self.status,
            "count": self.count,
            "truncated": self.truncated,
            "notes": self.notes,
            "findings": self.findings,
            **({"details": self.extra} if self.extra else {}),
        }


MESSAGE_COLUMNS = [
    "message_id", "chat_row_id", "chat", "local_time", "timestamp_ms", "direction",
    "message_type", "type_label", "reason", "text", "text_length",
    "context_before", "context_after",
]


def human_bytes(n: int) -> str:
    value = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.2f} {unit}"
        value /= 1024
    return f"{n} B"  # pragma: no cover


def format_local_time(ts_ms: Any) -> str:
    if ts_ms is None:
        return "no timestamp"
    try:
        value = int(ts_ms)
        if value <= 0:
            return f"invalid timestamp ({value})"
        return datetime.fromtimestamp(value / 1000).astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
    except (ValueError, OverflowError, OSError, TypeError):
        return "invalid timestamp"


def mask_jid(jid: str) -> str:
    user, sep, domain = jid.partition("@")
    masked = "*" * max(len(user) - 2, 0) + user[-2:] if len(user) > 4 else "*" * len(user)
    return masked + sep + domain


def mask_name(name: str) -> str:
    return f"{name[:1]}*** ({len(name)} chars)"


class Inspector:
    """Shared helpers. All redaction happens here, at the moment a value is
    read, so the terminal, JSON and CSV outputs can only ever see redacted data."""

    def __init__(self, conn: sqlite3.Connection, schema: Schema, opts: Options) -> None:
        self.conn = conn
        self.schema = schema
        self.opts = opts
        self.now_ms = int(time.time() * 1000)
        self._chat_labels: dict[Any, str] = {}
        cols = schema.tables.get("message", [])
        self.msg_cols = set(cols)
        # WhatsApp's sentinel row: _id = 1, chat_row_id = -1, key_id = '-1'.
        # Matched by shape as well as by id, in case the row id differs.
        if "chat_row_id" not in self.msg_cols:
            self.sentinel = "(0)"
        elif "key_id" in self.msg_cols:
            self.sentinel = "(m.chat_row_id = -1 AND (m._id = 1 OR m.key_id = '-1'))"
        else:
            self.sentinel = "(m.chat_row_id = -1 AND m._id = 1)"
        self.not_sentinel = f"NOT {self.sentinel}"

    # -- message rows ------------------------------------------------------
    def _col(self, name: str) -> str:
        return f"m.{name}" if name in self.msg_cols else "NULL"

    def _select(self) -> str:
        text = "m.text_data" if "text_data" in self.msg_cols else "NULL"
        return (
            f"SELECT m._id, m.chat_row_id, {self._col('from_me')}, {self._col('timestamp')}, "
            f"{self._col('message_type')}, substr({text}, 1, {PREVIEW_CHARS + 1}), length({text}) "
            "FROM message m"
        )

    def chat_label(self, chat_row_id: Any) -> str:
        if chat_row_id in self._chat_labels:
            return self._chat_labels[chat_row_id]
        label = f"missing chat #{chat_row_id}"
        if self.schema.has("chat", "_id"):
            subject_col = "c.subject" if self.schema.has("chat", "subject") else "NULL"
            if self.schema.has("chat", "jid_row_id") and self.schema.has("jid", "_id", "raw_string"):
                sql = (
                    f"SELECT {subject_col}, j.raw_string FROM chat c "
                    "LEFT JOIN jid j ON j._id = c.jid_row_id WHERE c._id = ?"
                )
            else:
                sql = f"SELECT {subject_col}, NULL FROM chat c WHERE c._id = ?"
            row = self.conn.execute(sql, (chat_row_id,)).fetchone()
            if row is not None:
                subject, jid = row
                if subject:
                    name = mask_name(str(subject)) if self.opts.redact else self.clean(str(subject))
                    label = f"group '{name}' (chat #{chat_row_id})"
                elif jid:
                    shown = mask_jid(str(jid)) if self.opts.redact else self.clean(str(jid))
                    label = f"{shown} (chat #{chat_row_id})"
                else:
                    label = f"chat #{chat_row_id}"
        self._chat_labels[chat_row_id] = label
        return label

    @staticmethod
    def clean(text: str) -> str:
        """Collapse control characters so stored text cannot drive the terminal."""
        return _CONTROL.sub(" ", text).strip()

    def _text(self, preview: Any) -> str | None:
        if self.opts.redact or preview is None:
            return None
        text = self.clean(str(preview))
        return text[:PREVIEW_CHARS] + "…" if len(text) > PREVIEW_CHARS else text

    @staticmethod
    def _direction(from_me: Any) -> str:
        return {1: "sent", 0: "received"}.get(from_me, "unknown")

    @staticmethod
    def type_label(message_type: Any) -> str:
        if message_type is None:
            return "no type"
        return TYPE_LABELS.get(message_type, f"type {message_type}")

    def _anchor(self, row: tuple[Any, ...]) -> dict[str, Any]:
        mid, _chat, from_me, ts, mtype, preview, length = row
        return {
            "message_id": mid,
            "local_time": format_local_time(ts),
            "direction": self._direction(from_me),
            "type_label": self.type_label(mtype),
            "text": self._text(preview),
            "text_length": length,
        }

    def context(self, message_id: int, chat_row_id: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Neighbours in the same chat, by _id (insertion order), as search anchors."""
        n = self.opts.context
        if n <= 0:
            return [], []
        base = f"{self._select()} WHERE m.chat_row_id IS ? AND {self.not_sentinel} AND "
        before = self.conn.execute(
            base + "m._id < ? ORDER BY m._id DESC LIMIT ?", (chat_row_id, message_id, n)
        ).fetchall()
        after = self.conn.execute(
            base + "m._id > ? ORDER BY m._id ASC LIMIT ?", (chat_row_id, message_id, n)
        ).fetchall()
        return [self._anchor(r) for r in reversed(before)], [self._anchor(r) for r in after]

    def describe(self, row: tuple[Any, ...], reason: str, *, with_context: bool = True) -> dict[str, Any]:
        mid, chat, from_me, ts, mtype, preview, length = row
        before, after = self.context(mid, chat) if with_context else ([], [])
        return {
            "message_id": mid,
            "chat_row_id": chat,
            "chat": self.chat_label(chat),
            "local_time": format_local_time(ts),
            "timestamp_ms": ts,
            "direction": self._direction(from_me),
            "message_type": mtype,
            "type_label": self.type_label(mtype),
            "reason": reason,
            "text": self._text(preview),
            "text_length": length,
            "context_before": before,
            "context_after": after,
        }

    def flag_messages(self, result: CheckResult, where: str, params: tuple[Any, ...], reason: Any) -> None:
        """Fill ``result`` with messages matching ``where`` (sentinel excluded)."""
        cond = f"{self.not_sentinel} AND ({where})"
        result.columns = MESSAGE_COLUMNS
        result.count = self.conn.execute(
            f"SELECT COUNT(*) FROM message m WHERE {cond}", params
        ).fetchone()[0]
        rows = self.conn.execute(
            f"{self._select()} WHERE {cond} ORDER BY m._id LIMIT ?", (*params, self.opts.limit)
        ).fetchall()
        result.findings = [self.describe(r, reason(r) if callable(reason) else reason) for r in rows]
        result.truncated = result.count > len(rows)
        result.status = "flagged" if result.count else "ok"

    def total_messages(self) -> int:
        return self.conn.execute(
            f"SELECT COUNT(*) FROM message m WHERE {self.not_sentinel}"
        ).fetchone()[0]


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------
def check_integrity(ins: Inspector) -> CheckResult:
    pragma = "integrity_check" if ins.opts.full_integrity else "quick_check"
    r = CheckResult(1, "integrity", "problem", f"Database structure (PRAGMA {pragma})")
    r.columns = ["message"]
    rows = [str(x[0]) for x in ins.conn.execute(f"PRAGMA {pragma}")]
    if rows != ["ok"]:
        r.status = "flagged"
        r.count = len(rows)
        r.findings = [{"message": ins.clean(m)} for m in rows[: ins.opts.limit]]
        r.truncated = len(rows) > len(r.findings)
        r.notes.append(
            "The database file itself is damaged. This cannot be fixed by deleting messages; "
            "make a fresh backup and rerun before trusting the other checks."
        )
    return r


def check_empty_text(ins: Inspector) -> CheckResult:
    r = CheckResult(2, "empty_text", "problem", "Text messages with no text (NULL text_data)")
    if why := ins.schema.missing("message", "_id", "chat_row_id", "message_type", "text_data"):
        return r.skip(why)
    ins.flag_messages(
        r, "m.message_type = ? AND m.text_data IS NULL", (TEXT_TYPE,),
        "text message with NULL text_data",
    )
    return r


def check_media_without_record(ins: Inspector) -> CheckResult:
    r = CheckResult(3, "media_without_record", "suspect", "Media or view-once messages with no message_media row")
    why = ins.schema.missing("message", "_id", "chat_row_id", "message_type") or ins.schema.missing(
        "message_media", "message_row_id"
    )
    if why:
        return r.skip(why)
    types = sorted(ins.opts.media_types)
    if not types:
        return r.skip("no media type codes configured")
    marks = ",".join("?" * len(types))
    ins.flag_messages(
        r,
        f"m.message_type IN ({marks}) AND NOT EXISTS "
        "(SELECT 1 FROM message_media mm WHERE mm.message_row_id = m._id)",
        tuple(types),
        lambda row: f"{ins.type_label(row[4])} message has no message_media row",
    )
    r.notes.append(f"Type codes treated as media: {', '.join(map(str, types))}.")
    return r


def check_orphan_messages(ins: Inspector) -> CheckResult:
    r = CheckResult(4, "orphan_messages", "suspect", "Messages whose chat does not exist")
    why = ins.schema.missing("message", "_id", "chat_row_id") or ins.schema.missing("chat", "_id")
    if why:
        return r.skip(why)
    ins.flag_messages(
        r,
        "m.chat_row_id IS NULL OR NOT EXISTS (SELECT 1 FROM chat c WHERE c._id = m.chat_row_id)",
        (),
        lambda row: f"chat_row_id {row[1]} is not in the chat table",
    )
    if r.count:
        r.notes.append("These belong to no visible chat, so they cannot be deleted in the app. Report only.")
    return r


def check_dangling_children(ins: Inspector) -> CheckResult:
    r = CheckResult(5, "dangling_children", "suspect", "Rows in other tables pointing at a non-existent message")
    r.columns = ["table", "column", "rowid", "missing_message_id", "position_pct"]
    if why := ins.schema.missing("message", "_id"):
        return r.skip(why)
    targets = [
        (table, col)
        for table, cols in sorted(ins.schema.tables.items())
        for col in ("message_row_id", "parent_message_row_id")
        if col in cols
    ]
    if not targets:
        return r.skip("no table has a message_row_id or parent_message_row_id column")
    per_table: dict[str, int] = {}
    total = ins.total_messages()
    for table, col in targets:
        t, c = quote_ident(table), quote_ident(col)
        cond = f"x.{c} IS NOT NULL AND x.{c} > 0 AND NOT EXISTS (SELECT 1 FROM message m WHERE m._id = x.{c})"
        try:
            n = ins.conn.execute(f"SELECT COUNT(*) FROM {t} x WHERE {cond}").fetchone()[0]
            if not n:
                continue
            per_table[f"{table}.{col}"] = n
            room = ins.opts.limit - len(r.findings)
            if room > 0:
                try:
                    rows = ins.conn.execute(
                        f"SELECT x.rowid, x.{c} FROM {t} x WHERE {cond} ORDER BY x.{c} LIMIT ?", (room,)
                    ).fetchall()
                except sqlite3.Error:  # WITHOUT ROWID table
                    rows = ins.conn.execute(
                        f"SELECT NULL, x.{c} FROM {t} x WHERE {cond} ORDER BY x.{c} LIMIT ?", (room,)
                    ).fetchall()
                for rowid, missing in rows:
                    r.findings.append({
                        "table": table, "column": col, "rowid": rowid,
                        "missing_message_id": missing,
                        "position_pct": position_pct(ins, missing, total),
                    })
        except sqlite3.Error as e:
            r.notes.append(f"Could not read {table}.{col} ({type(e).__name__}); skipped that table.")
    r.count = sum(per_table.values())
    r.extra["per_table"] = per_table
    r.truncated = r.count > len(r.findings)
    r.status = "flagged" if r.count else "ok"
    if ins.schema.unreadable:
        r.notes.append(
            f"{len(ins.schema.unreadable)} table(s) could not be introspected (usually virtual "
            "tables this SQLite build cannot load) and were not examined."
        )
    if r.count:
        r.notes.append(
            "Leftovers from messages that no longer exist. Nothing to delete in the app; "
            "position_pct shows roughly where in the table the missing message used to sit."
        )
    return r


def check_bad_timestamps(ins: Inspector) -> CheckResult:
    r = CheckResult(6, "bad_timestamps", "suspect", "Messages with a NULL, zero or future timestamp")
    if why := ins.schema.missing("message", "_id", "chat_row_id", "timestamp"):
        return r.skip(why)
    cutoff = ins.now_ms + FUTURE_SLACK_MS

    def reason(row: tuple[Any, ...]) -> str:
        ts = row[3]
        if ts is None:
            return "timestamp is NULL"
        if isinstance(ts, (int, float)) and ts <= 0:
            return "timestamp is zero or negative"
        if isinstance(ts, (int, float)):
            return "timestamp is in the future"
        return "timestamp is not a number"

    ins.flag_messages(
        r,
        "m.timestamp IS NULL OR typeof(m.timestamp) NOT IN ('integer', 'real') "
        "OR m.timestamp <= 0 OR m.timestamp > ?",
        (cutoff,),
        reason,
    )
    return r


def check_big_chats(ins: Inspector) -> CheckResult:
    o = ins.opts
    r = CheckResult(7, "big_chats", "suspect", "Very large chats")
    r.columns = ["chat_row_id", "chat", "messages", "media_bytes", "media_size", "flagged", "reason"]
    if why := ins.schema.missing("message", "_id", "chat_row_id"):
        return r.skip(why)
    counts: dict[Any, int] = dict(
        ins.conn.execute(
            f"SELECT m.chat_row_id, COUNT(*) FROM message m WHERE {ins.not_sentinel} GROUP BY m.chat_row_id"
        ).fetchall()
    )
    media: dict[Any, int] = {}
    size_cols = [c for c in ("file_length", "file_size") if ins.schema.has("message_media", c)]
    if ins.schema.has("message_media", "message_row_id") and size_cols:
        # Schemas differ on which column carries the size; take the larger per row.
        parts = [f"COALESCE(mm.{c}, 0)" for c in size_cols]
        size = f"MAX({', '.join(parts)})" if len(parts) > 1 else parts[0]
        media = {
            chat: int(total or 0)
            for chat, total in ins.conn.execute(
                f"SELECT m.chat_row_id, SUM({size}) FROM message_media mm "
                "JOIN message m ON m._id = mm.message_row_id "
                f"WHERE {ins.not_sentinel} GROUP BY m.chat_row_id"
            )
        }
    else:
        r.notes.append("message_media has no size column here; chats are ranked by message count only.")

    def row(chat: Any) -> dict[str, Any]:
        n, size_b = counts.get(chat, 0), media.get(chat, 0)
        reasons = []
        if n >= o.big_chat_messages:
            reasons.append(f"{n:,} messages (threshold {o.big_chat_messages:,})")
        if size_b >= o.big_chat_bytes:
            reasons.append(f"{human_bytes(size_b)} of media (threshold {human_bytes(o.big_chat_bytes)})")
        return {
            "chat_row_id": chat, "chat": ins.chat_label(chat), "messages": n,
            "media_bytes": size_b, "media_size": human_bytes(size_b),
            "flagged": bool(reasons), "reason": "; ".join(reasons),
        }

    chats = set(counts) | set(media)
    by_messages = sorted(chats, key=lambda c: (-counts.get(c, 0), str(c)))[: o.top]
    by_media = [c for c in sorted(chats, key=lambda c: (-media.get(c, 0), str(c)))[: o.top] if media.get(c, 0)]
    flagged = [
        c for c in chats
        if counts.get(c, 0) >= o.big_chat_messages or media.get(c, 0) >= o.big_chat_bytes
    ]
    shown = list(dict.fromkeys([*flagged, *by_messages, *by_media]))
    rows = sorted((row(c) for c in shown), key=lambda d: (not d["flagged"], -d["messages"], -d["media_bytes"]))
    r.findings = rows
    r.count = len(flagged)
    r.status = "flagged" if flagged else "ok"
    r.notes.append(f"Listing the top {o.top} chats by message count and by media size, plus any over a threshold.")
    return r


def position_pct(ins: Inspector, message_id: Any, total: int) -> float | None:
    if not total or not isinstance(message_id, int):
        return None
    pos = ins.conn.execute(
        f"SELECT COUNT(*) FROM message m WHERE {ins.not_sentinel} AND m._id <= ?", (message_id,)
    ).fetchone()[0]
    return round(100.0 * pos / total, 3)


def check_stall_hint(ins: Inspector, earlier: list[CheckResult]) -> CheckResult:
    r = CheckResult(8, "stall_hint", "experimental", "Stall position hint (heuristic)")
    pct = ins.opts.stall_pct
    if pct is None:
        return r.skip("pass --stall-pct N (the percentage where the transfer stops) to enable")
    if why := ins.schema.missing("message", "_id", "chat_row_id"):
        return r.skip(why)
    total = ins.total_messages()
    if not total:
        return r.skip("the message table is empty")
    r.status = "info"
    r.notes.append(
        "HEURISTIC ONLY: this assumes the export walks the message table in _id order at an "
        "even pace, which WhatsApp does not document. Use it to prioritise, not to conclude."
    )
    k = min(total, max(1, round(pct / 100.0 * total)))
    row = ins.conn.execute(
        f"{ins._select()} WHERE {ins.not_sentinel} ORDER BY m._id LIMIT 1 OFFSET ?", (k - 1,)
    ).fetchone()
    estimate = ins.describe(row, f"estimated message at {pct:g}% of {total:,} messages")
    r.extra = {"stall_pct": pct, "total_messages": total, "estimated_position": k, "estimated_message": estimate}

    suspects: list[dict[str, Any]] = []
    for res in earlier:
        for f in res.findings:
            mid = f.get("message_id", f.get("missing_message_id"))
            if res.name == "big_chats" or mid is None:
                continue
            p = f.get("position_pct") or position_pct(ins, mid, total)
            if p is None:
                continue
            suspects.append({
                "check": res.name, "message_id": mid, "position_pct": p,
                "distance_pct": round(abs(p - pct), 3),
                "chat": f.get("chat", f"(no message; {f.get('table')}.{f.get('column')})"),
                "local_time": f.get("local_time", ""),
            })
    if suspects:
        suspects.sort(key=lambda s: (s["distance_pct"], s["message_id"]))
        r.columns = ["check", "message_id", "position_pct", "distance_pct", "chat", "local_time"]
        r.findings = suspects
        r.extra["mode"] = "ranked_suspects"
    else:
        lo = max(0, k - 1 - STALL_NEIGHBOURS)
        rows = ins.conn.execute(
            f"{ins._select()} WHERE {ins.not_sentinel} ORDER BY m._id LIMIT ? OFFSET ?",
            (2 * STALL_NEIGHBOURS + 1, lo),
        ).fetchall()
        r.columns = [c for c in MESSAGE_COLUMNS if not c.startswith("context_")]
        r.findings = [ins.describe(x, "near the estimated stall position", with_context=False) for x in rows]
        r.extra["mode"] = "neighbours"
        r.notes.append("No check flagged anything, so these are simply the messages around that position.")
    r.count = len(r.findings)
    return r


def run_all(conn: sqlite3.Connection, schema: Schema, opts: Options) -> list[CheckResult]:
    ins = Inspector(conn, schema, opts)
    results: list[CheckResult] = []
    for fn in (
        check_integrity, check_empty_text, check_media_without_record, check_orphan_messages,
        check_dangling_children, check_bad_timestamps, check_big_chats,
    ):
        try:
            results.append(fn(ins))
        except sqlite3.Error as e:
            proto = CheckResult(len(results) + 1, fn.__name__.removeprefix("check_"), "suspect", fn.__name__)
            proto.status = "error"
            proto.notes.append(f"The check could not run: {type(e).__name__}: {Inspector.clean(str(e))}")
            results.append(proto)
    try:
        results.append(check_stall_hint(ins, results))
    except sqlite3.Error as e:
        failed = CheckResult(8, "stall_hint", "experimental", "Stall position hint (heuristic)", status="error")
        failed.notes.append(f"The check could not run: {type(e).__name__}: {Inspector.clean(str(e))}")
        results.append(failed)
    return results
