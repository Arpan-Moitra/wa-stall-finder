"""Plain-language instructions built from the check results.

Used by the desktop window. It works only from the (already redacted)
findings, so it cannot show anything the report itself would not show.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from .checks import CheckResult

DELETE_ORDER = ("empty_text", "media_without_record", "bad_timestamps")
MAX_LISTED = 30

_PERSON = re.compile(r"^(\S+)@s\.whatsapp\.net \(chat #\d+\)$")
_GROUP = re.compile(r"^group '(.*)' \(chat #\d+\)$")

WHY = {
    "empty_text": "it is a text message with nothing stored inside it",
    "media_without_record": "its photo, video or file is missing from WhatsApp's records",
    "bad_timestamps": "its date is missing or impossible",
}


def chat_name(label: str) -> str:
    if m := _GROUP.match(label):
        return f"the group \"{m.group(1)}\""
    if m := _PERSON.match(label):
        number = m.group(1)
        return f"the chat with {'+' + number if number.isdigit() else number}"
    return label


def when(local_time: str) -> str:
    try:
        return datetime.strptime(local_time, "%Y-%m-%d %H:%M:%S %z").strftime("%d %b %Y at %H:%M")
    except ValueError:
        return "date unknown"


def _what(f: dict[str, Any]) -> str:
    kind = {"text": "text message", "no type": "message"}.get(f["type_label"], f["type_label"])
    who = {"sent": "you sent", "received": "you received"}.get(f["direction"], "")
    article = "an" if kind[:1] in "aeiou" else "a"
    return f"{article} {kind} {who}".strip()


def _neighbour(a: dict[str, Any]) -> str:
    time = when(a["local_time"])
    if a.get("text"):
        return f"\"{a['text']}\"  ({time})"
    kind = "text message" if a["type_label"] == "text" else a["type_label"]
    return f"a {kind} {'you sent' if a['direction'] == 'sent' else 'you received'}  ({time})"


def _message_block(n: int, f: dict[str, Any], check: str) -> list[str]:
    lines = [
        f"{n}.  In {chat_name(f['chat'])}",
        f"     When:  {when(f['local_time'])}",
        f"     What:  {_what(f)}",
    ]
    before, after = f.get("context_before", []), f.get("context_after", [])
    if before:
        lines.append(f"     It comes right AFTER:   {_neighbour(before[-1])}")
    if after:
        lines.append(f"     It comes right BEFORE:  {_neighbour(after[0])}")
    lines.append(f"     Why:   {WHY[check]}")
    lines.append("")
    return lines


def friendly_summary(results: list[CheckResult], *, stall_pct: float | None = None) -> str:
    by_name = {r.name: r for r in results}
    out: list[str] = []

    to_delete: list[tuple[str, dict[str, Any]]] = [
        (name, f)
        for name in DELETE_ORDER
        if (r := by_name.get(name)) is not None and r.status == "flagged"
        for f in r.findings
    ]
    total = sum(by_name[n].count for n in DELETE_ORDER if n in by_name and by_name[n].status == "flagged")
    big = [f for f in by_name["big_chats"].findings if f.get("flagged")] if "big_chats" in by_name else []
    integrity_bad = "integrity" in by_name and by_name["integrity"].status == "flagged"

    if integrity_bad:
        out += [
            "IMPORTANT: the backup file itself looks damaged.",
            "Make a fresh backup on the phone (WhatsApp > Settings > Chats > Chat backup > Back up),",
            "copy the new file to this computer and try again before deleting anything.",
            "",
        ]

    if total:
        noun = "message" if total == 1 else "messages"
        out += [
            f"RESULT:  Found {total} {noun} that could be stopping your transfer.",
            "",
            "WHAT TO DO  (on the Android phone, in WhatsApp)",
            "",
            "Delete the messages listed below, starting from number 1.",
            "To find one: open the chat, tap the three dots at the top, tap Search, and type a few",
            "words from the message that comes right before or after it.",
            "To delete: press and hold the message, tap the bin icon, choose \"Delete for me\".",
            "The message itself may look blank or broken. That is expected.",
            "",
        ]
        for n, (check, f) in enumerate(to_delete[:MAX_LISTED], 1):
            out += _message_block(n, f, check)
        if total > MAX_LISTED:
            out += [f"... and {total - MAX_LISTED} more. The full list is in the report folder.", ""]
    else:
        out += ["RESULT:  No obviously broken message was found.", ""]

    if big:
        out += ["VERY LARGE CHATS", ""]
        out += [f"  -  {chat_name(f['chat'])}: {f['reason']}" for f in big]
        out += [
            "",
            "Only if the transfer still fails after the steps above: export these chats if you want",
            "to keep them (open chat > three dots > More > Export chat), then delete them.",
            "",
        ]

    hint = by_name.get("stall_hint")
    if not total and hint is not None and hint.status == "info":
        est = hint.extra["estimated_message"]
        out += [
            f"Your transfer stops at {stall_pct:g}%. As a rough guess (not a certainty), that is around:",
            "",
            f"     {chat_name(est['chat'])}, {when(est['local_time'])}",
            "",
            "Look at the messages in that chat around that date. If one looks blank, broken or",
            "unusual, delete it and try the transfer again.",
            "",
        ]
    elif not total and not big:
        out += [
            "Type the percentage where your transfer stops into the box above and run again.",
            "The app will then point to the part of your chats to look at.",
            "",
        ]

    leftovers = sum(
        by_name[n].count for n in ("orphan_messages", "dangling_children")
        if n in by_name and by_name[n].status == "flagged"
    )
    if leftovers:
        out += [
            f"Also found {leftovers} leftover record(s) that cannot be seen or deleted in WhatsApp.",
            "You do not need to do anything about them. They are listed in the report folder.",
            "",
        ]

    out += ["AFTERWARDS", ""]
    if total or big:
        out += [
            "1.  Try the transfer to the iPhone again.",
            "2.  If it stops at a DIFFERENT percentage, that is progress. There is another broken",
            "    message. Make a new backup on the phone, copy it here and run this app again.",
            "3.  If it stops at the SAME percentage, run this app again with that percentage typed in.",
        ]
    else:
        out += ["Deleting messages in WhatsApp cannot be undone, so only delete what looks broken."]
    skipped = [r.name for r in results if r.status in ("skipped", "error") and r.name != "stall_hint"]
    if skipped:
        out += ["", f"Note: {len(skipped)} check(s) could not run on this backup ({', '.join(skipped)})."]
    return "\n".join(out)
