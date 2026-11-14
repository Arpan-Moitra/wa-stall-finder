"""Terminal report, report.json and per-check CSV files.

Everything rendered here comes from CheckResult objects that were already
redacted when they were built, so no output path can bypass --redact.
"""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, TextIO

from . import __version__
from .checks import CheckResult

TERMINAL_MAX_FINDINGS = 25
DELETE_ORDER = ("empty_text", "media_without_record", "bad_timestamps", "big_chats")
BADGE = {"ok": "ok", "flagged": "FLAGGED", "skipped": "skipped", "error": "ERROR", "info": "info"}


def prepare_out_dir(out: Path) -> None:
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(out, 0o700)  # no effect on Windows, where the user profile's ACLs apply


def _open_private(path: Path) -> TextIO:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    if hasattr(os, "fchmod"):  # not available on Windows
        os.fchmod(fd, 0o600)
    return os.fdopen(fd, "w", encoding="utf-8", newline="")


def _anchor_line(a: dict[str, Any]) -> str:
    text = f' "{a["text"]}"' if a.get("text") else (
        f" [{a['text_length']} chars]" if a.get("text_length") else ""
    )
    return f"#{a['message_id']} {a['local_time']} {a['direction']} {a['type_label']}{text}"


def _csv_cell(value: Any) -> Any:
    if isinstance(value, list):
        value = " | ".join(_anchor_line(a) for a in value)
    if value is None:
        return ""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@"):
        return "'" + value  # stop spreadsheet apps treating message text as a formula
    return value


def build_summary(results: list[CheckResult]) -> tuple[list[str], list[str]]:
    by_name = {r.name: r for r in results}
    summary: list[str] = []
    steps: list[str] = []

    integrity = by_name.get("integrity")
    if integrity and integrity.status == "flagged":
        summary.append("0. integrity: the database file is structurally damaged. Deal with this first.")
        steps.append(
            "Make a fresh end-to-end encrypted backup and rerun. If integrity still fails, "
            "in-app deletion may not be enough."
        )

    rank = 0
    for name in DELETE_ORDER:
        r = by_name.get(name)
        if r is None or r.status != "flagged":
            continue
        rank += 1
        what = "chat(s)" if name == "big_chats" else "message(s)"
        summary.append(f"{rank}. {name} (check {r.number}, {r.severity}): {r.count} {what}")
    for name in ("orphan_messages", "dangling_children"):
        r = by_name.get(name)
        if r is not None and r.status == "flagged":
            summary.append(f"-  {name} (check {r.number}): {r.count} row(s), report only, not deletable in the app")
    for r in results:
        if r.status in ("skipped", "error") and r.name != "stall_hint":
            summary.append(f"-  {r.name} (check {r.number}): {r.status}, {r.notes[0] if r.notes else ''}")

    if rank:
        steps.append(
            "On the Android phone, delete the flagged items in WhatsApp in this order: "
            "empty_text (2), media_without_record (3), bad_timestamps (6), then big_chats (7). "
            "Find each one by opening the chat and searching for the neighbouring messages listed."
        )
        steps.append(
            "For big_chats, export the chat first if you need it, then clear or delete it; "
            "only do this if the earlier deletions did not fix the transfer."
        )
        steps.append("Retry the Move to iOS transfer.")
        steps.append(
            "If it now stalls at a DIFFERENT percentage, that is progress: another bad record "
            "remains. Make a new backup and rerun this tool."
        )
        steps.append("If it stalls at the SAME percentage, rerun with --stall-pct to look near that position.")
    else:
        summary.append("Nothing deletable was flagged by checks 2, 3, 6 or 7.")
        steps.append(
            "Rerun with --stall-pct N (your stall percentage) to list the messages near that "
            "position, and try deleting the ones that look unusual."
        )
        steps.append("If the percentage changes after a deletion, another bad record remains: rerun.")
    return summary, steps


def render_terminal(
    results: list[CheckResult], meta: dict[str, Any], warnings: list[str], out: Path
) -> str:
    lines: list[str] = []
    add = lines.append
    add(f"wa-stall-finder {__version__}  (read-only diagnostic; nothing was modified)")
    add(f"Input: {meta['input_name']} ({meta['input_kind']})   redaction: {'ON' if meta['redact'] else 'off'}")
    for w in warnings:
        add(f"WARNING: {w}")
    add("")
    for r in results:
        head = f"[{r.number}] {r.name} [{r.severity}]  {BADGE[r.status]}"
        if r.status == "flagged":
            head += f": {r.count}"
        add(head)
        add(f"    {r.title}")
        for f in r.findings[:TERMINAL_MAX_FINDINGS] if r.name != "stall_hint" else []:
            add(_finding_block(f))
        if r.name == "stall_hint" and r.status == "info":
            est = r.extra["estimated_message"]
            add(f"    Estimated message at {r.extra['stall_pct']:g}%: position "
                f"{r.extra['estimated_position']:,} of {r.extra['total_messages']:,}")
            add(_finding_block(est))
            label = "Suspects ranked by distance from that position:" if r.extra["mode"] == "ranked_suspects" \
                else "Messages around that position:"
            add(f"    {label}")
            for f in r.findings[:TERMINAL_MAX_FINDINGS]:
                if r.extra["mode"] == "ranked_suspects":
                    add(f"      {f['distance_pct']:>7.3f} pts away  #{f['message_id']} at {f['position_pct']}%"
                        f"  {f['check']}  {f['chat']}  {f['local_time']}")
                else:
                    add("      " + _anchor_line(f) + f"  {f['chat']}")
        hidden = (r.count if r.name != "big_chats" else len(r.findings)) - TERMINAL_MAX_FINDINGS
        if r.findings and hidden > 0 and r.name != "stall_hint":
            add(f"    … {hidden} more in {r.name}.csv")
        if r.truncated:
            add(f"    (details limited to the first {len(r.findings)}; raise --limit for more)")
        for n in r.notes:
            add(f"    note: {n}")
        add("")
    summary, steps = build_summary(results)
    add("SUMMARY (in priority order)")
    lines.extend(f"  {s}" for s in summary)
    add("")
    add("NEXT STEPS")
    lines.extend(f"  {i}. {s}" for i, s in enumerate(steps, 1))
    add("")
    add(f"Full report: {out / 'report.json'} and one CSV per check in {out}")
    if not meta["redact"]:
        add("These files contain message text and phone numbers. Delete them when done, or use --redact.")
    return "\n".join(lines)


def _finding_block(f: dict[str, Any]) -> str:
    if "message_id" in f and "direction" in f:
        text = f' "{f["text"]}"' if f.get("text") else (
            f" [{f['text_length']} chars]" if f.get("text_length") else ""
        )
        out = [
            f"    * message #{f['message_id']} in {f['chat']}",
            f"      {f['local_time']} | {f['direction']} | {f['type_label']}{text}",
            f"      why: {f['reason']}",
        ]
        out += [f"      before: {_anchor_line(a)}" for a in f.get("context_before", [])]
        out += [f"      after:  {_anchor_line(a)}" for a in f.get("context_after", [])]
        return "\n".join(out)
    if "messages" in f:
        mark = "FLAGGED " if f["flagged"] else ""
        why = f"  <- {f['reason']}" if f["reason"] else ""
        return f"    * {mark}{f['chat']}: {f['messages']:,} messages, {f['media_size']} media{why}"
    return "    * " + ", ".join(f"{k}={v}" for k, v in f.items())


def write_outputs(
    results: list[CheckResult], meta: dict[str, Any], warnings: list[str], out: Path
) -> None:
    summary, steps = build_summary(results)
    doc = {
        "tool": "wa-stall-finder",
        "version": __version__,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "input": {"name": meta["input_name"], "kind": meta["input_kind"]},
        "options": meta["options"],
        "redacted": meta["redact"],
        "warnings": warnings,
        "tables_found": meta["tables_found"],
        "checks": [r.to_json() for r in results],
        "summary": summary,
        "next_steps": steps,
    }
    with _open_private(out / "report.json") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False, default=str)
        f.write("\n")
    for r in results:
        if not r.columns:
            continue
        with _open_private(out / f"{r.name}.csv") as f:
            w = csv.writer(f)
            w.writerow(r.columns)
            for finding in r.findings:
                w.writerow([_csv_cell(finding.get(c)) for c in r.columns])
