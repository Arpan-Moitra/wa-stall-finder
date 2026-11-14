"""Each check flags exactly the planted rows, and nothing on the clean control."""

from __future__ import annotations

import csv
import sqlite3

import synth

MESSAGE_CHECKS = ["empty_text", "media_without_record", "orphan_messages", "bad_timestamps"]


def test_each_check_flags_exactly_the_planted_rows(dirty, run):
    path, planted = dirty
    r = run(path)
    assert r.code == 0
    for name in MESSAGE_CHECKS:
        assert r.ids(name) == sorted(getattr(planted, name)), name
        assert r.check(name)["status"] == "flagged"
        assert r.check(name)["count"] == len(getattr(planted, name))
    assert r.check("integrity")["status"] == "ok"

    dangling = r.check("dangling_children")
    got = sorted((f["table"], f["column"], f["missing_message_id"]) for f in dangling["findings"])
    assert got == sorted(planted.dangling_children)
    assert dangling["count"] == 2


def test_sentinel_is_never_reported(dirty, run):
    path, _ = dirty
    r = run(path)
    for check in r.report["checks"]:
        for f in check["findings"]:
            assert f.get("message_id") != 1
            assert f.get("chat_row_id") != -1
            for anchor in f.get("context_before", []) + f.get("context_after", []):
                assert anchor["message_id"] != 1


def test_clean_control_flags_nothing(clean, run):
    path, _ = clean
    r = run(path)
    assert r.code == 0
    for check in r.report["checks"]:
        if check["name"] == "stall_hint":
            assert check["status"] == "skipped"
            continue
        assert check["status"] == "ok", check["name"]
        assert check["count"] == 0, check["name"]
    assert "Nothing deletable was flagged" in r.stdout


def test_reasons_and_types(dirty, run):
    path, planted = dirty
    r = run(path)
    reasons = {f["message_id"]: f["reason"] for f in r.check("bad_timestamps")["findings"]}
    null_id, zero_id, future_id = planted.bad_timestamps
    assert "NULL" in reasons[null_id]
    assert "zero" in reasons[zero_id]
    assert "future" in reasons[future_id]
    labels = sorted(f["type_label"] for f in r.check("media_without_record")["findings"])
    assert labels == ["image", "view-once image"]


def test_suspect_fields_and_context(dirty, run):
    path, planted = dirty
    r = run(path, "--context", "2")
    f = r.check("empty_text")["findings"][0]
    mid = planted.empty_text[0]
    assert f["chat_row_id"] == 1
    assert synth.PHONES[0] in f["chat"]
    assert f["direction"] in ("sent", "received")
    assert f["type_label"] == "text"
    assert f["local_time"].startswith("2023-11-")
    assert [a["message_id"] for a in f["context_before"]] == [mid - 2, mid - 1]
    assert [a["message_id"] for a in f["context_after"]] == [mid + 1, mid + 2]
    assert synth.SECRET in f["context_after"][0]["text"]

    group = r.check("media_without_record")["findings"][0]
    assert synth.GROUP_SUBJECT in group["chat"]
    orphan = r.check("orphan_messages")["findings"][0]
    assert "missing chat #999" in orphan["chat"]

    r0 = run(path, "--context", "0")
    assert r0.check("empty_text")["findings"][0]["context_before"] == []


def test_big_chats_thresholds_and_top_list(dirty, run):
    path, planted = dirty
    default = run(path)
    big = default.check("big_chats")
    assert big["status"] == "ok" and big["count"] == 0
    assert big["findings"][0]["chat_row_id"] == planted.big_message_chat  # top list is always there
    assert big["findings"][0]["messages"] == 60

    r = run(path, "--big-chat-messages", "50", "--big-chat-gb", "0.005", "--top", "2")
    big = r.check("big_chats")
    flagged = {f["chat_row_id"]: f for f in big["findings"] if f["flagged"]}
    assert set(flagged) == {planted.big_message_chat, planted.big_media_chat}
    assert big["count"] == 2
    assert flagged[planted.big_media_chat]["media_bytes"] == 3 * 2 * 1024 * 1024
    assert "media" in flagged[planted.big_media_chat]["reason"]
    assert "messages" in flagged[planted.big_message_chat]["reason"]


def test_missing_tables_and_columns_are_skipped(tmp_path, run):
    path = tmp_path / "nomedia.db"
    synth.build(path, drop=("message_media", "message.text_data", "message.timestamp"))
    r = run(path)
    assert r.code == 0
    for name in ("media_without_record", "empty_text", "bad_timestamps"):
        check = r.check(name)
        assert check["status"] == "skipped", name
        assert "not found" in check["notes"][0]
    assert r.check("orphan_messages")["status"] == "flagged"

    nochat = tmp_path / "nochat.db"
    planted = synth.build(nochat, drop=("chat",))
    r = run(nochat)
    assert r.check("orphan_messages")["status"] == "skipped"
    assert r.ids("empty_text") == planted.empty_text


def test_not_a_whatsapp_database(tmp_path, run):
    other = tmp_path / "other.db"
    conn = sqlite3.connect(other)
    conn.execute("CREATE TABLE t (x)")
    conn.commit()
    conn.close()
    r = run(other)
    assert r.code == 1
    assert "message" in r.stderr


def test_stall_hint_ranks_suspects(dirty, run):
    path, planted = dirty
    target = planted.empty_text[0]
    pct = 100.0 * (planted.message_ids.index(target) + 1) / planted.total_messages
    r = run(path, "--stall-pct", f"{pct:.4f}")
    hint = r.check("stall_hint")
    assert hint["status"] == "info"
    assert any("HEURISTIC" in n for n in hint["notes"])
    assert hint["details"]["estimated_message"]["message_id"] == target
    assert hint["details"]["mode"] == "ranked_suspects"
    assert hint["findings"][0]["message_id"] == target
    assert hint["findings"][0]["check"] == "empty_text"
    distances = [f["distance_pct"] for f in hint["findings"]]
    assert distances == sorted(distances)
    # every message-level suspect and both dangling references are ranked
    expected = len(planted.empty_text + planted.media_without_record + planted.orphan_messages
                   + planted.bad_timestamps) + len(planted.dangling_children)
    assert len(hint["findings"]) == expected
    assert "heuristic" in r.stdout.lower()


def test_stall_hint_lists_neighbours_when_nothing_flagged(clean, run):
    path, planted = clean
    r = run(path, "--stall-pct", "82")
    hint = r.check("stall_hint")
    assert hint["details"]["mode"] == "neighbours"
    k = round(0.82 * planted.total_messages)
    assert hint["details"]["estimated_message"]["message_id"] == planted.message_ids[k - 1]
    ids = [f["message_id"] for f in hint["findings"]]
    assert planted.message_ids[k - 1] in ids
    assert ids == sorted(ids) and 1 not in ids


def test_limit_caps_details_but_not_counts(dirty, run):
    path, planted = dirty
    r = run(path, "--limit", "1")
    ts = r.check("bad_timestamps")
    assert ts["count"] == 3 and len(ts["findings"]) == 1 and ts["truncated"] is True


def test_csv_files_match_json(dirty, run):
    path, planted = dirty
    r = run(path)
    for name in MESSAGE_CHECKS + ["integrity", "dangling_children", "big_chats"]:
        assert (r.out / f"{name}.csv").is_file(), name
    with open(r.out / "bad_timestamps.csv", newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert sorted(int(x["message_id"]) for x in rows) == sorted(planted.bad_timestamps)
    assert rows[0]["context_before"]


def test_integrity_failure_is_reported(dirty, run, tmp_path):
    path, _ = dirty
    damaged = tmp_path / "damaged.db"
    raw = bytearray(path.read_bytes())
    page_size = int.from_bytes(raw[16:18], "big")
    # scribble over the interior of a table page (page 3), leaving the header page intact
    raw[2 * page_size + 8 : 2 * page_size + 200] = b"\xff" * 192
    damaged.write_bytes(raw)
    r = run(damaged, "--full-integrity")
    assert r.code in (0, 1)  # a badly damaged file may be unreadable; it must not crash
    if r.code == 0:
        statuses = {c["name"]: c["status"] for c in r.report["checks"]}
        assert statuses["integrity"] == "flagged" or "error" in statuses.values()
