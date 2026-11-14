"""Read-only behaviour, redaction, key handling, decryption and exit codes."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import sqlite3
import stat
import tempfile
from pathlib import Path

import pytest

import synth

posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
from wa_stall_finder import cli, db, keys
from wa_stall_finder.decrypt import SQLITE_MAGIC, DecryptError, decrypt_backup


def snapshot(directory: Path) -> dict[str, str]:
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(directory.iterdir())}


def sqlite_files_under(root: Path) -> list[Path]:
    found = []
    for p in root.rglob("*"):
        if p.is_file():
            with open(p, "rb") as f:
                if f.read(16) == SQLITE_MAGIC:
                    found.append(p)
    return found


# ---------------------------------------------------------------- read-only
def test_plain_input_is_byte_identical(dirty, run):
    path, _ = dirty
    before = snapshot(path.parent)
    r = run(path, "--full-integrity", "--stall-pct", "50")
    assert r.code == 0
    assert snapshot(path.parent) == before  # same bytes, and no -journal/-wal/-shm created


def test_encrypted_input_and_key_file_are_byte_identical(encrypted, run):
    crypt, key_file, _ = encrypted
    before = snapshot(crypt.parent)
    r = run(crypt, "--key-file", str(key_file))
    assert r.code == 0
    assert snapshot(crypt.parent) == before


def test_connections_refuse_writes(dirty):
    path, _ = dirty
    with db.open_plain(path) as conn:
        assert conn.execute("PRAGMA query_only").fetchone()[0] == 1
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("DELETE FROM message")
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("CREATE TABLE x (y)")
    with db.open_bytes(path.read_bytes()) as conn:
        assert conn.execute("PRAGMA query_only").fetchone()[0] == 1
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("UPDATE message SET text_data = 'x'")


def test_source_has_no_write_statements_or_network():
    src = Path(cli.__file__).parent
    code = "\n".join(p.read_text() for p in src.glob("*.py"))
    assert not re.search(r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|REPLACE)\s", code)
    assert not re.search(r"^\s*(import|from)\s+(socket|urllib\.request|http|requests|ssl|ftplib|subprocess)\b",
                         code, re.M)


# ------------------------------------------------------------ no plaintext
def test_no_plaintext_on_disk_by_default(encrypted, run, tmp_path, monkeypatch):
    crypt, key_file, _ = encrypted
    scratch = tmp_path / "tmpdir"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    r = run(crypt, "--key-file", str(key_file))
    assert r.code == 0
    assert list(scratch.iterdir()) == []
    assert sqlite_files_under(r.out) == []
    assert "decrypted in memory" in r.stdout


@posix_only
def test_keep_decrypted_is_opt_in(encrypted, run, dirty):
    crypt, key_file, _ = encrypted
    r = run(crypt, "--key-file", str(key_file), "--keep-decrypted")
    kept = r.out / cli.KEPT_NAME
    assert sqlite_files_under(r.out) == [kept]
    assert stat.S_IMODE(kept.stat().st_mode) == 0o600
    assert kept.read_bytes() == dirty[0].read_bytes()
    assert "plain text" in r.stdout


@posix_only
def test_tempfile_fallback_is_private_and_removed(dirty):
    path, _ = dirty
    with db.open_bytes(path.read_bytes(), force_tempfile=True) as conn:
        tmp = Path(conn.execute("PRAGMA database_list").fetchone()[2])
        assert stat.S_IMODE(tmp.stat().st_mode) == 0o600
        assert stat.S_IMODE(tmp.parent.stat().st_mode) == 0o700
        assert conn.execute("SELECT COUNT(*) FROM message").fetchone()[0] > 100
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("DELETE FROM message")
    assert not tmp.exists() and not tmp.parent.exists()


def test_tempfile_fallback_removed_on_error(dirty):
    path, _ = dirty
    with pytest.raises(RuntimeError):
        with db.open_bytes(path.read_bytes(), force_tempfile=True) as conn:
            tmp = Path(conn.execute("PRAGMA database_list").fetchone()[2])
            raise RuntimeError("boom")
    assert not tmp.parent.exists()


@posix_only
def test_output_permissions(dirty, run):
    path, _ = dirty
    r = run(path)
    assert stat.S_IMODE(r.out.stat().st_mode) == 0o700
    for p in r.out.iterdir():
        assert stat.S_IMODE(p.stat().st_mode) == 0o600, p.name


# ----------------------------------------------------------------- redaction
def test_redaction_leaks_nothing(dirty, run):
    path, _ = dirty
    r = run(path, "--redact", "--stall-pct", "40", "--big-chat-messages", "50", "--big-chat-gb", "0.005")
    assert r.code == 0
    everything = r.all_output()
    assert synth.SECRET not in everything
    for word in synth.GROUP_SUBJECT.split():
        assert word not in everything
    for phone in synth.PHONES:
        assert phone not in everything
        assert phone[:6] not in everything and phone[-6:] not in everything
    assert not re.search(r"\d{7,}@", everything)
    assert "@s.whatsapp.net" in everything  # masked, not removed
    assert r.report["redacted"] is True
    for check in r.report["checks"]:
        for f in check["findings"]:
            assert f.get("text") is None
            for a in f.get("context_before", []) + f.get("context_after", []):
                assert a["text"] is None


def test_redaction_with_neighbour_listing(clean, run):
    path, _ = clean
    r = run(path, "--redact", "--stall-pct", "82")
    everything = r.all_output()
    assert synth.SECRET not in everything
    assert all(p not in everything for p in synth.PHONES)


def test_unredacted_report_does_contain_anchors(dirty, run):
    path, _ = dirty
    r = run(path)
    assert synth.SECRET in r.stdout and synth.GROUP_SUBJECT in r.stdout  # the control for the test above


def test_control_characters_are_neutralised(tmp_path, run):
    path = tmp_path / "esc.db"
    synth.build(path)
    conn = sqlite3.connect(path)
    conn.execute("UPDATE message SET text_data = ? WHERE _id = 14", ("evil\x1b[2Jtext\nline",))
    conn.commit()
    conn.close()
    r = run(path)
    assert "\x1b" not in r.all_output()


# ---------------------------------------------------------------------- key
def test_key_normalisation():
    k = secrets.token_hex(32)
    spaced = " ".join(k[i : i + 4] for i in range(0, 64, 4)).upper() + "\n"
    assert keys.normalise_key(spaced) == k
    for bad in ("", "abc", k[:-1], k + "0", "g" * 64):
        with pytest.raises(keys.KeyFormatError) as e:
            keys.normalise_key(bad)
        assert bad == "" or bad not in str(e.value)


def test_key_is_not_a_command_line_option(dirty, capsys):
    options = {s for a in cli.build_parser()._actions for s in a.option_strings}
    assert not any("key" in o for o in options - {"--key-file"})
    with pytest.raises(SystemExit) as e:
        cli.main([str(dirty[0]), "--key", "0" * 64])
    assert e.value.code == 2


def test_hidden_prompt_is_used_without_key_file(encrypted, run, key_hex, monkeypatch):
    crypt, _, planted = encrypted
    prompts = []

    def fake_getpass(prompt=""):
        prompts.append(prompt)
        return "  " + key_hex.upper() + " \n"

    monkeypatch.setattr(keys.getpass, "getpass", fake_getpass)
    r = run(crypt)
    assert r.code == 0 and len(prompts) == 1
    assert r.ids("empty_text") == planted.empty_text
    assert key_hex not in r.all_output() and key_hex.upper() not in r.all_output()


def test_plain_database_never_asks_for_a_key(dirty, run, monkeypatch):
    monkeypatch.setattr(keys.getpass, "getpass", lambda *_: pytest.fail("prompted for a key"))
    assert run(dirty[0]).code == 0


def test_malformed_key_is_a_usage_error(encrypted, run, tmp_path):
    crypt, _, _ = encrypted
    bad = tmp_path / "bad.txt"
    bad.write_text("not-a-key-1234")
    r = run(crypt, "--key-file", str(bad))
    assert r.code == 2
    assert "64 hex digits" in r.stderr and "not-a-key" not in r.stderr
    assert not r.out.exists()


# --------------------------------------------------------------- decryption
def test_encrypted_backup_gives_same_findings_as_plain(encrypted, dirty, run):
    crypt, key_file, planted = encrypted
    enc = run(crypt, "--key-file", str(key_file))
    plain = run(dirty[0])
    assert enc.code == 0
    strip = lambda rep: [(c["name"], c["status"], c["count"], c["findings"]) for c in rep["checks"]]
    assert strip(enc.report) == strip(plain.report)
    assert enc.ids("empty_text") == planted.empty_text


def test_wrong_key_fails_clearly_without_leaking(encrypted, run, tmp_path, key_hex):
    crypt, _, _ = encrypted
    wrong = secrets.token_hex(32)
    wrong_file = tmp_path / "wrong.txt"
    wrong_file.write_text(wrong)
    wrong_file.chmod(0o600)
    r = run(crypt, "--key-file", str(wrong_file))
    assert r.code == 1
    assert "wrong key" in r.stderr
    assert wrong not in r.stdout + r.stderr and key_hex not in r.stdout + r.stderr
    assert not r.out.exists()


def test_library_logging_cannot_leak_the_key(encrypted, key_hex, caplog):
    crypt, _, _ = encrypted
    import logging

    with caplog.at_level(logging.DEBUG):
        data, warnings = decrypt_backup(crypt, key_hex)
    assert data.startswith(SQLITE_MAGIC) and warnings == []
    assert key_hex not in caplog.text


def test_garbage_and_truncated_files_fail_cleanly(encrypted, run, tmp_path):
    crypt, key_file, _ = encrypted
    garbage = tmp_path / "garbage.crypt15"
    garbage.write_bytes(os.urandom(4096))
    truncated = tmp_path / "truncated.crypt15"
    truncated.write_bytes(crypt.read_bytes()[:-500])
    empty = tmp_path / "empty.crypt15"
    empty.write_bytes(b"")
    for bad in (garbage, truncated, empty):
        r = run(bad, "--key-file", str(key_file))
        assert r.code == 1, bad.name
        assert r.stderr.startswith("error:"), bad.name
        assert "Traceback" not in r.stderr


def test_multifile_zip_backup_is_rejected(tmp_path, key_hex):
    import zlib  # noqa: F401
    from wa_crypt_tools.lib.db.db15 import Database15
    from wa_crypt_tools.lib.key.keyfactory import KeyFactory
    from wa_crypt_tools.lib.props import Props

    key = KeyFactory.from_hex(key_hex)
    blob = Database15(key=key).encrypt(key, Props(), b"PK\x03\x04" + b"\x00" * 64)
    path = tmp_path / "multi.crypt15"
    path.write_bytes(blob)
    with pytest.raises(DecryptError, match="multi-file"):
        decrypt_backup(path, key_hex)


# --------------------------------------------------------------- exit codes
def test_exit_codes(dirty, run, tmp_path, capsys):
    assert run(dirty[0]).code == 0
    assert run(tmp_path / "does-not-exist.db").code == 1
    for argv in ([], [str(dirty[0]), "--context", "-1"], [str(dirty[0]), "--stall-pct", "150"],
                 [str(dirty[0]), "--no-such-flag"]):
        with pytest.raises(SystemExit) as e:
            cli.main(argv)
        assert e.value.code == 2
    capsys.readouterr()
