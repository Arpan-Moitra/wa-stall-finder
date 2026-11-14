"""The desktop window's logic: form validation, the run itself, and the plain-language summary."""

from __future__ import annotations

import pytest

import synth
from wa_stall_finder import gui


def test_run_analysis_on_encrypted_backup(encrypted, key_hex, tmp_path):
    crypt, _, planted = encrypted
    spaced = " ".join(key_hex[i : i + 4] for i in range(0, 64, 4)).upper()
    outcome, friendly = gui.run_analysis(crypt, spaced, "82", False, tmp_path / "rep")
    assert (tmp_path / "rep" / "report.json").is_file()
    total = len(planted.empty_text + planted.media_without_record + planted.bad_timestamps)
    assert f"Found {total} messages" in friendly
    assert "Delete for me" in friendly and "DIFFERENT percentage" in friendly
    assert f"the chat with +{synth.PHONES[0]}" in friendly
    assert f'the group "{synth.GROUP_SUBJECT}"' in friendly
    assert "It comes right AFTER" in friendly and synth.SECRET in friendly
    assert "leftover record" in friendly
    assert key_hex not in friendly + outcome.text
    # empty_text is listed first, as the most likely culprit
    assert friendly.index("nothing stored inside") < friendly.index("missing from WhatsApp's records")


def test_friendly_summary_respects_redaction(dirty, tmp_path):
    path, _ = dirty
    _, friendly = gui.run_analysis(path, "", "", True, tmp_path / "rep")
    assert synth.SECRET not in friendly
    assert all(p not in friendly for p in synth.PHONES)
    assert all(w not in friendly for w in synth.GROUP_SUBJECT.split())


def test_clean_backup_messages(clean, tmp_path):
    path, _ = clean
    _, friendly = gui.run_analysis(path, "", "", False, tmp_path / "a")
    assert "No obviously broken message" in friendly and "Type the percentage" in friendly
    _, friendly = gui.run_analysis(path, "", "82%", False, tmp_path / "b")
    assert "stops at 82%" in friendly and "rough guess" in friendly


@pytest.mark.parametrize(
    "key, stall, expected",
    [
        ("abc", "", "exactly 64 characters"),
        ("g" * 64, "", "exactly 64 characters"),
        ("", "abc", "should be a number"),
        ("", "150", "between 0 and 100"),
    ],
)
def test_form_errors_are_plain_language(encrypted, tmp_path, key, stall, expected):
    crypt, _, _ = encrypted
    with pytest.raises(ValueError, match=expected) as e:
        gui.run_analysis(crypt, key, stall, False, tmp_path / "rep")
    assert key == "" or key not in str(e.value)
    assert not (tmp_path / "rep").exists()


def test_no_file_chosen(tmp_path):
    with pytest.raises(ValueError, match="choose your backup file"):
        gui.run_analysis(tmp_path / "nothing", "", "", False, tmp_path / "rep")


def test_window_builds_and_closes():
    pytest.importorskip("tkinter")
    try:
        assert gui.main(["--self-test"]) == 0
    except Exception as e:  # no display available (headless CI)
        if type(e).__name__ == "TclError":
            pytest.skip(f"no display: {e}")
        raise
