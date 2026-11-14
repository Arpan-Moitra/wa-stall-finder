from __future__ import annotations

import json
import secrets
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import synth  # noqa: E402
from wa_stall_finder.cli import main  # noqa: E402


@dataclass
class Run:
    code: int
    stdout: str
    stderr: str
    out: Path

    @property
    def report(self) -> dict[str, Any]:
        return json.loads((self.out / "report.json").read_text(encoding="utf-8"))

    def check(self, name: str) -> dict[str, Any]:
        return next(c for c in self.report["checks"] if c["name"] == name)

    def ids(self, name: str) -> list[int]:
        return sorted(f["message_id"] for f in self.check(name)["findings"])

    def all_output(self) -> str:
        files = "".join(p.read_text(encoding="utf-8") for p in sorted(self.out.iterdir()) if p.is_file())
        return self.stdout + self.stderr + files


@pytest.fixture
def run(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    counter = 0

    def _run(source: Path, *args: str) -> Run:
        nonlocal counter
        counter += 1
        out = tmp_path / f"report{counter}"
        capsys.readouterr()
        code = main([str(source), "--out", str(out), *args])
        captured = capsys.readouterr()
        return Run(code, captured.out, captured.err, out)

    return _run


@pytest.fixture
def dirty(tmp_path: Path) -> tuple[Path, synth.Planted]:
    path = tmp_path / "inputs" / "msgstore.db"
    path.parent.mkdir()
    return path, synth.build(path)


@pytest.fixture
def clean(tmp_path: Path) -> tuple[Path, synth.Planted]:
    path = tmp_path / "clean_inputs" / "msgstore.db"
    path.parent.mkdir()
    return path, synth.build(path, clean=True)


@pytest.fixture
def key_hex() -> str:
    return secrets.token_hex(32)  # throwaway key, generated per test


@pytest.fixture
def encrypted(tmp_path: Path, dirty: tuple[Path, synth.Planted], key_hex: str) -> tuple[Path, Path, synth.Planted]:
    db_path, planted = dirty
    enc_dir = tmp_path / "enc"
    enc_dir.mkdir()
    crypt = enc_dir / "msgstore.db.crypt15"
    crypt.write_bytes(synth.encrypt_crypt15(db_path.read_bytes(), key_hex))
    key_file = enc_dir / "key.txt"
    key_file.write_text(key_hex + "\n")
    key_file.chmod(0o600)
    return crypt, key_file, planted
