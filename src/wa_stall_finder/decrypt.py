"""In-memory decryption of a .crypt15 backup through the wa-crypt-tools library API.

Written against wa-crypt-tools 0.1.0 (the pinned version). Notes on that version,
taken from reading its source rather than its README:

* It defines no exception classes. ``InvalidKeyError``, ``HeaderError``,
  ``DecryptionError`` and ``IntegrityError`` exist only in the unreleased git
  version. We look them up by name so a later pin picks them up, and otherwise
  detect the same failures ourselves.
* A wrong key does not raise: the GCM tag mismatch is only logged and garbage
  is returned. We detect it from the log record and from the failed inflate.
* ``KeyFactory.new(key)`` first tries to *open a file* named after the key
  string, so we call ``KeyFactory.from_hex`` directly.
* Its loggers print key material at DEBUG ("Root key: ...") and in one ERROR
  path. We therefore silence the library's loggers and never relay its
  messages; we only test them for one fixed, harmless phrase.
"""

from __future__ import annotations

import logging
import zlib
from pathlib import Path

SQLITE_MAGIC = b"SQLite format 3\x00"
_TAG_MISMATCH = "Authentication tag mismatch"


class DecryptError(Exception):
    """Decryption failed; the message is safe to show (no key, no content)."""


class _FlagHandler(logging.Handler):
    """Remembers whether the library reported a tag mismatch. Stores no text."""

    def __init__(self) -> None:
        super().__init__(level=logging.ERROR)
        self.tag_mismatch = False

    def emit(self, record: logging.LogRecord) -> None:
        try:
            if _TAG_MISMATCH in str(record.msg):
                self.tag_mismatch = True
        except Exception:  # pragma: no cover - never let logging break a run
            pass


def is_sqlite_file(path: Path) -> bool:
    with open(path, "rb") as f:
        return f.read(len(SQLITE_MAGIC)) == SQLITE_MAGIC


def _named_errors(module: object, *names: str) -> tuple[type[BaseException], ...]:
    found = [getattr(module, n, None) for n in names]
    return tuple(e for e in found if isinstance(e, type) and issubclass(e, BaseException))


def decrypt_backup(path: Path, key_hex: str) -> tuple[bytes, list[str]]:
    """Return (plaintext SQLite bytes, warnings). Nothing is written to disk."""
    import wa_crypt_tools
    from wa_crypt_tools.lib.db.dbfactory import DatabaseFactory
    from wa_crypt_tools.lib.key.keyfactory import KeyFactory

    lib_log = logging.getLogger("wa_crypt_tools")
    flag = _FlagHandler()
    saved = (lib_log.level, lib_log.propagate, list(lib_log.handlers))
    lib_log.handlers = [flag]
    lib_log.setLevel(logging.ERROR)  # DEBUG would log the root key
    lib_log.propagate = False

    invalid_key = _named_errors(wa_crypt_tools, "InvalidKeyError")
    header_err = _named_errors(wa_crypt_tools, "HeaderError")
    decrypt_err = _named_errors(wa_crypt_tools, "DecryptionError")
    integrity_err = _named_errors(wa_crypt_tools, "IntegrityError")
    warnings: list[str] = []

    try:
        try:
            make_key = getattr(KeyFactory, "from_hex", None) or KeyFactory.new
            key = make_key(key_hex)
        except Exception as e:
            if invalid_key and isinstance(e, invalid_key):
                raise DecryptError("the key was rejected as invalid") from None
            raise DecryptError("the key could not be loaded (expected 64 hex digits)") from None
        if key is None:
            raise DecryptError("the key could not be loaded (expected 64 hex digits)")

        with open(path, "rb") as f:
            try:
                db = DatabaseFactory.from_file(f)
            except Exception as e:
                kind = "header error" if header_err and isinstance(e, header_err) else type(e).__name__
                raise DecryptError(
                    f"this does not look like a WhatsApp .crypt15 backup ({kind} while "
                    "reading the header). Check you picked msgstore.db.crypt15"
                ) from None
            if db is None:
                raise DecryptError("the backup header could not be read; the file may be truncated")
            flavour = type(db).__name__
            if flavour != "Database15":
                raise DecryptError(
                    f"this backup is {flavour.replace('Database', 'crypt')}, not crypt15. Only "
                    "end-to-end encrypted (64-digit key) backups are supported; turn that on "
                    "in WhatsApp and make a new backup"
                )
            try:
                plaintext: bytes = db.decrypt(key, f.read())
            except Exception as e:
                if integrity_err and isinstance(e, integrity_err):
                    # Newer versions carry the unverified plaintext on the exception.
                    data = getattr(e, "data", None)
                    if not isinstance(data, (bytes, bytearray)):
                        raise DecryptError(
                            "integrity check failed: wrong key, or the backup is corrupted"
                        ) from None
                    plaintext = bytes(data)
                    flag.tag_mismatch = True
                elif decrypt_err and isinstance(e, decrypt_err):
                    raise DecryptError("decryption failed: the backup looks corrupted") from None
                else:
                    raise DecryptError(
                        f"decryption failed ({type(e).__name__}): the backup looks truncated "
                        "or corrupted"
                    ) from None
    finally:
        lib_log.setLevel(saved[0])
        lib_log.propagate = saved[1]
        lib_log.handlers = saved[2]

    try:
        database = zlib.decompress(plaintext)
    except zlib.error:
        if plaintext.startswith(SQLITE_MAGIC):
            database = plaintext  # stored uncompressed
        elif plaintext.startswith(b"PK\x03\x04"):
            raise DecryptError(
                "this is a multi-file (ZIP) backup, which is not supported; use the single "
                "msgstore.db.crypt15 file"
            ) from None
        elif flag.tag_mismatch:
            raise DecryptError(
                "wrong key for this backup (authentication failed). Use the 64-digit key "
                "that was shown when this particular backup was created"
            ) from None
        else:
            raise DecryptError(
                "decrypted data could not be decompressed: the backup looks corrupted"
            ) from None
    del plaintext

    if not database.startswith(SQLITE_MAGIC):
        raise DecryptError("decrypted data is not an SQLite database")
    if flag.tag_mismatch:
        warnings.append(
            "The backup's authentication tag did not verify, but it decrypted to a readable "
            "database. The file may be damaged; treat results with care and consider "
            "making a fresh backup."
        )
    return database, warnings
