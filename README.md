# wa-stall-finder

A small, local, read-only diagnostic for one specific problem: moving WhatsApp from
Android to iPhone (Apple's Move to iOS) fails during WhatsApp's "preparing" step at the
same percentage every time, usually with "An unknown error occurred".

The usual cause is one or more bad records in WhatsApp's Android message database.
WhatsApp does not say which. This tool decrypts your backup **in memory**, looks for the
records most likely to stall the export, and tells you where they are (chat, time,
neighbouring messages) so you can delete them in the app and retry.

It only diagnoses. It does not repair, re-encrypt, or talk to your phone.

## What it guarantees

- **Read-only.** The backup is opened for reading only. Decrypted databases are opened
  with `mode=ro&immutable=1` and `PRAGMA query_only = ON`. The source contains no write
  statements; a test checks that, and that inputs are byte-identical after a run.
- **Offline.** No network access, telemetry or update checks.
- **Key handling.** The 64-digit key comes from a hidden prompt or `--key-file`. It is
  never accepted as a command-line argument, never logged and never written anywhere.
- **No plaintext on disk by default.** The database is decrypted and loaded in memory
  (`sqlite3.Connection.deserialize`). If your SQLite build cannot do that, it falls back
  to a `0600` file in a `0700` temporary directory that is removed when the run ends.
  `--keep-decrypted` is the only way to get a decrypted copy, and it goes into `--out`.
- The only thing written is the report directory (`--out`, mode `0700`, files `0600`).

## The easy way: the desktop app

For someone who does not use a terminal there is a double-click app for Windows and
Mac (Apple Silicon). It has one window: choose the backup file, type the key, click
"Find the problem messages". It shows plain-language instructions for which messages to
delete and how to find them, and saves the full report to a folder on the Desktop.

Download the zip for your computer from the repository's Releases page. Each zip contains
the app and `HOW TO USE.txt`, a step-by-step guide written for non-technical readers.

The apps are not code-signed, so the first launch needs one extra step:

- **Windows:** "Windows protected your PC" > More info > Run anyway.
- **Mac:** System Settings > Privacy & Security > Open Anyway.

The app is the same read-only code as the command-line tool. To build the apps, push a
version tag (`git tag v0.1.0 && git push origin v0.1.0`) or run the "Build desktop apps"
workflow by hand; see `.github/workflows/build-apps.yml`.

## Install (command line)

Python 3.11 or newer.

```bash
python3 -m venv .venv && .venv/bin/pip install .
```

The only dependency is `wa-crypt-tools==0.1.0` (pinned), which brings `pycryptodomex`,
`protobuf` and `javaobj-py3` with it.

## Make a backup this tool can decrypt

On the Android phone:

1. WhatsApp > Settings > Chats > Chat backup > **End-to-end encrypted backup**.
2. Turn it on and choose **Use 64-digit encryption key** (not a password). Write the key down.
3. Go back and tap **Back up**. You can turn off Google backup if you only want the local file.
4. Copy this file to your computer:
   `Android/media/com.whatsapp/WhatsApp/Databases/msgstore.db.crypt15`

Password-protected backups and old crypt12/crypt14 backups are not supported.

## Run

```bash
wa-stall-finder msgstore.db.crypt15
```

You are asked for the key with a hidden prompt. Alternatively put it in a text file
(`chmod 600`) and pass `--key-file key.txt`. Spaces, line breaks and upper case are fine.
An already-decrypted `.db` works too and needs no key.

Useful options:

| Option | Meaning |
| --- | --- |
| `--stall-pct 82` | Where your transfer stops. Enables the experimental stall hint. |
| `--redact` | No message text; masked phone numbers and group names in every output. |
| `--context N` | Neighbouring messages shown around each suspect (default 3). |
| `--out DIR` | Report directory (default `./wa_report`). |
| `--full-integrity` | `PRAGMA integrity_check` instead of `quick_check`. Slower. |
| `--big-chat-messages N`, `--big-chat-gb GB`, `--top N` | Big-chat thresholds (100000, 2) and list size (10). |
| `--limit N` | Detailed findings per check (default 200). Counts are always exact. |
| `--media-types 1,2,3` | Override which `message_type` codes count as media. |
| `--keep-decrypted` | Opt in to writing the decrypted database into `--out`. |

Exit codes: `0` the checks ran (whatever they found), `1` error, `2` usage error.

## The checks

| # | Name | Level | What it looks for |
| --- | --- | --- | --- |
| 1 | `integrity` | problem | SQLite structural damage. |
| 2 | `empty_text` | problem | Text messages (`message_type = 0`) with NULL `text_data`. The main known culprit. |
| 3 | `media_without_record` | suspect | Media or view-once messages with no `message_media` row. |
| 4 | `orphan_messages` | suspect | Messages whose chat does not exist. Not deletable in the app; report only. |
| 5 | `dangling_children` | suspect | Rows in any table whose `message_row_id` / `parent_message_row_id` points at a missing message. Report only. |
| 6 | `bad_timestamps` | suspect | NULL, zero, negative, or more than a day in the future. |
| 7 | `big_chats` | suspect | Chats over the message or media threshold. The largest chats are always listed. |
| 8 | `stall_hint` | experimental | See below. |

The schema is introspected at run time. If a table or column a check needs is missing,
that check is reported as **skipped** with the reason. WhatsApp's internal sentinel row
(`_id = 1`, `chat_row_id = -1`, `key_id = '-1'`) is always excluded.

`message_type` codes are not documented by WhatsApp. The tool uses a small map, checked
against two open-source projects in November 2026. Codes 0 (text), 2 (audio), 5
(location), 15 (deleted) and 20 (sticker) are agreed by both. Codes 1 (image), 3 (video),
9 (document), 13 (gif), 42/43 (view-once image/video) and 82 (view-once voice) come from
one source only, which is why check 3 is a "suspect" and why `--media-types` exists.

### The stall hint is a heuristic

`--stall-pct N` finds the message N% of the way through the table in `_id` order, then
ranks the suspects from the other checks by how far they are from it. If nothing was
flagged, it lists the messages around that position instead. This assumes the export
walks messages in `_id` order at an even pace. WhatsApp does not document that, so use
the hint to decide what to try first, not as proof.

## Reading the report

The terminal shows each check, then a prioritised summary and next steps. The same data
is in `report.json`, with one CSV per check, in the report directory.

For each suspect you get the message id, the chat (group subject or JID), local time,
direction (sent/received), type, and the messages just before and after it in the same
chat. Message ids are not visible in WhatsApp, so use the neighbours: open the chat,
search for the text of a neighbouring message, and the suspect is next to it.

What to do:

1. Delete flagged items in the app in this order: `empty_text` (2),
   `media_without_record` (3), `bad_timestamps` (6), then `big_chats` (7). For a big
   chat, export it first if you need it.
2. Retry the transfer.
3. If it now stalls at a **different** percentage, another bad record remains. Make a
   new backup and run the tool again.

Without `--redact` the report contains message text and phone numbers. Delete the report
directory when you are done.

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[test]'
```

```bash
.venv/bin/python -m pytest
```

Tests run only on synthetic data. `tests/synth.py` builds a fake msgstore with one planted
defect per check, the sentinel row, look-alike healthy rows, and a clean control. It can
also wrap that database in a real crypt15 container with a throwaway key.

Notes on `wa-crypt-tools` 0.1.0, from reading its source: it has no exception classes
(`InvalidKeyError`, `HeaderError`, `DecryptionError` and `IntegrityError` are only in its
unreleased git version; this tool uses them if present), a wrong key is logged rather
than raised, and its loggers can print key material. `decrypt.py` handles all three.

## Licence

`wa-crypt-tools` is licensed under **GPL-3.0**. This tool imports it, so if you
distribute this tool it must be under GPL-3.0-compatible terms; it is marked
GPL-3.0-or-later.

## Disclaimer

Not affiliated with WhatsApp, Meta or Apple. The checks are informed guesses based on
community reports, not on documentation; a flagged record may be harmless and the real
cause may not be flagged. Deleting messages and chats in WhatsApp is permanent, so export
anything you need first. Your backup contains other people's messages as well as your
own: keep it, the key and any unredacted report private. Provided as is, with no warranty.
