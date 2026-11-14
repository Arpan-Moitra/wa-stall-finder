"""A small desktop window around the same read-only analysis as the CLI.

Standard library only (tkinter). The key is typed into a masked field, used
once and cleared; it is never stored, logged or written to disk.
"""

from __future__ import annotations

import os
import queue
import sqlite3
import sys
import threading
import webbrowser
from pathlib import Path

from . import __version__
from .checks import Options
from .cli import InputError, Outcome, analyse
from .decrypt import DecryptError, is_sqlite_file
from .friendly import friendly_summary
from .keys import KeyFormatError, normalise_key

REPORT_FOLDER_NAME = "WhatsApp transfer report"
PAD = 10


def default_report_dir() -> Path:
    desktop = Path.home() / "Desktop"
    return (desktop if desktop.is_dir() else Path.home()) / REPORT_FOLDER_NAME


def run_analysis(src: Path, key_text: str, stall_text: str, redact: bool, out: Path) -> tuple[Outcome, str]:
    """Validate the form values and run the checks. Raises ValueError with a
    plain-language message for anything the person can fix themselves."""
    stall: float | None = None
    if stall_text.strip():
        try:
            stall = float(stall_text.strip().rstrip("%"))
        except ValueError:
            raise ValueError("The percentage should be a number, for example 82.") from None
        if not 0 <= stall <= 100:
            raise ValueError("The percentage should be between 0 and 100.")
    if not src.is_file():
        raise ValueError("Please choose your backup file first.")
    key = ""
    if not is_sqlite_file(src):
        try:
            key = normalise_key(key_text)
        except KeyFormatError:
            digits = len("".join(key_text.split()))
            raise ValueError(
                f"The key should be exactly 64 characters, using only 0-9 and a-f. You typed {digits}."
            ) from None
    opts = Options(redact=redact, stall_pct=stall)
    outcome = analyse(src, out, opts, lambda: key)
    return outcome, friendly_summary(outcome.results, stall_pct=stall)


def main(argv: list[str] | None = None) -> int:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    from tkinter.scrolledtext import ScrolledText

    argv = sys.argv[1:] if argv is None else argv
    root = tk.Tk()
    root.title("WhatsApp Transfer Stall Finder")
    root.minsize(760, 680)

    file_var = tk.StringVar()
    key_var = tk.StringVar()
    stall_var = tk.StringVar()
    redact_var = tk.BooleanVar(value=False)
    show_key_var = tk.BooleanVar(value=False)
    out_var = tk.StringVar(value=str(default_report_dir()))
    count_var = tk.StringVar(value="0 of 64")
    status_var = tk.StringVar(value="")
    jobs: queue.Queue[tuple[str, object]] = queue.Queue()

    frame = ttk.Frame(root, padding=PAD * 2)
    frame.pack(fill="both", expand=True)
    frame.columnconfigure(0, weight=1)

    def heading(text: str, row: int) -> None:
        ttk.Label(frame, text=text, font=("", 13, "bold")).grid(row=row, column=0, sticky="w", pady=(PAD, 2))

    ttk.Label(frame, text="Find the message that is stopping your WhatsApp transfer",
              font=("", 16, "bold")).grid(row=0, column=0, sticky="w")
    ttk.Label(frame, text="Everything stays on this computer. Nothing is uploaded, and your backup is never changed.",
              foreground="#555").grid(row=1, column=0, sticky="w")

    heading("1.  Choose your backup file  (msgstore.db.crypt15)", 2)
    row_file = ttk.Frame(frame)
    row_file.grid(row=3, column=0, sticky="ew")
    row_file.columnconfigure(1, weight=1)

    def choose_file() -> None:
        path = filedialog.askopenfilename(
            title="Choose msgstore.db.crypt15",
            filetypes=[("WhatsApp backup", "*.crypt15 *.db"), ("All files", "*.*")],
        )
        if path:
            file_var.set(path)

    ttk.Button(row_file, text="Choose file…", command=choose_file).grid(row=0, column=0)
    ttk.Label(row_file, textvariable=file_var, foreground="#555").grid(row=0, column=1, sticky="w", padx=PAD)

    heading("2.  Type your 64-digit backup key", 4)
    row_key = ttk.Frame(frame)
    row_key.grid(row=5, column=0, sticky="ew")
    row_key.columnconfigure(0, weight=1)
    key_entry = ttk.Entry(row_key, textvariable=key_var, show="•", font=("Courier", 12))
    key_entry.grid(row=0, column=0, sticky="ew")
    ttk.Label(row_key, textvariable=count_var, width=9).grid(row=0, column=1, padx=PAD)
    ttk.Checkbutton(
        row_key, text="Show", variable=show_key_var,
        command=lambda: key_entry.configure(show="" if show_key_var.get() else "•"),
    ).grid(row=0, column=2)
    ttk.Label(frame, text="This is the key WhatsApp showed when you turned on end-to-end encrypted backup. "
                          "Spaces are fine.", foreground="#555").grid(row=6, column=0, sticky="w")
    key_var.trace_add("write", lambda *_: count_var.set(f"{len(''.join(key_var.get().split()))} of 64"))

    heading("3.  At what percentage does the transfer stop?  (optional)", 7)
    row_pct = ttk.Frame(frame)
    row_pct.grid(row=8, column=0, sticky="w")
    ttk.Entry(row_pct, textvariable=stall_var, width=6).grid(row=0, column=0)
    ttk.Label(row_pct, text="%   for example 82").grid(row=0, column=1, padx=4)

    ttk.Checkbutton(frame, text="Hide message text and phone numbers in the results (harder to find the message)",
                    variable=redact_var).grid(row=9, column=0, sticky="w", pady=(PAD, 0))

    row_out = ttk.Frame(frame)
    row_out.grid(row=10, column=0, sticky="ew", pady=(4, 0))
    ttk.Label(row_out, text="Report is saved to:").grid(row=0, column=0)
    ttk.Label(row_out, textvariable=out_var, foreground="#555").grid(row=0, column=1, padx=6)

    def choose_out() -> None:
        path = filedialog.askdirectory(title="Choose where to save the report")
        if path:
            out_var.set(str(Path(path) / REPORT_FOLDER_NAME))

    ttk.Button(row_out, text="Change…", command=choose_out).grid(row=0, column=2)

    row_go = ttk.Frame(frame)
    row_go.grid(row=11, column=0, sticky="ew", pady=PAD)
    go = ttk.Button(row_go, text="Find the problem messages")
    go.grid(row=0, column=0)
    bar = ttk.Progressbar(row_go, mode="indeterminate", length=160)
    ttk.Label(row_go, textvariable=status_var).grid(row=0, column=2, padx=PAD)
    open_btn = ttk.Button(row_go, text="Open report folder", state="disabled",
                          command=lambda: open_folder(Path(out_var.get())))
    open_btn.grid(row=0, column=3, padx=PAD)

    text = ScrolledText(frame, wrap="word", height=18, font=("Courier", 12), state="disabled")
    text.grid(row=12, column=0, sticky="nsew")
    frame.rowconfigure(12, weight=1)

    def show(content: str) -> None:
        text.configure(state="normal")
        text.delete("1.0", "end")
        text.insert("1.0", content)
        text.configure(state="disabled")

    show("Your results will appear here.\n\nNeed the backup file? On the Android phone open WhatsApp > Settings > "
         "Chats > Chat backup >\nEnd-to-end encrypted backup, turn it on with a 64-digit key, then tap Back up.\n"
         "Copy this file to the computer:\n  Android/media/com.whatsapp/WhatsApp/Databases/msgstore.db.crypt15")

    def open_folder(path: Path) -> None:
        if hasattr(os, "startfile"):
            os.startfile(path)  # type: ignore[attr-defined]  # Windows
        else:
            webbrowser.open(path.as_uri())

    def worker(src: Path, key_text: str, stall_text: str, redact: bool, out: Path) -> None:
        try:
            outcome, friendly = run_analysis(src, key_text, stall_text, redact, out)
            jobs.put(("done", friendly + "\n\n" + "=" * 78 + "\nTECHNICAL DETAILS\n\n" + outcome.text))
        except (ValueError, DecryptError, InputError) as e:
            jobs.put(("error", str(e)[:1].upper() + str(e)[1:]))
        except (OSError, sqlite3.Error, MemoryError) as e:
            jobs.put(("error", f"Something went wrong while reading the file ({type(e).__name__})."))

    def start() -> None:
        go.configure(state="disabled")
        open_btn.configure(state="disabled")
        status_var.set("Working… large backups can take a few minutes.")
        bar.grid(row=0, column=1, padx=PAD)
        bar.start(12)
        args = (Path(file_var.get()), key_var.get(), stall_var.get(), redact_var.get(), Path(out_var.get()))
        threading.Thread(target=worker, args=args, daemon=True).start()
        root.after(100, poll)

    def poll() -> None:
        try:
            kind, payload = jobs.get_nowait()
        except queue.Empty:
            root.after(100, poll)
            return
        bar.stop()
        bar.grid_remove()
        go.configure(state="normal")
        if kind == "done":
            key_var.set("")  # do not keep the key around once it has been used
            status_var.set("Done.")
            open_btn.configure(state="normal")
            show(str(payload))
        else:
            status_var.set("")
            messagebox.showerror("Could not check the backup", str(payload))

    go.configure(command=start)
    ttk.Label(frame, text=f"Version {__version__}. Not affiliated with WhatsApp, Meta or Apple.",
              foreground="#777").grid(row=13, column=0, sticky="w", pady=(4, 0))

    if "--self-test" in argv:  # used by the build to prove the bundled app starts
        root.update()
        root.destroy()
        return 0
    root.mainloop()
    return 0


def entry_point() -> None:
    sys.exit(main())


if __name__ == "__main__":
    entry_point()
