# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""Native macOS dialogs for decisions that must not pass through the AI client.

The settings panel runs inside the AI client. Anything typed there travels
through the client as a tool argument, and the client decides which tools
the model may call. Two things are therefore asked for in a dialog drawn by
macOS itself, outside the client:

  * passwords, which go straight from the dialog into the Keychain, and
  * confirmations of changes that give the AI more power or send the stored
    password somewhere new (raising permissions, changing servers).

Approval of messages before sending happens in the mailbox panel instead
(see send_approval), where the user reads the whole message.

The dialogs are shown with `osascript`. Texts are passed as arguments to an
`on run argv` handler, never spliced into the script source, so no account
name or server name can break out of the AppleScript string.

Other operating systems have no such dialog here; there the settings panel
sends the user to the browser-based settings page instead.

Entry points:
    available() -> bool
    ask_password(title, message, ok, cancel) -> str | None
    confirm(title, message, ok, cancel) -> bool
    choose_file(prompt) -> str | None
    choose_folder(prompt) -> str | None
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

# Long enough to find a password manager and copy a password, short enough
# that a forgotten dialog does not hold a tool call open indefinitely.
DIALOG_TIMEOUT_SECONDS = int(os.getenv("IMAP_DIALOG_TIMEOUT_SECONDS", "180"))

_PASSWORD_SCRIPT = [
    "on run argv",
    "  set dialogResult to display dialog (item 2 of argv) with title (item 1 of argv) "
    "default answer \"\" with hidden answer buttons {(item 4 of argv), (item 3 of argv)} "
    "default button (item 3 of argv) cancel button (item 4 of argv) with icon note "
    f"giving up after {DIALOG_TIMEOUT_SECONDS}",
    "  if gave up of dialogResult then error number -128",
    "  return text returned of dialogResult",
    "end run",
]

_CONFIRM_SCRIPT = [
    "on run argv",
    "  set dialogResult to display dialog (item 2 of argv) with title (item 1 of argv) "
    "buttons {(item 4 of argv), (item 3 of argv)} default button (item 4 of argv) "
    "cancel button (item 4 of argv) with icon caution "
    f"giving up after {DIALOG_TIMEOUT_SECONDS}",
    "  if gave up of dialogResult then error number -128",
    "  return button returned of dialogResult",
    "end run",
]


class DialogUnavailable(Exception):
    """No native dialog can be shown on this system."""


def available() -> bool:
    return sys.platform == "darwin" and shutil.which("osascript") is not None


def _run(script: list[str], args: list[str]) -> str | None:
    """Run an AppleScript handler; return stdout, or None if the user cancelled."""
    if not available():
        raise DialogUnavailable("Native dialogs are only available on macOS.")
    command = ["osascript"]
    for line in script:
        command += ["-e", line]
    command += ["--", *args]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=DIALOG_TIMEOUT_SECONDS + 15,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None
    if completed.returncode != 0:
        # -128 is "User canceled"; anything else is reported, but without
        # stdout, which could hold a typed password.
        if "-128" in completed.stderr:
            return None
        raise DialogUnavailable(f"The dialog could not be shown: {completed.stderr.strip()[:200]}")
    # osascript appends one newline; the password itself is kept verbatim.
    return completed.stdout[:-1] if completed.stdout.endswith("\n") else completed.stdout


def ask_password(title: str, message: str, ok: str, cancel: str) -> str | None:
    """Ask for a password with hidden input. None if cancelled or left empty."""
    value = _run(_PASSWORD_SCRIPT, [title, message, ok, cancel])
    return value or None


def confirm(title: str, message: str, ok: str, cancel: str) -> bool:
    """Ask for confirmation. The cancel button is the default, so Return declines."""
    return _run(_CONFIRM_SCRIPT, [title, message, ok, cancel]) == ok


_CHOOSE_FILE_SCRIPT = [
    "on run argv",
    "  set chosen to choose file with prompt (item 1 of argv) of type {\"md\", \"markdown\", \"txt\", \"public.plain-text\"}",
    "  return POSIX path of chosen",
    "end run",
]

_CHOOSE_FOLDER_SCRIPT = [
    "on run argv",
    "  set chosen to choose folder with prompt (item 1 of argv)",
    "  return POSIX path of chosen",
    "end run",
]


def choose_file(prompt: str) -> str | None:
    """Let the user pick a Markdown or text file; return its path or None."""
    return _run(_CHOOSE_FILE_SCRIPT, [prompt]) or None


def choose_folder(prompt: str) -> str | None:
    """Let the user pick a folder; return its path or None."""
    return _run(_CHOOSE_FOLDER_SCRIPT, [prompt]) or None

