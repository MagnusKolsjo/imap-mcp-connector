# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""Native macOS dialogs for decisions that must not pass through the AI client.

The settings panel runs inside the AI client. Anything typed there travels
through the client as a tool argument, and the client decides which tools
the model may call. Two things are therefore asked for in a dialog drawn by
macOS itself, outside the client:

  * passwords, which go straight from the dialog into the Keychain, and
  * confirmations of changes that give the AI more power or send the stored
    password somewhere new (raising permissions, changing servers), and
  * approval of each message before it is sent.

The dialogs are shown with `osascript`. Texts are passed as arguments to an
`on run argv` handler, never spliced into the script source, so no account
name or server name can break out of the AppleScript string.

Other operating systems have no such dialog here; there the settings panel
sends the user to the browser-based settings page instead.

Entry points:
    available() -> bool
    ask_password(title, message, ok, cancel) -> str | None
    confirm(title, message, ok, cancel) -> bool
    choose(title, message, buttons) -> str | None
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


_CHOOSE_SCRIPT = [
    "on run argv",
    "  set choices to items 3 thru -1 of argv",
    "  set dialogResult to display dialog (item 2 of argv) with title (item 1 of argv) "
    "buttons choices default button (item 3 of argv) cancel button (item 3 of argv) "
    f"with icon caution giving up after {DIALOG_TIMEOUT_SECONDS}",
    "  if gave up of dialogResult then error number -128",
    "  return button returned of dialogResult",
    "end run",
]


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


def choose(title: str, message: str, buttons: list[str]) -> str | None:
    """Show up to three buttons; the first is Cancel and the default.

    Returns the label of the button pressed, or None when cancelled. macOS
    lays buttons out right to left, so the first one ends up leftmost-safe
    only by convention; making it the default means Return never sends.
    """
    if not 2 <= len(buttons) <= 3:
        raise ValueError("A dialog takes two or three buttons.")
    choice = _run(_CHOOSE_SCRIPT, [title, message, *buttons])
    return None if choice in (None, buttons[0]) else choice
