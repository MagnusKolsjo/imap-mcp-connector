# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""Saving attachments to disk in a fixed folder structure.

This is the one place where mail content is written to disk, so it only
works for accounts where the user has turned on `save_attachments`, and
only under the attachments folder chosen in the settings. Callers (and the
AI behind them) never choose a path:

    <root>/<account id>/<YYYY>/<MM>/dokument/<file>
    <root>/<account id>/<YYYY>/<MM>/karantän/<file>

Year and month are when the message arrived on the server.

Quarantine is decided by rules first; the AI may only add to it:

  * every attachment of a message in the junk folder goes to quarantine,
  * only allowlisted document and media types go to the documents folder;
    everything else goes to quarantine, with an explicit reason for the
    known risky kinds (programs and scripts, macro documents, disk images,
    shortcuts, archives, double extensions such as "invoice.pdf.exe"),
  * the caller can send an otherwise harmless file to quarantine, but can
    never move a rule-based quarantine file to the documents folder.

Only known document and media types can go to the documents folder (an
allowlist); every other type goes to quarantine. Saved files get mode 0600
(never executable) and macOS's quarantine attribute, so the system warns
before opening anything downloaded from mail.
Identical content already in the target folder is not saved twice.

Entry points:
    save_message_attachments(account, raw, internal_date, folder_role, ...) -> list[dict]
    classify(filename, content_type, in_junk) -> (category, reasons)
    safe_filename(name) -> str
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import Any

import accounts
import mail_parse

DOCUMENTS = "dokument"
QUARANTINE = "karantän"

# Limits per call: enough for a month of invoices, small enough that one
# mistaken call cannot fill the disk.
MAX_FILE_BYTES = int(os.getenv("IMAP_ATTACHMENT_MAX_MB", "50")) * 1024 * 1024
MAX_TOTAL_BYTES = int(os.getenv("IMAP_ATTACHMENT_MAX_TOTAL_MB", "500")) * 1024 * 1024

_RISKY_EXTENSIONS = {
    # programs, scripts and installers
    "exe", "com", "scr", "pif", "bat", "cmd", "msi", "msp", "dll", "cpl", "jar",
    "js", "jse", "vbs", "vbe", "wsf", "wsh", "ps1", "psm1", "hta", "sh", "command",
    "app", "pkg", "apk", "reg", "scf", "inf", "gadget", "applescript", "scpt", "workflow",
    # Office files that can carry macros
    "docm", "dotm", "xlsm", "xltm", "xlam", "xlsb", "pptm", "potm", "ppam", "ppsm", "sldm",
    # disk images and shortcuts
    "iso", "img", "dmg", "vhd", "vhdx", "lnk", "url", "webloc", "desktop",
    # archives: their content is not inspected, so it is not trusted
    "zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "xz", "cab", "ace", "arj", "z",
    # HTML can phish when opened locally
    "html", "htm", "shtml", "svg",
}
# Allowlist: only these final extensions may go to the documents folder.
# Anything else, including types nobody thought of, goes to quarantine.
_DOCUMENT_LIKE = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "rtf",
    "txt", "csv", "md", "ics", "vcf", "pages", "numbers", "key",
    "jpg", "jpeg", "png", "gif", "heic", "heif", "webp", "tif", "tiff", "bmp",
    "mp3", "m4a", "wav", "mp4", "mov",
}


class AttachmentError(Exception):
    """Saving attachments is not allowed or failed in a way the user should hear about."""


def safe_filename(name: str) -> str:
    """A file name that cannot escape its folder or hide its real extension."""
    name = unicodedata.normalize("NFC", name or "")
    name = "".join(ch for ch in name if not mail_parse._is_invisible(ch))
    # Right-to-left overrides are already removed above; path separators and
    # characters that are invalid on common file systems are replaced.
    name = re.sub(r'[\\/:*?"<>|\x00-\x1f]', "_", name)
    name = re.sub(r"\s+", " ", name).strip(" .")
    if name in ("", ".", ".."):
        name = "bilaga"
    # Keep the extension when shortening, so a long name cannot push it off.
    stem, dot, ext = name.rpartition(".")
    if dot and len(ext) <= 12:
        return stem[: 150].rstrip(" .") + "." + ext
    return name[:160]


def _extensions(filename: str) -> list[str]:
    parts = safe_filename(filename).casefold().split(".")
    return [re.sub(r"[^0-9a-z]", "", p) for p in parts[1:] if p.strip()]


def classify(filename: str, content_type: str, in_junk: bool) -> tuple[str, list[str]]:
    """Return (DOCUMENTS or QUARANTINE, reason codes)."""
    reasons = []
    if in_junk:
        reasons.append("junk_folder")
    exts = _extensions(filename)
    if exts and exts[-1] in _RISKY_EXTENSIONS:
        reasons.append("risky_type")
    if len(exts) >= 2 and exts[-2] in _DOCUMENT_LIKE and exts[-1] not in _DOCUMENT_LIKE:
        reasons.append("double_extension")
    if not exts or exts[-1] not in _DOCUMENT_LIKE:
        reasons.append("not_allowlisted")
    if content_type in ("application/x-msdownload", "application/x-dosexec", "application/java-archive",
                        "application/vnd.ms-office.vbaproject", "application/x-sh"):
        reasons.append("risky_type")
    return (QUARANTINE if reasons else DOCUMENTS), sorted(set(reasons))


def _mark_quarantined(path: Path) -> None:
    """Set macOS's quarantine attribute so Gatekeeper warns before opening."""
    if sys.platform != "darwin":
        return
    value = f"0081;{int(datetime.now().timestamp()):x};imap-connector;"
    try:
        subprocess.run(["xattr", "-w", "com.apple.quarantine", value, str(path)],
                       capture_output=True, timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):
        pass  # the folder name still says what it is


def _target(directory: Path, filename: str, data: bytes) -> tuple[Path, bool]:
    """Pick a free path in `directory`; (path, already_saved) if identical content exists."""
    digest = hashlib.sha256(data).hexdigest()
    candidate = directory / filename
    stem, dot, ext = filename.rpartition(".")
    if not dot:
        stem, ext = filename, ""
    n = 2
    while candidate.exists():
        try:
            if candidate.stat().st_size == len(data) and hashlib.sha256(candidate.read_bytes()).hexdigest() == digest:
                return candidate, True
        except OSError:
            pass
        candidate = directory / (f"{stem} ({n}).{ext}" if ext else f"{stem} ({n})")
        n += 1
    return candidate, False


def save_message_attachments(
    account: accounts.Account,
    raw: bytes,
    internal_date: datetime | None,
    *,
    in_junk: bool,
    part_ids: list[str] | None = None,
    include_inline: bool = False,
    quarantine: bool = False,
    budget: list[int] | None = None,
) -> list[dict[str, Any]]:
    """Save one message's attachments; return a result row per attachment.

    `budget` is a one-element list holding the bytes still allowed in this
    call, shared across messages.
    """
    if not account.permissions.save_attachments:
        raise AttachmentError(
            f"Account {account.id!r} does not allow saving attachments. "
            "The user can turn it on in the settings."
        )
    parsed = mail_parse.parse_message(raw)
    when = internal_date or datetime.now()
    root = accounts.attachments_root()
    base = root / account.id / f"{when:%Y}" / f"{when:%m}"
    budget = budget if budget is not None else [MAX_TOTAL_BYTES]
    results = []
    for att in parsed.attachments:
        if part_ids is not None and att.part_id not in part_ids:
            continue
        if att.inline and not include_inline and part_ids is None:
            continue
        part = mail_parse.get_part(parsed.message, att.part_id)
        data = mail_parse.part_bytes(part) if part is not None else b""
        row: dict[str, Any] = {"part_id": att.part_id, "filename": att.filename, "size_bytes": len(data)}
        if len(data) > MAX_FILE_BYTES:
            results.append({**row, "status": "skipped", "reason": "too_large"})
            continue
        if len(data) > budget[0]:
            results.append({**row, "status": "skipped", "reason": "call_limit_reached"})
            continue
        # Classify the very name that will be written: normalising after
        # classifying would let "x.pdf.ex\u200be" pass as a document and
        # then be saved as "x.pdf.exe".
        name = safe_filename(att.filename)
        category, reasons = classify(name, att.content_type, in_junk)
        if quarantine and category == DOCUMENTS:
            category, reasons = QUARANTINE, ["requested"]
        directory = base / category
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        path, duplicate = _target(directory, name, data)
        if not duplicate:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            # Every saved attachment carries macOS's quarantine mark, as Mail
            # and browsers do; the quarantine folder is the stricter layer.
            _mark_quarantined(path)
            budget[0] -= len(data)
        results.append({
            **row,
            "status": "already_saved" if duplicate else "saved",
            "category": category,
            "quarantine_reasons": reasons,
            "path": str(path.relative_to(root)),
        })
    return results
