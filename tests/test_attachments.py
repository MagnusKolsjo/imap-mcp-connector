# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""Saving attachments: permission, folder structure, quarantine rules and file safety."""

from __future__ import annotations

import os
import stat
from email.message import EmailMessage

import pytest

import accounts
import attachment_store
from attachment_store import DOCUMENTS, QUARANTINE, classify, safe_filename


@pytest.mark.parametrize("name,ctype,junk,expected", [
    ("faktura.pdf", "application/pdf", False, DOCUMENTS),
    ("Rapport 2026.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", False, DOCUMENTS),
    ("faktura.pdf", "application/pdf", True, QUARANTINE),            # junk folder
    ("setup.exe", "application/octet-stream", False, QUARANTINE),
    ("budget.xlsm", "application/vnd.ms-excel.sheet.macroEnabled.12", False, QUARANTINE),
    ("faktura.pdf.exe", "application/octet-stream", False, QUARANTINE),
    ("faktura.pdf.js", "text/javascript", False, QUARANTINE),
    ("bilder.zip", "application/zip", False, QUARANTINE),
    ("noextension", "application/octet-stream", False, QUARANTINE),
    ("data.bin", "application/octet-stream", False, QUARANTINE),
    ("sida.html", "text/html", False, QUARANTINE),
    ("okand.xyz", "application/x-something", False, QUARANTINE),   # not allowlisted
    ("faktura.PDF", "application/pdf", False, DOCUMENTS),
    ("bild.HEIC", "image/heic", False, DOCUMENTS),
    # Hidden characters must not disguise the real extension.
    ("faktura.pdf.ex​e", "application/pdf", False, QUARANTINE),
    ("faktura.pdf.ex⁠e ", "application/pdf", False, QUARANTINE),
    ("faktura‮gpj.exe", "image/jpeg", False, QUARANTINE),
])
def test_classify(name, ctype, junk, expected):
    category, _reasons = classify(name, ctype, junk)
    assert category == expected


@pytest.mark.parametrize("raw,expected", [
    ("../../.zshrc", "_.._.zshrc"),
    ("a/b\\c:d.pdf", "a_b_c_d.pdf"),
    ("  .hidden. ", "hidden"),
    ("", "bilaga"),
    ("x" * 300 + ".pdf", "x" * 150 + ".pdf"),
])
def test_safe_filename(raw, expected):
    assert safe_filename(raw) == expected


def _message(attachments: list[tuple[str, str, bytes]]) -> bytes:
    msg = EmailMessage()
    msg["From"] = "a@example.com"
    msg["To"] = "test@example.com"
    msg["Subject"] = "Bilagor"
    msg.set_content("Se bifogat.")
    for name, ctype, data in attachments:
        maintype, subtype = ctype.split("/")
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    return msg.as_bytes()


@pytest.fixture
def saving_account(account, tmp_path):
    acc = accounts.get_account("test")
    acc.permissions.save_attachments = True
    accounts.save_account(acc)
    accounts.save_settings(attachments_root=str(tmp_path / "bilagor"))
    return accounts.get_account("test"), tmp_path / "bilagor"


def test_requires_permission(account):
    with pytest.raises(attachment_store.AttachmentError, match="does not allow saving"):
        attachment_store.save_message_attachments(account, _message([("a.pdf", "application/pdf", b"%PDF")]),
                                                  None, in_junk=False)


def test_saves_into_account_year_month_category(saving_account):
    acc, root = saving_account
    from datetime import datetime
    raw = _message([("faktura.pdf", "application/pdf", b"%PDF-1"), ("setup.exe", "application/octet-stream", b"MZ")])
    rows = attachment_store.save_message_attachments(acc, raw, datetime(2026, 3, 9), in_junk=False)
    paths = {r["filename"]: r["path"] for r in rows}
    assert paths["faktura.pdf"] == "test/2026/03/dokument/faktura.pdf"
    assert paths["setup.exe"] == "test/2026/03/karantän/setup.exe"
    saved = root / paths["setup.exe"]
    mode = stat.S_IMODE(os.stat(saved).st_mode)
    assert mode == 0o600 and not mode & stat.S_IXUSR


def test_duplicates_are_not_saved_twice(saving_account):
    acc, root = saving_account
    raw = _message([("faktura.pdf", "application/pdf", b"%PDF-same")])
    first = attachment_store.save_message_attachments(acc, raw, None, in_junk=False)
    second = attachment_store.save_message_attachments(acc, raw, None, in_junk=False)
    assert first[0]["status"] == "saved" and second[0]["status"] == "already_saved"
    other = _message([("faktura.pdf", "application/pdf", b"%PDF-different")])
    third = attachment_store.save_message_attachments(acc, other, None, in_junk=False)
    assert third[0]["path"].endswith("faktura (2).pdf")


def test_caller_can_add_quarantine_but_not_remove_it(saving_account):
    acc, _root = saving_account
    raw = _message([("faktura.pdf", "application/pdf", b"%PDF"), ("x.exe", "application/octet-stream", b"MZ")])
    rows = attachment_store.save_message_attachments(acc, raw, None, in_junk=False, quarantine=True)
    assert all(r["category"] == QUARANTINE for r in rows)


def test_paths_never_leave_the_root(saving_account):
    acc, root = saving_account
    raw = _message([("../../../../etc/evil.pdf", "application/pdf", b"%PDF")])
    rows = attachment_store.save_message_attachments(acc, raw, None, in_junk=False)
    written = (root / rows[0]["path"]).resolve()
    assert str(written).startswith(str(root.resolve()))


def test_size_limits(saving_account, monkeypatch):
    acc, _root = saving_account
    monkeypatch.setattr(attachment_store, "MAX_FILE_BYTES", 10)
    raw = _message([("big.pdf", "application/pdf", b"x" * 20)])
    rows = attachment_store.save_message_attachments(acc, raw, None, in_junk=False)
    assert rows[0]["status"] == "skipped" and rows[0]["reason"] == "too_large"


def test_mcp_tool_saves_without_marking_read(saving_account, fake_server, mailbox):
    import asyncio
    import mcp_server

    folder, uid = mailbox["multipart"]
    validity = asyncio.run(mcp_server.mcp.call_tool("imap_search", {"account": "test"})).structured_content["uidvalidity"]
    before = fake_server.store.flags(folder, uid)
    result = asyncio.run(mcp_server.mcp.call_tool("imap_save_attachments", {
        "account": "test", "folder": folder, "uids": [uid], "uidvalidity": validity})).structured_content
    assert result["counts"]["saved"] >= 1
    assert all(r["path"].startswith("test/") for r in result["saved"] if r["status"] == "saved")
    assert fake_server.store.flags(folder, uid) == before


def test_mcp_tool_needs_permission(account, mailbox):
    import asyncio
    from mcp.server.mcpserver.exceptions import ToolError
    import mcp_server

    folder, uid = mailbox["multipart"]
    with pytest.raises(ToolError, match="does not allow saving"):
        asyncio.run(mcp_server.mcp.call_tool("imap_save_attachments", {
            "account": "test", "folder": folder, "uids": [uid], "uidvalidity": 1}))


def test_inline_parts_are_reported_as_skipped(saving_account, fake_server, mailbox):
    from fake_imap import FakeImapServer  # noqa: F401  - fixture module already loaded
    acc, _root = saving_account
    raw = fake_server.store.folder(mailbox["multipart"][0]).messages[mailbox["multipart"][1]].raw
    rows = attachment_store.save_message_attachments(acc, raw, None, in_junk=False)
    inline = [r for r in rows if r.get("reason") == "inline"]
    assert inline and all(r["status"] == "skipped" for r in inline)
