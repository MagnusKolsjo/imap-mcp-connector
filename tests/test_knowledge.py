# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""Knowledge base: parsing, internal notes, search, import and the MCP tools."""

from __future__ import annotations

import asyncio

import pytest
from mcp.server.mcpserver.exceptions import ToolError

import accounts
import knowledge_base
import mcp_server
import native_dialog

SAMPLE = """---
ton: vänlig och kortfattad, du-tilltal
signatur: Styrelsen, Exempelföreningen
---

## Hur blir jag medlem?
Nyckelord: medlemskap, gå med, anmälan
Fyll i formuläret på föreningens webbplats.

## Vad kostar medlemsavgiften?
300 kronor per år. <!-- Höjs troligen 2027, nämn inte. -->

## När är årsmötet?
Årsmötet hålls i mars varje år.

<!--
## Utkast som inte är klart
Ska inte synas.
-->
"""


def call(_tool: str, **arguments):
    try:
        result = asyncio.run(mcp_server.mcp.call_tool(_tool, arguments))
    except ToolError as exc:
        return None, True, str(exc)
    return result.structured_content, result.is_error, ""


def test_parse_front_matter_entries_keywords():
    kb = knowledge_base.parse(SAMPLE)
    assert kb.meta == {"ton": "vänlig och kortfattad, du-tilltal", "signatur": "Styrelsen, Exempelföreningen"}
    assert [e.question for e in kb.entries] == ["Hur blir jag medlem?", "Vad kostar medlemsavgiften?", "När är årsmötet?"]
    assert kb.entries[0].keywords == ["medlemskap", "gå med", "anmälan"]


def test_comments_never_reach_the_ai():
    kb = knowledge_base.parse(SAMPLE)
    flat = repr(kb)
    assert "2027" not in flat and "Utkast" not in flat and "Ska inte synas" not in flat


@pytest.mark.parametrize("query,expected", [
    ("Hej! Vad kostar det att vara medlem?", "Vad kostar medlemsavgiften?"),
    ("Jag skulle vilja gå med i föreningen", "Hur blir jag medlem?"),
    ("När har ni årsmöte i år?", "När är årsmötet?"),
])
def test_search_finds_the_right_question(query, expected):
    kb = knowledge_base.parse(SAMPLE)
    assert knowledge_base.search(kb, query)[0]["question"] == expected


def test_search_without_match_is_empty():
    assert knowledge_base.search(knowledge_base.parse(SAMPLE), "Parkering vid stationen") == []


def test_import_validates(config_file):
    with pytest.raises(knowledge_base.KnowledgeError, match="No questions"):
        knowledge_base.import_text("test", "Bara text utan rubriker.")
    with pytest.raises(knowledge_base.KnowledgeError, match="UTF-8"):
        knowledge_base.import_text("test", "## Fråga\nSvar".encode("latin-1"))
    with pytest.raises(knowledge_base.KnowledgeError, match="1 MB"):
        knowledge_base.import_text("test", "## F\n" + "x" * (knowledge_base.MAX_FILE_BYTES + 1))


def test_import_stores_privately_and_load(config_file):
    kb = knowledge_base.import_text("test", SAMPLE)
    assert len(kb.entries) == 3
    path = accounts.knowledge_path("test")
    assert path.stat().st_mode & 0o777 == 0o600
    assert knowledge_base.load("test").entries[2].answer.startswith("Årsmötet")


def test_knowledge_removed_with_account(account):
    knowledge_base.import_text("test", SAMPLE)
    accounts.delete_account("test")
    assert not accounts.knowledge_path("test").exists()


def test_mcp_search_tool(account):
    knowledge_base.import_text("test", SAMPLE)
    result, is_error, _ = call("imap_knowledge_search", account="test", query="Vad kostar medlemskapet?")
    assert not is_error
    assert result["matches"][0]["question"] == "Vad kostar medlemsavgiften?"
    assert result["meta"]["signatur"] == "Styrelsen, Exempelföreningen"
    assert "do not" in result["guidance"].lower() or "Do not" in result["guidance"]


def test_mcp_tools_without_knowledge_base(account):
    _r, is_error, text = call("imap_knowledge_overview", account="test")
    assert is_error and "no knowledge base" in text


def test_overview_hides_answers_unless_asked(account):
    knowledge_base.import_text("test", SAMPLE)
    short, _, _ = call("imap_knowledge_overview", account="test")
    full, _, _ = call("imap_knowledge_overview", account="test", include_answers=True)
    assert "answer" not in short["entries"][0] and "answer" in full["entries"][0]


def test_panel_import_reads_file_from_native_picker(account, tmp_path, monkeypatch):
    source = tmp_path / "faq.md"
    source.write_text(SAMPLE, encoding="utf-8")
    monkeypatch.setattr(native_dialog, "available", lambda: True)
    monkeypatch.setattr(native_dialog, "choose_file", lambda prompt: str(source))
    result, is_error, _ = call("imap_panel_import_knowledge", account_id="test", lang="sv")
    assert not is_error and result == {"imported": True, "entries": 3, "meta_keys": ["signatur", "ton"]}
    # The file was copied: editing the original does not change the account's copy.
    source.write_text("## Ny\nNytt svar", encoding="utf-8")
    assert len(knowledge_base.load("test").entries) == 3


def test_panel_import_reports_bad_file(account, tmp_path, monkeypatch):
    source = tmp_path / "fel.md"
    source.write_text("Ingen fråga här", encoding="utf-8")
    monkeypatch.setattr(native_dialog, "available", lambda: True)
    monkeypatch.setattr(native_dialog, "choose_file", lambda prompt: str(source))
    result, _, _ = call("imap_panel_import_knowledge", account_id="test")
    assert result["imported"] is False and "No questions" in result["error"]
