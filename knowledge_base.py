# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""Per-account knowledge bases of questions and answers, for suggesting replies.

A knowledge base is one Markdown file per account, imported through the
settings (browser page or panel) into the connector's own folder, so the
tools always know where it is. The format is deliberately plain so that
people and AI tools can write it:

    ---
    ton: vänlig och kortfattad, du-tilltal
    signatur: Styrelsen, Exempelföreningen
    instruktioner: Hänvisa betalningsfrågor till kassören.
    ---

    ## Hur blir jag medlem?
    Nyckelord: medlemskap, gå med, anmälan
    Fyll i formuläret på …

    ## Vad kostar medlemsavgiften?
    300 kronor per år. <!-- Höjs troligen 2027, nämn inte. -->

  * The optional front matter holds `key: value` lines for tone, signature
    and other instructions. Any key is passed on.
  * Each `## ` heading is a question; the text until the next heading is the
    answer. An optional first line `Nyckelord:`/`Keywords:` lists words that
    should also match.
  * HTML comments are notes for the people editing the file. They are
    removed when the file is read and never reach the AI, so internal notes
    cannot leak into a reply.

The connector itself does not write replies; it has no language model. It
finds the entries that match a message, and the AI client writes a draft
from them. The knowledge base is read-only for the MCP tools: nothing a
received mail says can change it.

Entry points:
    parse(text) -> KnowledgeBase
    load(account_id) -> KnowledgeBase | None
    import_text(account_id, text) -> KnowledgeBase
    remove(account_id)
    search(kb, query, limit) -> list[dict]
"""

from __future__ import annotations

import os
import re
import tempfile
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import accounts

MAX_FILE_BYTES = 1024 * 1024
_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_KEYWORDS = re.compile(r"^\s*(?:nyckelord|keywords)\s*:\s*(.+)$", re.IGNORECASE)
_WORD = re.compile(r"[\w]+", re.UNICODE)
# Words too common to say anything about which question a mail is about.
_STOPWORDS = {
    # Swedish
    "och", "att", "det", "som", "en", "ett", "är", "på", "för", "med", "till", "av", "jag", "vi",
    "du", "ni", "kan", "hur", "vad", "när", "var", "om", "har", "inte", "den", "de", "i", "så",
    "min", "mitt", "mina", "er", "ert", "era", "man", "ska", "skulle", "vill", "hej", "tack",
    "vänliga", "hälsningar", "mvh", "eller", "men", "från", "sig", "detta", "denna", "här",
    # English
    "the", "a", "an", "and", "or", "to", "of", "in", "on", "for", "with", "is", "are", "i", "we",
    "you", "can", "how", "what", "when", "where", "do", "does", "my", "our", "your", "it", "this",
    "that", "be", "have", "has", "not", "hi", "hello", "thanks", "regards", "please",
}


class KnowledgeError(Exception):
    """The knowledge file could not be read or imported."""


@dataclass
class Entry:
    question: str
    answer: str
    keywords: list[str] = field(default_factory=list)


@dataclass
class KnowledgeBase:
    meta: dict[str, str]
    entries: list[Entry]
    updated: str | None = None


def _normalise_words(text: str) -> list[str]:
    text = unicodedata.normalize("NFC", text).casefold()
    return [w for w in _WORD.findall(text) if w not in _STOPWORDS and len(w) > 1]


def parse(text: str) -> KnowledgeBase:
    """Parse the Markdown format described in the module docstring."""
    text = _COMMENT.sub("", text.replace("\r\n", "\n").replace("\r", "\n"))
    meta: dict[str, str] = {}
    lines = text.split("\n")
    if lines and lines[0].strip() == "---":
        for i in range(1, len(lines)):
            if lines[i].strip() == "---":
                for line in lines[1:i]:
                    key, sep, value = line.partition(":")
                    if sep and key.strip():
                        meta[key.strip().casefold()] = value.strip()
                lines = lines[i + 1:]
                break

    entries: list[Entry] = []
    question: str | None = None
    body: list[str] = []

    def flush() -> None:
        if question is None:
            return
        keywords: list[str] = []
        content = list(body)
        while content and not content[0].strip():
            content.pop(0)
        if content and (m := _KEYWORDS.match(content[0])):
            keywords = [k.strip() for k in m.group(1).split(",") if k.strip()]
            content.pop(0)
        answer = "\n".join(content).strip()
        if question.strip() and answer:
            entries.append(Entry(question.strip(), answer, keywords))

    for line in lines:
        if line.startswith("## "):
            flush()
            question, body = line[3:], []
        elif question is not None:
            body.append(line)
    flush()
    return KnowledgeBase(meta=meta, entries=entries)


def load(account_id: str) -> KnowledgeBase | None:
    path = accounts.knowledge_path(account_id)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError) as exc:
        raise KnowledgeError(f"Cannot read the knowledge base: {exc}") from exc
    kb = parse(text)
    kb.updated = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
    return kb


def import_text(account_id: str, data: bytes | str) -> KnowledgeBase:
    """Validate and store a knowledge file for an account (replacing any previous one)."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    if len(raw) > MAX_FILE_BYTES:
        raise KnowledgeError("The file is larger than 1 MB.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise KnowledgeError("The file is not UTF-8 text. Save it as UTF-8 and try again.") from exc
    kb = parse(text)
    if not kb.entries:
        raise KnowledgeError(
            "No questions were found. Each question should start with '## ' on its own line, "
            "followed by the answer."
        )
    path = accounts.knowledge_path(account_id)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".kb-", suffix=".md")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    kb.updated = datetime.now(timezone.utc).isoformat()
    return kb


def remove(account_id: str) -> bool:
    path = accounts.knowledge_path(account_id)
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return False


def _score(query_words: list[str], entry: Entry) -> float:
    """Word overlap, weighted towards the question and keywords.

    Swedish compounds ("medlemsavgift", "avgiften") are matched by shared
    prefixes of at least five letters, which catches most inflections
    without a stemmer.
    """
    def matches(word: str, candidates: set[str]) -> bool:
        if word in candidates:
            return True
        stem = word[:5]
        return len(word) >= 5 and any(c.startswith(stem) or (len(c) >= 5 and word.startswith(c[:5])) for c in candidates)

    question = set(_normalise_words(entry.question))
    keywords = set(_normalise_words(" ".join(entry.keywords)))
    answer = set(_normalise_words(entry.answer))
    score = 0.0
    for word in set(query_words):
        if matches(word, question):
            score += 3
        elif matches(word, keywords):
            score += 3
        elif matches(word, answer):
            score += 1
    return score


def search(kb: KnowledgeBase, query: str, limit: int = 5) -> list[dict[str, Any]]:
    words = _normalise_words(query)
    ranked = sorted(
        ((s, i, e) for i, e in enumerate(kb.entries) if (s := _score(words, e)) > 0),
        key=lambda t: (-t[0], t[1]),
    )
    return [
        {"question": e.question, "answer": e.answer, "keywords": e.keywords, "score": s}
        for s, _i, e in ranked[: max(1, min(int(limit), 20))]
    ]
