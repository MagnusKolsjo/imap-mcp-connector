# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""Translations for the admin UI.

Each language is one flat JSON file in `locales/`, named after its BCP 47
code (`sv.json`, `en.json`). Adding a language means dropping a new file
there; it is discovered at start-up. The key `_meta.language_name` holds the
language's name written in that language, for the language switcher.

Lookup order for a key is: the requested language, English, the key itself.
Showing the key rather than failing keeps a half-translated file usable and
makes the gap visible.

Entry points:
    available_languages() -> list[tuple[code, name]]
    translate(lang, key, **values) -> str
    raw(lang, key) -> str
    negotiate(query, cookie, accept_language) -> code
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

LOCALES_DIR = Path(__file__).resolve().parent / "locales"
REFERENCE_LANGUAGE = "en"

# Codes become file names and HTML lang attributes, so only plain BCP 47
# shapes such as "sv" or "pt-BR" are accepted.
_CODE_PATTERN = re.compile(r"^[a-z]{2,3}(-[A-Za-z0-9]{2,8})?$")


@lru_cache(maxsize=1)
def _catalogs() -> dict[str, dict[str, str]]:
    catalogs: dict[str, dict[str, str]] = {}
    for path in sorted(LOCALES_DIR.glob("*.json")):
        code = path.stem
        if not _CODE_PATTERN.match(code):
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        catalogs[code] = {str(k): str(v) for k, v in data.items()}
    return catalogs


def reload() -> None:
    """Forget cached catalogs, so edited or added files are read again."""
    _catalogs.cache_clear()


def catalog(lang: str) -> dict[str, str]:
    return dict(_catalogs().get(lang, {}))


def available_languages() -> list[tuple[str, str]]:
    """Return (code, name in its own language), sorted by code."""
    return [
        (code, entries.get("_meta.language_name", code))
        for code, entries in sorted(_catalogs().items())
    ]


def is_supported(code: str | None) -> bool:
    return bool(code) and code in _catalogs()


def raw(lang: str, key: str) -> str:
    """Return the untranslated template string for a key."""
    catalogs = _catalogs()
    for code in (lang, REFERENCE_LANGUAGE):
        value = catalogs.get(code, {}).get(key)
        if value is not None:
            return value
    return key


def translate(lang: str, key: str, **values: object) -> str:
    """Return the translated string with {placeholders} filled in."""
    template = raw(lang, key)
    if not values:
        return template
    try:
        return template.format(**values)
    except (KeyError, IndexError, ValueError):
        # A translation that names a placeholder the code does not pass is
        # still better shown unformatted than not at all.
        return template


def _parse_accept_language(header: str) -> list[str]:
    weighted = []
    for position, part in enumerate(header.split(",")):
        piece = part.strip()
        if not piece:
            continue
        tag, _, params = piece.partition(";")
        quality = 1.0
        for param in params.split(";"):
            name, _, value = param.strip().partition("=")
            if name == "q":
                try:
                    quality = float(value)
                except ValueError:
                    quality = 0.0
        if quality > 0:
            # Position breaks ties so the browser's own order is kept.
            weighted.append((-quality, position, tag.strip()))
    return [tag for _, _, tag in sorted(weighted)]


def negotiate(query: str | None, cookie: str | None, accept_language: str | None) -> str:
    """Pick the UI language: ?lang=, then cookie, then Accept-Language, then English."""
    for candidate in (query, cookie):
        if is_supported(candidate):
            return candidate  # type: ignore[return-value]
    for tag in _parse_accept_language(accept_language or ""):
        if is_supported(tag):
            return tag
        primary = tag.split("-")[0].lower()
        if is_supported(primary):
            return primary
    return REFERENCE_LANGUAGE
