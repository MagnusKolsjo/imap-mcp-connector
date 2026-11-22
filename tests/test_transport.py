# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""Transport selection: http mode never starts without a proper key."""

from __future__ import annotations

import logging

import pytest

import mcp_transport


@pytest.fixture
def started(monkeypatch):
    calls = []
    monkeypatch.setenv("MCP_TRANSPORT", "http")
    monkeypatch.delenv("MCP_HOST", raising=False)
    monkeypatch.delenv("MCP_PORT", raising=False)
    monkeypatch.setattr(mcp_transport, "_start_http", lambda mcp, **kwargs: calls.append(kwargs))
    return calls


@pytest.mark.parametrize("key", ["", "   ", "short", "x" * (mcp_transport.MIN_API_KEY_LENGTH - 1)])
def test_http_refuses_a_missing_or_short_key(started, monkeypatch, key):
    monkeypatch.setenv("MCP_API_KEY", key)
    with pytest.raises(SystemExit) as exit_info:
        mcp_transport.start(object(), default_port=8143)
    assert exit_info.value.code == 2 and started == []


def test_http_starts_with_a_long_key_and_warns_about_a_public_address(started, monkeypatch, caplog):
    key = "k" * mcp_transport.MIN_API_KEY_LENGTH
    monkeypatch.setenv("MCP_API_KEY", key)
    with caplog.at_level(logging.WARNING, logger="mcp_transport"):
        mcp_transport.start(object(), default_port=8143)
        assert started == [{"host": "127.0.0.1", "port": 8143, "api_key": key}] and caplog.records == []
        monkeypatch.setenv("MCP_HOST", "0.0.0.0")
        mcp_transport.start(object(), default_port=8143)
    assert started[-1]["host"] == "0.0.0.0"
    assert any("does not encrypt" in record.getMessage() for record in caplog.records)
