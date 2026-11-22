# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""Server side of the panels: privacy, read marking, permissions and native confirmations.

The panel HTML itself is checked in a browser with tests/panel_harness.py.
These tests pin down what the panel tools allow, because the client's
"app only" visibility is a hint the server cannot enforce: a model calling
a panel tool directly must gain nothing.
"""

from __future__ import annotations

import asyncio
import json
import subprocess

import pytest
from mcp.server.mcpserver.exceptions import ToolError

import accounts
import mcp_panels
import mcp_server
import native_dialog

# Captured at import, before the autouse fixture replaces it: the two tests
# at the end check the real implementation against a faked osascript.
_REAL_RUN = native_dialog._run


def call(_tool: str, **arguments):
    try:
        result = asyncio.run(mcp_server.mcp.call_tool(_tool, arguments))
    except ToolError as exc:
        return None, True, str(exc)
    text = " ".join(getattr(c, "text", "") for c in result.content)
    return result.structured_content, result.is_error, text


def data(_tool: str, **arguments) -> dict:
    content, is_error, text = call(_tool, **arguments)
    assert not is_error, text
    return content


class Dialogs:
    """Records native dialog requests and answers them as configured."""

    def __init__(self):
        self.confirm_answer = True
        self.password = "from-native-dialog"
        self.confirmations: list[str] = []
        self.password_prompts: list[str] = []

    def confirm(self, title, message, ok, cancel):
        self.confirmations.append(message)
        return self.confirm_answer

    def ask_password(self, title, message, ok, cancel):
        self.password_prompts.append(message)
        return self.password


@pytest.fixture
def dialogs(monkeypatch):
    fake = Dialogs()
    monkeypatch.setattr(native_dialog, "available", lambda: True)
    monkeypatch.setattr(native_dialog, "confirm", fake.confirm)
    monkeypatch.setattr(native_dialog, "ask_password", fake.ask_password)
    return fake


def form(acc: accounts.Account, **changes) -> dict:
    data = acc.to_json()
    perms = data.pop("permissions")
    data.update(organise=perms["organise"], send_mode=perms["send_mode"])
    data.update(changes)
    return data


# -----------------------------------------------------------------------------
# Opening tools and resources
# -----------------------------------------------------------------------------

def test_opening_tools_carry_no_mail(account, mailbox):
    result = data("imap_open_mailbox")
    assert result["panel"] == "mailbox" and result["account"] == "test"
    flat = json.dumps(result)
    assert "Lunch on Friday" not in flat and "subject" not in flat


def test_tools_declare_ui_metadata():
    tools = {t.name: t for t in asyncio.run(mcp_server.mcp.list_tools())}
    assert tools["imap_open_mailbox"].meta["ui"]["resourceUri"] == mcp_panels.MAILBOX_URI
    assert tools["imap_open_settings"].meta["ui"]["resourceUri"] == mcp_panels.SETTINGS_URI
    panel_tools = [n for n in tools if n.startswith("imap_panel_")]
    assert len(panel_tools) == 17
    assert all(tools[n].meta["ui"]["visibility"] == ["app"] for n in panel_tools)


@pytest.mark.parametrize("uri", [mcp_panels.MAILBOX_URI, mcp_panels.SETTINGS_URI])
def test_panel_resources_embed_translations(uri):
    [content] = asyncio.run(mcp_server.mcp.read_resource(uri))
    assert content.mime_type == mcp_panels.APP_MIME_TYPE
    assert "/*__I18N__*/null" not in content.content
    assert '"sv"' in content.content and '"en"' in content.content


def test_panel_translations_cannot_close_the_script(monkeypatch):
    # Locale files are editable by anyone translating; a value must not be
    # able to end the script element it is embedded in.
    import i18n

    monkeypatch.setattr(i18n, "catalog", lambda code: {"panel.evil": "</script><img src=x onerror=alert(1)>"})
    html = mcp_panels._panel_html("mailbox.html")
    assert "</script><img" not in html
    assert "<\\/script><img" in html


# -----------------------------------------------------------------------------
# Reading in the panel
# -----------------------------------------------------------------------------

def _open(mailbox_key, mailbox):
    folder, uid = mailbox[mailbox_key]
    listing = data("imap_panel_list", account="test", folder=folder)
    return data("imap_panel_open", account="test", folder=folder, uid=uid, uidvalidity=listing["uidvalidity"])


def test_panel_open_does_not_mark_read_by_default(account, fake_server, mailbox):
    result = _open("plain", mailbox)
    assert result["marked_read"] is False
    assert "\\Seen" not in fake_server.store.flags(*mailbox["plain"])


def test_panel_open_marks_read_when_user_chose_it(account, fake_server, mailbox):
    acc = accounts.get_account("test")
    acc.read_marking = accounts.ReadMarking.USER_OPEN
    accounts.save_account(acc)
    result = _open("plain", mailbox)
    assert result["marked_read"] is True and "\\Seen" in result["flags"]
    assert "\\Seen" in fake_server.store.flags(*mailbox["plain"])
    # The model's own reading still never marks anything, whatever the setting.
    folder, uid = mailbox["html"]
    data("imap_get_message", account="test", folder=folder, uid=uid)
    assert "\\Seen" not in fake_server.store.flags(folder, uid)


def test_panel_open_returns_plain_text_body(account, mailbox):
    result = _open("html", mailbox)
    assert result["body_format"] == "html"
    assert "<" not in result["body"].split("(")[0]  # converted to text, hidden parts removed


def test_panel_action_needs_organise(account, fake_server, mailbox):
    folder, uid = mailbox["plain"]
    before = fake_server.store.flags(folder, uid)
    _c, is_error, text = call("imap_panel_action", account="test", folder=folder, uids=[uid],
                              uidvalidity=1, action="mark_read")
    assert is_error and "does not allow organising" in text
    assert fake_server.store.flags(folder, uid) == before


def test_panel_action_with_organise(account, fake_server, mailbox):
    acc = accounts.get_account("test")
    acc.permissions.organise = True
    accounts.save_account(acc)
    folder, uid = mailbox["plain"]
    validity = data("imap_panel_list", account="test", folder=folder)["uidvalidity"]
    data("imap_panel_action", account="test", folder=folder, uids=[uid], uidvalidity=validity, action="flag")
    assert "\\Flagged" in fake_server.store.flags(folder, uid)
    data("imap_panel_action", account="test", folder=folder, uids=[uid], uidvalidity=validity, action="trash")
    assert uid not in fake_server.store.folder(folder).messages


# -----------------------------------------------------------------------------
# Settings: what needs a native confirmation
# -----------------------------------------------------------------------------

def _acc(**perms) -> accounts.Account:
    return accounts.Account(
        id="x", display_name="X", email="x@example.com", imap_host="imap.example.com",
        permissions=accounts.Permissions(**perms),
    )


@pytest.mark.parametrize("old,new,expected", [
    (dict(), dict(), []),
    (dict(organise=True), dict(), []),                                         # lowering
    (dict(send_mode=accounts.SendMode.SEND), dict(send_mode=accounts.SendMode.DRAFTS), []),
    (dict(), dict(organise=True), ["dialog.reason.organise_on"]),
    (dict(), dict(send_mode=accounts.SendMode.DRAFTS), ["dialog.reason.send_raised"]),
    (dict(send_mode=accounts.SendMode.DRAFTS), dict(send_mode=accounts.SendMode.SEND), ["dialog.reason.send_raised"]),
    (dict(send_approval=accounts.SendApproval.ASK), dict(send_approval=accounts.SendApproval.NEVER), ["dialog.reason.approval_relaxed"]),
    (dict(send_approval=accounts.SendApproval.NEVER), dict(send_approval=accounts.SendApproval.ASK_OR_WINDOW), []),
    (dict(), dict(save_attachments=True), ["dialog.reason.attachments_on"]),
    (dict(save_attachments=True), dict(), []),
])
def test_needs_confirmation_permissions(config_file, old, new, expected):
    assert mcp_panels.needs_confirmation(_acc(**old), _acc(**new)) == expected


def test_needs_confirmation_server_change_only_with_password(config_file, monkeypatch):
    old, new = _acc(), _acc()
    new.imap_host = "evil.example.net"
    monkeypatch.setattr(accounts, "has_secret", lambda account_id, kind="imap": False)
    assert mcp_panels.needs_confirmation(old, new) == []
    monkeypatch.setattr(accounts, "has_secret", lambda account_id, kind="imap": True)
    assert mcp_panels.needs_confirmation(old, new) == ["dialog.reason.server_changed"]


def test_needs_confirmation_smtp_only_secret(config_file, monkeypatch):
    old, new = _acc(), _acc()
    new.smtp_host = "evil.example.net"
    monkeypatch.setattr(accounts, "has_secret", lambda account_id, kind="imap": kind == "smtp")
    assert mcp_panels.needs_confirmation(old, new) == ["dialog.reason.server_changed"]


def test_save_lowering_needs_no_dialog(account, dialogs):
    acc = accounts.get_account("test")
    acc.permissions = accounts.Permissions(organise=True, send_mode=accounts.SendMode.SEND)
    acc.smtp_host = "smtp.example.com"
    accounts.save_account(acc)
    result = data("imap_panel_save_account", account=form(acc, organise=False, send_mode="drafts"),
                  account_id="test", lang="sv")
    assert result == {"saved": True, "account_id": "test", "confirmed": False}
    assert dialogs.confirmations == []
    assert accounts.get_account("test").permissions.organise is False


def test_save_raising_is_confirmed_natively(account, dialogs):
    acc = accounts.get_account("test")
    result = data("imap_panel_save_account", account=form(acc, organise=True), account_id="test", lang="sv")
    assert result["saved"] is True and result["confirmed"] is True
    assert len(dialogs.confirmations) == 1 and "organisera" in dialogs.confirmations[0]


def test_save_raising_cancelled_changes_nothing(account, dialogs):
    dialogs.confirm_answer = False
    acc = accounts.get_account("test")
    result = data("imap_panel_save_account", account=form(acc, send_mode="drafts"), account_id="test")
    assert result["saved"] is False and result["cancelled"] is True and result["reasons"]
    assert accounts.get_account("test").permissions.send_mode is accounts.SendMode.OFF


def test_server_change_with_password_is_confirmed(account, dialogs):
    acc = accounts.get_account("test")
    dialogs.confirm_answer = False
    result = data("imap_panel_save_account", account=form(acc, imap_host="evil.example.net"), account_id="test")
    assert result["cancelled"] is True
    assert accounts.get_account("test").imap_host == acc.imap_host


def test_save_without_native_dialogs_sends_to_browser(account, monkeypatch):
    monkeypatch.setattr(native_dialog, "available", lambda: False)
    acc = accounts.get_account("test")
    result = data("imap_panel_save_account", account=form(acc, organise=True), account_id="test", lang="en")
    assert result["saved"] is False and result["needs_browser"] is True and result["reasons"]
    assert accounts.get_account("test").permissions.organise is False


def test_save_invalid_input_returns_problems(account, dialogs):
    acc = accounts.get_account("test")
    result = data("imap_panel_save_account", account=form(acc, email="no-at-sign", imap_port="abc"), account_id="test")
    assert result["saved"] is False and {"email", "imap_port"} <= set(result["problems"])


def test_save_rejects_string_booleans(account, dialogs):
    acc = accounts.get_account("test")
    result = data("imap_panel_save_account", account=form(acc, organise="false"), account_id="test")
    assert result["saved"] is False and "organise" in result["problems"]


def test_create_account_from_panel(config_file, dialogs):
    new = {"display_name": "Föreningen", "email": "info@forening.se", "imap_host": "imap.forening.se"}
    result = data("imap_panel_save_account", account=new, lang="sv")
    assert result["saved"] is True and dialogs.confirmations == []
    assert accounts.get_account(result["account_id"]).imap_host == "imap.forening.se"


# -----------------------------------------------------------------------------
# Passwords only through the native dialog
# -----------------------------------------------------------------------------

def test_set_password_goes_from_dialog_to_keychain(account, dialogs, isolated_keyring):
    result = data("imap_panel_set_password", account_id="test", kind="imap", lang="sv")
    assert result == {"stored": True}
    assert isolated_keyring.get_password(accounts.KEYRING_SERVICE, "test:imap") == "from-native-dialog"
    # The password is in neither the arguments nor the result.
    assert "from-native-dialog" not in json.dumps(result)
    assert "test@example.com" in dialogs.password_prompts[0]


def test_set_password_cancelled(account, dialogs, isolated_keyring):
    dialogs.password = None
    result = data("imap_panel_set_password", account_id="test", kind="smtp")
    assert result == {"stored": False, "cancelled": True}
    assert isolated_keyring.get_password(accounts.KEYRING_SERVICE, "test:smtp") is None


def test_delete_is_confirmed_natively(account, dialogs):
    dialogs.confirm_answer = False
    assert data("imap_panel_delete_account", account_id="test")["cancelled"] is True
    assert "test" in accounts.load_accounts()
    dialogs.confirm_answer = True
    assert data("imap_panel_delete_account", account_id="test")["deleted"] is True
    assert "test" not in accounts.load_accounts()


@pytest.mark.parametrize("tool,args", [
    ("imap_panel_save_account", {"account": {}, "account_id": "test"}),
    ("imap_panel_set_password", {"account_id": "test"}),
    ("imap_panel_delete_account", {"account_id": "test"}),
])
def test_settings_changes_refused_over_http(account, dialogs, monkeypatch, tool, args):
    monkeypatch.setenv("MCP_TRANSPORT", "http")
    _c, is_error, text = call(tool, **args)
    assert is_error and "locally" in text


def test_settings_state_never_contains_passwords(account, dialogs, isolated_keyring):
    data("imap_panel_set_password", account_id="test")
    state = data("imap_panel_settings_state")
    assert "from-native-dialog" not in json.dumps(state)
    assert state["accounts"][0]["password_stored"] is True


# -----------------------------------------------------------------------------
# The dialog module itself
# -----------------------------------------------------------------------------

def test_native_dialog_passes_text_as_arguments(monkeypatch):
    seen = {}

    def fake_run(command, **kwargs):
        seen["command"] = command
        return subprocess.CompletedProcess(command, 0, stdout="Spara\n", stderr="")

    monkeypatch.setattr(native_dialog, "available", lambda: True)
    monkeypatch.setattr(native_dialog, "_run", _REAL_RUN)
    monkeypatch.setattr(subprocess, "run", fake_run)
    hostile = 'X" & (do shell script "rm -rf ~") & "'
    assert native_dialog.confirm("T", hostile, "Spara", "Avbryt") is True
    script = " ".join(seen["command"][: seen["command"].index("--")])
    # The account text is an argument after "--", never part of the script.
    assert hostile not in script and seen["command"][-3] == hostile


def test_native_dialog_cancel(monkeypatch):
    monkeypatch.setattr(native_dialog, "available", lambda: True)
    monkeypatch.setattr(native_dialog, "_run", _REAL_RUN)
    monkeypatch.setattr(subprocess, "run", lambda command, **kw: subprocess.CompletedProcess(
        command, 1, stdout="", stderr="execution error: User canceled. (-128)"))
    assert native_dialog.ask_password("T", "M", "OK", "Avbryt") is None
    assert native_dialog.confirm("T", "M", "OK", "Avbryt") is False

