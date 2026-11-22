# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""Panels (MCP Apps) for browsing mail and changing settings inside the AI client.

Two panels are served as `ui://` resources and rendered by clients that
support MCP Apps. Clients without that support
simply show the text result of the opening tool.

    imap_open_mailbox    mailbox panel: folders, message list, reading pane
    imap_open_settings   settings panel: accounts, servers, permissions

The opening tools return no mail content, only enough for the panel to
start. Everything the panel shows is fetched by the panel itself through
tools marked `visibility: ["app"]`, which the client keeps out of the
model's tool list. Mail the user browses is therefore shown to the user
without being handed to the model; the model sees a message only when the
user asks about it.

Visibility is enforced by the client, not by this server. The panel tools
are written so that a model calling one directly gains nothing it could
not do with the ordinary tools:

  * reading through the panel never marks mail as read unless the account
    is set to mark messages read when the user opens them, and then the
    worst case is a message marked read;
  * organising through the panel requires the same `organise` permission;
  * every settings change that gives the AI more power, or sends a stored
    password to a different server, needs a native macOS confirmation
    (native_dialog), and passwords are only ever typed into a native
    dialog. Lowering permissions needs no confirmation.

On systems without native dialogs the settings panel can show and lower
settings, and sends the user to the browser-based settings page for the
rest.

Entry point:
    register(mcp)
"""

from __future__ import annotations

import json
import os
from email.utils import getaddresses
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

import accounts
import i18n
import imap_client
import knowledge_base
import smtp_client
import mail_parse
import native_dialog
import send_approval
from mcp_annotations import LOCAL_ACTION, ORGANISE, READ_LOCAL, READ_MAILBOX, SAVE_LOCAL, SEND, TRASH

APP_MIME_TYPE = "text/html;profile=mcp-app"
MAILBOX_URI = "ui://imap-mcp-connector/mailbox.html"
SETTINGS_URI = "ui://imap-mcp-connector/settings.html"
PANEL_DIR = Path(__file__).resolve().parent / "panels"

# Locale keys the panels need. Only these are embedded in the panel HTML,
# so the admin page's texts do not travel to the client for nothing.
_PANEL_KEY_PREFIXES = ("_meta.", "panel.", "mailbox.", "settingspanel.", "dialog.", "field.", "hint.",
                       "error.", "send_mode.", "send_approval.", "save_sent.", "read_marking.", "security.", "common.")

# The panel shows whole messages, but a runaway body must not freeze it.
PANEL_MAX_BODY_CHARS = 200_000

_SEND_RANK = {accounts.SendMode.OFF: 0, accounts.SendMode.DRAFTS: 1, accounts.SendMode.SEND: 2}
# Higher means fewer questions before sending, i.e. more power for the AI.
_APPROVAL_RANK = {accounts.SendApproval.ASK: 0, accounts.SendApproval.ASK_OR_WINDOW: 1, accounts.SendApproval.NEVER: 2}
# Fields that decide where the stored password is sent. Changing any of them
# on an account that has a password is confirmed like raising a permission.
_SERVER_FIELDS = ("email", "imap_host", "imap_port", "imap_security", "username",
                  "smtp_host", "smtp_port", "smtp_security", "smtp_username")

_APP_ONLY = {"ui": {"visibility": ["app"]}}

_PANEL_WRITE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False
)
_PANEL_DELETE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=False
)


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def _t(lang: str, key: str, **values: object) -> str:
    return i18n.translate(lang if i18n.is_supported(lang) else "en", key, **values)


def _lang(code: str) -> str:
    """Map a host locale such as "sv-SE" to a language with a catalogue."""
    code = (code or "").strip()
    for candidate in (code, code.split("-")[0].lower()):
        if candidate and i18n.is_supported(candidate):
            return candidate
    return "en"


def _account(account_id: str) -> accounts.Account:
    try:
        return accounts.get_account(account_id)
    except accounts.ConfigError as exc:
        raise ToolError(str(exc)) from exc


def _call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except (imap_client.ImapError, accounts.ConfigError, accounts.SecretError) as exc:
        raise ToolError(str(exc)) from exc


def smtp_client_build(acc, **kwargs):
    return smtp_client.build_message(acc, **kwargs)


def _local_only() -> None:
    # Native dialogs would open on the server, not in front of the user.
    if os.getenv("MCP_TRANSPORT", "stdio").strip().lower() != "stdio":
        raise ToolError("Settings can only be changed when the server runs locally (stdio).")


def _panel_html(filename: str) -> str:
    """Panel HTML with the translations it needs embedded as JSON."""
    strings = {}
    for code, _name in i18n.available_languages():
        catalog = i18n.catalog(code)
        strings[code] = {k: v for k, v in catalog.items() if k.startswith(_PANEL_KEY_PREFIXES)}
    payload = json.dumps(strings, ensure_ascii=False).replace("</", "<\\/")
    html = (PANEL_DIR / filename).read_text(encoding="utf-8")
    return html.replace("/*__I18N__*/null", payload)


def _account_summary(acc: accounts.Account) -> dict[str, Any]:
    return {
        "id": acc.id,
        "display_name": acc.display_name,
        "email": acc.email,
        "organise": acc.permissions.organise,
        "send_mode": acc.permissions.send_mode.value,
        "read_marking": acc.read_marking.value,
        "send_approval": acc.permissions.send_approval.value,
        "save_attachments": acc.permissions.save_attachments,
        "has_knowledge_base": accounts.knowledge_path(acc.id).exists(),
    }


def _knowledge_status(account_id: str) -> dict[str, Any] | None:
    try:
        kb = knowledge_base.load(account_id)
    except knowledge_base.KnowledgeError as exc:
        return {"error": str(exc)}
    if kb is None:
        return None
    return {"entries": len(kb.entries), "updated": kb.updated, "meta_keys": sorted(kb.meta)}


def _accounts_or_error() -> dict[str, accounts.Account]:
    try:
        return accounts.load_accounts()
    except accounts.ConfigError as exc:
        raise ToolError(str(exc)) from exc


# -----------------------------------------------------------------------------
# Settings changes: what needs a native confirmation
# -----------------------------------------------------------------------------

def needs_confirmation(old: accounts.Account | None, new: accounts.Account) -> list[str]:
    """Reasons (translation keys) why saving `new` must be confirmed natively.

    Empty means the change only lowers what the AI may do, or touches
    nothing security relevant (names, folders, read marking, sent copies).
    """
    reasons = []
    if old is None:
        if (new.permissions.organise or new.permissions.save_attachments
                or new.permissions.send_mode is not accounts.SendMode.OFF
                or new.permissions.send_approval is not accounts.SendApproval.ASK):
            reasons.append("dialog.reason.new_with_permissions")
        return reasons
    if new.permissions.save_attachments and not old.permissions.save_attachments:
        reasons.append("dialog.reason.attachments_on")
    if new.permissions.organise and not old.permissions.organise:
        reasons.append("dialog.reason.organise_on")
    if _SEND_RANK[new.permissions.send_mode] > _SEND_RANK[old.permissions.send_mode]:
        reasons.append("dialog.reason.send_raised")
    if _APPROVAL_RANK[new.permissions.send_approval] > _APPROVAL_RANK[old.permissions.send_approval]:
        reasons.append("dialog.reason.approval_relaxed")
    # Any stored secret counts: a separate SMTP password follows smtp_host
    # just as the IMAP password follows imap_host, and the SMTP login falls
    # back to the IMAP password when no SMTP password exists.
    has_any_secret = accounts.has_secret(old.id, "imap") or accounts.has_secret(old.id, "smtp")
    if has_any_secret and any(getattr(old, f) != getattr(new, f) for f in _SERVER_FIELDS):
        reasons.append("dialog.reason.server_changed")
    return reasons


def _account_from_panel(data: dict[str, Any], existing: accounts.Account | None) -> tuple[accounts.Account | None, list[str]]:
    """Build an Account from panel input; return (account, problem field names)."""
    problems: list[str] = []
    text = lambda key: str(data.get(key, "") or "").strip()  # noqa: E731

    def port(key: str, default: int) -> int:
        raw = text(key)
        if not raw:
            return default
        try:
            return int(raw)
        except ValueError:
            problems.append(key)
            return default

    def enum(cls, key: str, default):
        try:
            return cls(text(key) or default.value)
        except ValueError:
            problems.append(key)
            return default

    organise = data.get("organise", False)
    if not isinstance(organise, bool):
        problems.append("organise")
        organise = False
    save_attachments = data.get("save_attachments", False)
    if not isinstance(save_attachments, bool):
        problems.append("save_attachments")
        save_attachments = False

    if existing is None:
        current_ids = set(_accounts_or_error())
        account_id = accounts.new_account_id(text("display_name") or text("email"), current_ids)
    else:
        account_id = existing.id

    candidate = accounts.Account(
        id=account_id,
        display_name=text("display_name"),
        email=text("email"),
        imap_host=text("imap_host"),
        imap_port=port("imap_port", 993),
        imap_security=text("imap_security") or "ssl",
        username=text("username"),
        smtp_host=text("smtp_host"),
        smtp_port=port("smtp_port", 465),
        smtp_security=text("smtp_security") or "ssl",
        smtp_username=text("smtp_username"),
        sent_folder=text("sent_folder"),
        drafts_folder=text("drafts_folder"),
        trash_folder=text("trash_folder"),
        save_sent=enum(accounts.SaveSent, "save_sent", accounts.SaveSent.AUTO),
        read_marking=enum(accounts.ReadMarking, "read_marking", accounts.ReadMarking.NEVER),
        permissions=accounts.Permissions(
            organise=organise,
            save_attachments=save_attachments,
            send_mode=enum(accounts.SendMode, "send_mode", accounts.SendMode.OFF),
            send_approval=enum(accounts.SendApproval, "send_approval", accounts.SendApproval.ASK),
        ),
    )
    try:
        problems += accounts.validate_account(candidate)
    except accounts.ConfigError as exc:
        raise ToolError(str(exc)) from exc
    return (None if problems else candidate), sorted(set(problems))


# -----------------------------------------------------------------------------
# Registration
# -----------------------------------------------------------------------------

def register(mcp) -> None:
    """Register the panel resources and tools on the MCP server."""

    @mcp.resource(
        MAILBOX_URI,
        name="Mailbox",
        title="Mailbox panel",
        description="Folders, message list and reading pane for the configured IMAP accounts.",
        mime_type=APP_MIME_TYPE,
    )
    def mailbox_panel() -> str:
        return _panel_html("mailbox.html")

    @mcp.resource(
        SETTINGS_URI,
        name="Settings",
        title="Settings panel",
        description="Accounts, servers and permissions for the IMAP MCP Connector. Passwords are entered in a native macOS dialog.",
        mime_type=APP_MIME_TYPE,
    )
    def settings_panel() -> str:
        return _panel_html("settings.html")

    # ---- Opening tools (visible to the model) ------------------------------

    @mcp.tool(title="Show the mailbox", annotations=READ_LOCAL, meta={"ui": {"resourceUri": MAILBOX_URI}})
    def imap_open_mailbox(
        account: str = "",
        folder: str = "INBOX",
        open_uid: int = 0,
        open_uidvalidity: int = 0,
    ) -> dict[str, Any]:
        """Show the mailbox panel so the user can browse, read and write mail themselves.

        In clients that support MCP Apps an interactive panel opens; other
        clients only get this text. The result contains no mail: the panel
        loads messages itself, and what the user reads there is not passed
        to you. If the user then asks about a message, read it with
        imap_get_message. `account` preselects an account id.

        With open_uid (and open_uidvalidity) the panel opens that message
        directly; a draft opens ready for editing. Use this right after
        saving a draft (imap_save_draft, imap_reply, imap_forward return the
        values) so the user can review and change it before it is sent.
        """
        items = _accounts_or_error()
        if account and account not in items:
            raise ToolError(f"Unknown account {account!r}.")
        chosen = account or (sorted(items)[0] if items else "")
        return {
            "panel": "mailbox",
            "account": chosen,
            "folder": folder,
            "open": {"uid": int(open_uid), "uidvalidity": int(open_uidvalidity)} if open_uid else None,
            "accounts": [_account_summary(a) for a in sorted(items.values(), key=lambda a: a.display_name.lower())],
            "note": (
                "The mailbox panel is shown to the user. No mail content is included here."
                if items else "No accounts yet. Call imap_open_settings so the user can add one."
            ),
        }

    @mcp.tool(title="Show mail settings", annotations=READ_LOCAL, meta={"ui": {"resourceUri": SETTINGS_URI}})
    def imap_open_settings() -> dict[str, Any]:
        """Show the settings panel for adding and changing mail accounts.

        In clients that support MCP Apps an interactive panel opens. On macOS
        passwords are typed into a native system dialog, never into the chat.
        If the user sees no panel, or is not on macOS, use
        imap_open_settings_in_browser instead.
        """
        items = _accounts_or_error()
        return {
            "panel": "settings",
            "accounts": [_account_summary(a) for a in sorted(items.values(), key=lambda a: a.display_name.lower())],
            "native_dialogs": native_dialog.available(),
            "note": "The settings panel is shown to the user. If nothing appears, call imap_open_settings_in_browser.",
        }

    # ---- Mailbox panel tools (app only) -------------------------------------

    @mcp.tool(title="Panel: folders", annotations=READ_MAILBOX, meta=_APP_ONLY)
    def imap_panel_folders(account: str) -> dict[str, Any]:
        """Mailbox panel helper: folders with counts. Not for answering questions."""
        acc = _account(account)
        return {"account": acc.id, "folders": _call(imap_client.list_folders, acc, True)}

    @mcp.tool(title="Panel: message list", annotations=READ_MAILBOX, meta=_APP_ONLY)
    def imap_panel_list(
        account: str,
        folder: str = "INBOX",
        text: str = "",
        unseen: bool | None = None,
        flagged: bool | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Mailbox panel helper: one page of message summaries, newest first."""
        acc = _account(account)
        criteria = _call(imap_client.build_criteria, text=text, unseen=unseen, flagged=flagged)
        result = _call(imap_client.search, acc, folder, criteria, limit, offset)
        result["account"] = acc.id
        result["permissions"] = _account_summary(acc)
        return result

    @mcp.tool(title="Panel: open message", annotations=ORGANISE, meta=_APP_ONLY)
    def imap_panel_open(account: str, folder: str, uid: int, uidvalidity: int) -> dict[str, Any]:
        """Mailbox panel helper: one message for the reading pane.

        Marks the message as read only when the account is set to mark mail
        read when the user opens it (read_marking = user_open).
        """
        acc = _account(account)
        parsed, flags, current = _call(imap_client.get_message, acc, folder, uid, uidvalidity)
        marked = False
        if acc.read_marking is accounts.ReadMarking.USER_OPEN and "\\Seen" not in flags:
            updated = _call(imap_client.set_flags, acc, folder, [uid], ["seen"], None, current)
            flags = updated["updated"][0]["flags"] if updated["updated"] else flags
            marked = True
        text = parsed.text
        return {
            "account": acc.id,
            "folder": folder,
            "uid": uid,
            "uidvalidity": current,
            "flags": flags,
            "marked_read": marked,
            "headers": parsed.headers,
            "body_format": parsed.body_format,
            "body": text[:PANEL_MAX_BODY_CHARS],
            "body_truncated": len(text) > PANEL_MAX_BODY_CHARS,
            "attachments": [a.as_dict() for a in parsed.attachments],
        }

    @mcp.tool(title="Panel: organise", annotations=TRASH, meta=_APP_ONLY)
    def imap_panel_action(
        account: str,
        folder: str,
        uids: list[int],
        uidvalidity: int,
        action: str,
        destination: str = "",
    ) -> dict[str, Any]:
        """Mailbox panel helper: mark_read, mark_unread, flag, unflag, trash or move.

        Requires the account's organise permission, like the ordinary tools.
        """
        acc = _account(account)
        if not acc.permissions.organise:
            raise ToolError(f"Account {acc.id!r} does not allow organising.")
        if not uidvalidity or int(uidvalidity) <= 0:
            raise ToolError("uidvalidity is required.")
        flag_actions = {
            "mark_read": (["seen"], None),
            "mark_unread": (None, ["seen"]),
            "flag": (["flagged"], None),
            "unflag": (None, ["flagged"]),
        }
        if action in flag_actions:
            add, remove = flag_actions[action]
            return _call(imap_client.set_flags, acc, folder, uids, add, remove, uidvalidity)
        if action == "trash":
            return _call(imap_client.trash_messages, acc, folder, uids, uidvalidity)
        if action == "move":
            if not destination:
                raise ToolError("destination is required for move.")
            return _call(imap_client.move_messages, acc, folder, uids, destination, False, uidvalidity)
        raise ToolError(f"Unknown action {action!r}.")

    # ---- Settings panel tools (app only) ------------------------------------

    @mcp.tool(title="Panel: settings", annotations=READ_LOCAL, meta=_APP_ONLY)
    def imap_panel_settings_state() -> dict[str, Any]:
        """Settings panel helper: all accounts as stored (never passwords)."""
        items = _accounts_or_error()
        return {
            "accounts": [
                {
                    **a.to_json(),
                    "password_stored": accounts.has_secret(a.id, "imap"),
                    "smtp_password_stored": accounts.has_secret(a.id, "smtp"),
                    "knowledge": _knowledge_status(a.id),
                }
                for a in sorted(items.values(), key=lambda a: a.display_name.lower())
            ],
            "config_file": str(accounts.config_path()),
            "attachments_folder": str(accounts.attachments_root()),
            "config_problems": accounts.load_errors(),
            "keyring_available": accounts.keyring_available(),
            "native_dialogs": native_dialog.available(),
            "send_allow_minutes": send_approval.ALLOW_MINUTES,
            "can_change": os.getenv("MCP_TRANSPORT", "stdio").strip().lower() == "stdio",
        }

    @mcp.tool(title="Panel: save account", annotations=_PANEL_WRITE, meta=_APP_ONLY)
    def imap_panel_save_account(account: dict[str, Any], account_id: str = "", lang: str = "en") -> dict[str, Any]:
        """Settings panel helper: create (no account_id) or update an account.

        Returns {saved: false, problems: [...]} for invalid input. Changes
        that raise permissions or move a stored password to another server
        are confirmed in a native macOS dialog first.
        """
        _local_only()
        lang = _lang(lang)
        existing = _account(account_id) if account_id else None
        candidate, problems = _account_from_panel(account, existing)
        if candidate is None:
            return {"saved": False, "problems": problems}

        reasons = needs_confirmation(existing, candidate)
        if reasons:
            if not native_dialog.available():
                return {"saved": False, "needs_browser": True, "reasons": [_t(lang, r) for r in reasons]}
            message = "\n\n".join(
                [_t(lang, "dialog.confirm.intro", name=candidate.display_name)]
                + [f"• {_t(lang, r)}" for r in reasons]
            )
            try:
                ok = native_dialog.confirm(
                    _t(lang, "dialog.title"), message,
                    _t(lang, "dialog.confirm.ok"), _t(lang, "dialog.cancel"),
                )
            except native_dialog.DialogUnavailable as exc:
                raise ToolError(str(exc)) from exc
            if not ok:
                return {"saved": False, "cancelled": True, "reasons": [_t(lang, r) for r in reasons]}

        _call(accounts.save_account, candidate)
        return {"saved": True, "account_id": candidate.id, "confirmed": bool(reasons)}

    @mcp.tool(title="Panel: set password", annotations=_PANEL_WRITE, meta=_APP_ONLY)
    def imap_panel_set_password(account_id: str, kind: str = "imap", lang: str = "en") -> dict[str, Any]:
        """Settings panel helper: ask for a password in a native dialog and store it in the Keychain.

        The password never passes through this tool's arguments or result.
        """
        _local_only()
        lang = _lang(lang)
        if kind not in ("imap", "smtp"):
            raise ToolError("kind must be 'imap' or 'smtp'.")
        acc = _account(account_id)
        if not native_dialog.available():
            return {"stored": False, "needs_browser": True}
        if not accounts.keyring_available():
            raise ToolError(
                f"No secure keychain is available. Set {accounts.secret_env_name(acc.id, kind)} instead."
            )
        host = acc.imap_host if kind == "imap" else (acc.smtp_host or acc.imap_host)
        user = acc.login if kind == "imap" else acc.smtp_login
        try:
            value = native_dialog.ask_password(
                _t(lang, "dialog.title"),
                _t(lang, f"dialog.password.{kind}", name=acc.display_name, user=user, host=host),
                _t(lang, "dialog.password.ok"), _t(lang, "dialog.cancel"),
            )
        except native_dialog.DialogUnavailable as exc:
            raise ToolError(str(exc)) from exc
        if value is None:
            return {"stored": False, "cancelled": True}
        _call(accounts.set_secret, acc.id, kind, value)
        return {"stored": True}

    @mcp.tool(title="Panel: test connection", annotations=READ_MAILBOX, meta=_APP_ONLY)
    def imap_panel_test_connection(account_id: str) -> dict[str, Any]:
        """Settings panel helper: log in and list folders. Changes nothing."""
        acc = _account(account_id)
        try:
            return imap_client.test_connection(acc)
        except imap_client.ImapError as exc:
            return {"ok": False, "error": str(exc)}

    @mcp.tool(title="Panel: delete account", annotations=_PANEL_DELETE, meta=_APP_ONLY)
    def imap_panel_delete_account(account_id: str, lang: str = "en") -> dict[str, Any]:
        """Settings panel helper: remove an account and its stored passwords after a native confirmation.

        Mail on the server is not touched.
        """
        _local_only()
        lang = _lang(lang)
        acc = _account(account_id)
        if not native_dialog.available():
            return {"deleted": False, "needs_browser": True}
        try:
            ok = native_dialog.confirm(
                _t(lang, "dialog.title"),
                _t(lang, "dialog.delete.message", name=acc.display_name),
                _t(lang, "dialog.delete.ok"), _t(lang, "dialog.cancel"),
            )
        except native_dialog.DialogUnavailable as exc:
            raise ToolError(str(exc)) from exc
        if not ok:
            return {"deleted": False, "cancelled": True}
        _call(accounts.delete_account, acc.id)
        return {"deleted": True}

    @mcp.tool(title="Panel: save attachments", annotations=SAVE_LOCAL, meta=_APP_ONLY)
    def imap_panel_save_attachments(account: str, folder: str, uid: int, uidvalidity: int) -> dict[str, Any]:
        """Mailbox panel helper: save one message's attachments (same rules as imap_save_attachments)."""
        import mcp_server

        return mcp_server.save_attachments(_account(account), folder, [uid], uidvalidity)

    @mcp.tool(title="Panel: choose attachments folder", annotations=_PANEL_WRITE, meta=_APP_ONLY)
    def imap_panel_choose_attachments_folder(lang: str = "en") -> dict[str, Any]:
        """Settings panel helper: pick the attachments folder in a native macOS folder dialog."""
        _local_only()
        lang = _lang(lang)
        if not native_dialog.available():
            return {"changed": False, "needs_browser": True}
        try:
            chosen = native_dialog.choose_folder(_t(lang, "dialog.choose_attachments_folder"))
        except native_dialog.DialogUnavailable as exc:
            raise ToolError(str(exc)) from exc
        if not chosen:
            return {"changed": False, "cancelled": True}
        _call(accounts.save_settings, attachments_root=chosen.rstrip("/") or "/")
        return {"changed": True, "attachments_folder": str(accounts.attachments_root())}

    @mcp.tool(title="Panel: import knowledge base", annotations=_PANEL_WRITE, meta=_APP_ONLY)
    def imap_panel_import_knowledge(account_id: str, lang: str = "en") -> dict[str, Any]:
        """Settings panel helper: pick a Markdown file in a native dialog and import it as the account's knowledge base.

        The file's content never passes through the client.
        """
        _local_only()
        lang = _lang(lang)
        acc = _account(account_id)
        if not native_dialog.available():
            return {"imported": False, "needs_browser": True}
        try:
            chosen = native_dialog.choose_file(_t(lang, "dialog.choose_knowledge_file", name=acc.display_name))
        except native_dialog.DialogUnavailable as exc:
            raise ToolError(str(exc)) from exc
        if not chosen:
            return {"imported": False, "cancelled": True}
        try:
            data = Path(chosen).read_bytes()[: knowledge_base.MAX_FILE_BYTES + 1]
            kb = knowledge_base.import_text(acc.id, data)
        except (OSError, knowledge_base.KnowledgeError) as exc:
            return {"imported": False, "error": str(exc)}
        return {"imported": True, "entries": len(kb.entries), "meta_keys": sorted(kb.meta)}

    @mcp.tool(title="Panel: remove knowledge base", annotations=_PANEL_DELETE, meta=_APP_ONLY)
    def imap_panel_remove_knowledge(account_id: str, lang: str = "en") -> dict[str, Any]:
        """Settings panel helper: remove the account's knowledge base after a native confirmation."""
        _local_only()
        lang = _lang(lang)
        acc = _account(account_id)
        if not native_dialog.available():
            return {"removed": False, "needs_browser": True}
        try:
            ok = native_dialog.confirm(
                _t(lang, "dialog.title"), _t(lang, "dialog.remove_knowledge", name=acc.display_name),
                _t(lang, "dialog.remove_knowledge.ok"), _t(lang, "dialog.cancel"),
            )
        except native_dialog.DialogUnavailable as exc:
            raise ToolError(str(exc)) from exc
        if not ok:
            return {"removed": False, "cancelled": True}
        return {"removed": knowledge_base.remove(acc.id)}

    # ---- Writing from the mailbox panel (app only) --------------------------

    @mcp.tool(title="Panel: prepare a message", annotations=READ_MAILBOX, meta=_APP_ONLY)
    def imap_panel_compose_prepare(
        account: str, action: str, folder: str = "", uid: int = 0, uidvalidity: int = 0
    ) -> dict[str, Any]:
        """Mailbox panel helper: starting values for writing a message.

        action: new | reply | reply_all | forward | edit_draft. For replies
        and forwards the original is quoted below the user's text when the
        message is saved or sent; it is not part of the editable body.
        """
        import mcp_server

        acc = _account(account)
        perms = {"send_mode": acc.permissions.send_mode.value,
                 "send_approval": acc.permissions.send_approval.value}
        if acc.permissions.send_mode is accounts.SendMode.OFF:
            return {"allowed": False, **perms}
        if action == "new":
            return {"allowed": True, **perms, "action": action, "to": [], "cc": [], "bcc": [],
                    "subject": "", "body": "", "quoted_from": None}
        if action not in ("reply", "reply_all", "forward", "edit_draft"):
            raise ToolError(f"Unknown action {action!r}.")
        parsed, flags, current = _call(imap_client.get_message, acc, folder, uid, uidvalidity or None)
        h = parsed.headers
        base = {"allowed": True, **perms, "action": action, "folder": folder, "uid": uid, "uidvalidity": current}
        if action == "edit_draft":
            return {**base, "to": mcp_server._addr_list(h["to"]), "cc": mcp_server._addr_list(h["cc"]),
                    "bcc": mcp_server._addr_list(h["bcc"]), "subject": h["subject"], "body": parsed.text,
                    "is_draft": "\\Draft" in flags, "quoted_from": None}
        sender = h["from"][0]["email"] if h["from"] else ""
        if action == "forward":
            return {**base, "to": [], "cc": [], "bcc": [],
                    "subject": smtp_client.reply_subject(h["subject"], "Fwd:"), "body": "",
                    "quoted_from": sender,
                    "attachments_not_included": [a.filename for a in parsed.attachments]}
        to, cc = mcp_server.reply_recipients(acc, h, action == "reply_all")
        warning = None
        senders = {a["email"].rsplit("@", 1)[-1].lower() for a in h["from"]}
        foreign = [a["email"] for a in h["reply_to"] if a["email"].rsplit("@", 1)[-1].lower() not in senders]
        if foreign:
            warning = {"reply_to": foreign, "sender": sender}
        return {**base, "to": to, "cc": cc, "bcc": [],
                "subject": smtp_client.reply_subject(h["subject"], "Re:"), "body": "",
                "quoted_from": sender, "reply_to_warning": warning}

    @mcp.tool(title="Panel: save or send a message", annotations=SEND, meta=_APP_ONLY)
    async def imap_panel_compose_deliver(
        account: str,
        action: str,
        body: str,
        to: list[str],
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        subject: str = "",
        folder: str = "",
        uid: int = 0,
        uidvalidity: int = 0,
        deliver: str = "draft",
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        """Mailbox panel helper: save the user's message as a draft, or send it.

        Sending follows the account's approval setting exactly like the
        ordinary tools. For edit_draft the old draft is moved to Trash once
        the new version is saved or sent (only that draft, so it can be
        recovered).
        """
        import mcp_server

        acc = _account(account)
        mcp_server._require_compose(acc, need_send=(deliver == "send"))
        if deliver not in ("draft", "send"):
            raise ToolError("deliver must be 'draft' or 'send'.")
        if action in ("reply", "reply_all", "forward", "edit_draft"):
            mcp_server._require_uidvalidity(uidvalidity)
        state: dict[str, Any] = {}

        def build():
            in_reply_to, references, quoted, extra, original_h = "", [], None, "", None
            if action in ("reply", "reply_all", "forward", "edit_draft"):
                parsed, _flags, current = _call(imap_client.get_message, acc, folder, uid, uidvalidity)
                state["uidvalidity"] = current
                original_h = parsed.headers
                if action in ("reply", "reply_all"):
                    # Same Reply-To rule as imap_reply when a recipient is the
                    # foreign Reply-To address: drafts warn, sending is refused.
                    foreign = {a["email"].lower() for a in original_h["reply_to"]}
                    chosen = {addr.lower() for _n, addr in getaddresses(list(to) + list(cc or []) + list(bcc or []))}
                    if foreign & chosen:
                        state["reply_to_warning"] = mcp_server._reply_to_check(original_h, deliver)
                    in_reply_to, references = mcp_server.reply_threading(original_h)
                    extra = "\n\n" + mcp_server.reply_quote(parsed) + "\n"
                    quoted = mcp_server._quotation(original_h)
                elif action == "forward":
                    extra = "\n\n" + mcp_server.forward_block(parsed)
                    quoted = mcp_server._quotation(original_h, excerpt=parsed.text)
                else:  # edit_draft keeps the draft's own threading headers
                    in_reply_to = original_h["in_reply_to"]
                    references = original_h["references"]
            elif action != "new":
                raise ToolError(f"Unknown action {action!r}.")
            msg = _call(smtp_client_build, acc, to=to, cc=cc, bcc=bcc, subject=subject,
                        body=body.rstrip() + extra, in_reply_to=in_reply_to, references=references)
            return msg, quoted

        msg, quoted = await mcp_server._in_thread(build)
        result = await mcp_server._send_or_draft(acc, msg, deliver, ctx, authored=body, quoted=quoted)
        if state.get("reply_to_warning"):
            result["reply_to_warning"] = state["reply_to_warning"]
        # Follow-up changes use the uidvalidity the server reported when the
        # original was read in this call, never the caller's value.
        current = state.get("uidvalidity")
        if action == "edit_draft" and current and result.get("status") in ("draft_saved", "sent"):
            try:
                result["old_draft_moved_to_trash"] = await mcp_server._in_thread(
                    imap_client.retire_own_draft, acc, folder, uid, current)
            except imap_client.ImapError:
                result["old_draft_moved_to_trash"] = False
        if action in ("reply", "reply_all") and current and result.get("status") == "sent" and acc.permissions.organise:
            try:
                await mcp_server._in_thread(imap_client.set_flags, acc, folder, [uid], ["answered"], None, current)
            except imap_client.ImapError:
                pass
        return result

    @mcp.tool(title="Panel: open browser settings", annotations=LOCAL_ACTION, meta=_APP_ONLY)
    def imap_panel_open_browser_settings() -> dict[str, Any]:
        """Settings panel helper: open the browser-based settings page."""
        _local_only()
        import admin_server

        try:
            admin_server.launch_in_background()
        except OSError as exc:
            raise ToolError(f"Could not start the settings page: {exc}") from exc
        return {"opened": True}
