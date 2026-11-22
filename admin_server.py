# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""Local admin UI for configuring mail accounts.

A small server-rendered web application, bound to 127.0.0.1, where the
owner adds, edits, tests and deletes the accounts the MCP server may use.
Besides the accounts it sets the attachments folder and imports each
account's knowledge base, so that owners without macOS (where the panel
cannot open native dialogs) can do everything here. Every page works
without JavaScript. A small same-origin script,
`admin/static/app.js`, adds what cannot be done without it: a keep-alive
ping while the owner types, a warning before the idle timeout (WCAG 2.2.1),
focus on status messages, and a confirmation before leaving a form with
unsaved changes.

The server has access to mail passwords, so it is locked down even though
it only listens on the loopback interface:

    * a single-use start token in the start-up URL is exchanged for a
      session cookie (HttpOnly, SameSite=Strict) and then forgotten;
    * the Host header must be 127.0.0.1:<port> or localhost:<port>, which
      stops DNS-rebinding attacks from a web page in the same browser;
    * every POST must come from the same origin and carry the session's
      CSRF token;
    * a strict Content-Security-Policy and no-store caching on every
      response;
    * the server stops itself after a period without requests, and on
      request through the "Close settings" button. `/keepalive` (POST,
      CSRF) counts as a request; `/status` (GET) reports the time left
      without counting as one, so polling it cannot keep the server alive.

Passwords are written to the keychain through `accounts.set_secret` and are
never rendered back, logged, put in a URL or in a flash message.

Environment variables:
    IMAP_ADMIN_PORT          fixed port (a random free port when unset)
    IMAP_ADMIN_IDLE_MINUTES  minutes without requests before the server
                             stops (15 when unset, 0 turns it off)

Entry points:
    python admin_server.py [--no-browser]
    launch_in_background() -> None
    create_app(port, token, idle_minutes, shutdown) -> Starlette
"""

from __future__ import annotations

import argparse
import hmac
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

import jinja2
from markupsafe import Markup, escape
from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.concurrency import run_in_threadpool
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

import accounts
import send_approval
import i18n
import imap_client
import knowledge_base

BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = BASE_DIR / "admin" / "templates"
STATIC_DIR = BASE_DIR / "admin" / "static"

DEFAULT_IDLE_MINUTES = 15
# Room for the multipart framing and the CSRF field around a knowledge file
# of the largest allowed size; a larger body is refused before it is parsed.
UPLOAD_OVERHEAD_BYTES = 64 * 1024
LANG_COOKIE = "imap_admin_lang"
START_COMMAND = "python admin_server.py"

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    ),
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
}

# Form fields in page order, so the error summary lists problems in the
# order the user meets them. Radio groups link to their first option.
FIELD_ANCHORS = {
    "display_name": "f-display_name",
    "email": "f-email",
    "imap_host": "f-imap_host",
    "imap_port": "f-imap_port",
    "imap_security": "f-imap_security-ssl",
    "password": "f-password",
    "smtp_host": "f-smtp_host",
    "smtp_port": "f-smtp_port",
    "smtp_security": "f-smtp_security-ssl",
    "smtp_password": "f-smtp_password",
    "save_sent": "f-save_sent-auto",
    "read_marking": "f-read_marking-never",
    "send_mode": "f-send_mode-off",
    "send_approval": "f-send_approval-ask",
    "save_attachments": "f-save_attachments",
}

# Paths that must not count as activity for the idle timeout: the warning
# script polls /status, and a poll is not the owner doing something.
PASSIVE_PATHS = {"/status"}

TEXT_FIELDS = (
    "display_name", "email", "imap_host", "username", "smtp_host",
    "smtp_username", "sent_folder", "drafts_folder", "trash_folder",
)


# -----------------------------------------------------------------------------
# State
# -----------------------------------------------------------------------------

@dataclass
class Session:
    csrf: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    flashes: list[tuple[str, str, dict[str, str]]] = field(default_factory=list)
    test_results: dict[str, dict[str, Any]] = field(default_factory=dict)


class AdminState:
    """Everything the running admin server keeps in memory."""

    def __init__(self, port: int, token: str, idle_minutes: float, shutdown: Callable[[], None]):
        self.port = port
        self.idle_minutes = idle_minutes
        self.shutdown = shutdown
        self.sessions: dict[str, Session] = {}
        self.session_cookie = f"imap_admin_session_{port}"  # cookies ignore ports
        self.allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        self.last_activity = time.monotonic()
        self._token: str | None = token
        self._lock = threading.Lock()

    def touch(self) -> None:
        self.last_activity = time.monotonic()

    def seconds_left(self) -> float | None:
        """Seconds until the idle timeout stops the server; None when it is off."""
        if self.idle_minutes <= 0:
            return None
        return max(self.idle_minutes * 60 - (time.monotonic() - self.last_activity), 0.0)

    def consume_token(self, candidate: str) -> bool:
        """Accept the start token exactly once."""
        with self._lock:
            if self._token is None or not hmac.compare_digest(candidate.encode(), self._token.encode()):
                return False
            self._token = None
            return True

    def new_session(self) -> str:
        session_id = secrets.token_urlsafe(32)
        self.sessions[session_id] = Session()
        return session_id


class RejectedRequest(Exception):
    """A POST failed the origin or CSRF check."""


# -----------------------------------------------------------------------------
# Rendering
# -----------------------------------------------------------------------------

_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=True,
    undefined=jinja2.StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
)


def _translator(lang: str) -> Callable[..., Markup]:
    def t(key: str, **values: Any) -> Markup:
        template = Markup(escape(i18n.raw(lang, key)))
        if not values:
            return template
        try:
            # Markup.format escapes every value that is not already Markup.
            return template.format(**values)
        except (KeyError, IndexError, ValueError):
            return template
    return t


def _code(value: str) -> Markup:
    return Markup("<code>{}</code>").format(value)


def _counter(lang: str) -> Callable[[float], str]:
    """Write small whole numbers as words (2 to 12), as Swedish style asks.

    One is left to the caller, since its form depends on the noun (ett fel,
    en minut); such strings have their own "_one" key.
    """
    def count(value: float) -> str:
        if float(value).is_integer() and 2 <= int(value) <= 12:
            return i18n.raw(lang, f"number.{int(value)}")
        return "%g" % value
    return count


def _render(
    request: Request,
    template: str,
    *,
    title: str | Markup,
    status: int = 200,
    error: bool = False,
    nav: str = "",
    minimal: bool = False,
    background: BackgroundTask | None = None,
    **context: Any,
) -> HTMLResponse:
    lang = request.state.lang
    t = _translator(lang)
    state: AdminState = request.app.state.admin
    session: Session | None = getattr(request.state, "session", None)
    flashes = []
    if session is not None and not minimal:
        flashes = [(kind, t(key, **params)) for kind, key, params in session.flashes]
        session.flashes.clear()
    # Keep Markup all the way into the template: a str() here would turn an
    # already escaped name such as O&#39;Brien into text that autoescape
    # escapes a second time.
    page = (t("title.error_prefix") if error else Markup("")) + title
    html = _env.get_template(template).render(
        lang=lang,
        t=t,
        code=_code,
        count=_counter(lang),
        languages=i18n.available_languages(),
        path=request.url.path,
        nav=nav,
        minimal=minimal,
        csrf=session.csrf if session else "",
        flashes=flashes,
        page_title=t("title.pattern", page=page, site=t("site.name")),
        idle_minutes=state.idle_minutes,
        send_allow_minutes=send_approval.ALLOW_MINUTES,
        idle_seconds=int(state.idle_minutes * 60),
        # app.js writes the clock time of the shutdown into this element.
        idle_time_slot=Markup('<span data-idle-time></span>'),
        **context,
    )
    return HTMLResponse(html, status_code=status, background=background)


def _forbidden(request: Request) -> HTMLResponse:
    """Bilingual (all languages) page for requests without a session."""
    lang = request.state.lang
    order = [lang] + [code for code, _ in i18n.available_languages() if code != lang]
    sections = [(code, _translator(code)) for code in order]
    t = _translator(lang)
    html = _env.get_template("forbidden.html").render(
        lang=lang, sections=sections, code=_code, command=START_COMMAND,
        page_title=t("title.pattern", page=t("forbidden.title"), site=t("site.name")),
    )
    return HTMLResponse(html, status_code=403)


def _rejected(request: Request) -> HTMLResponse:
    t = _translator(request.state.lang)
    return _render(request, "rejected.html", title=t("rejected.title"), status=403, error=True)


def _flash(request: Request, key: str, **params: str) -> None:
    request.state.session.flashes.append(("success", key, params))


def _redirect(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=303)


# -----------------------------------------------------------------------------
# Request guard
# -----------------------------------------------------------------------------

def _same_origin(request: Request) -> bool:
    expected = f"http://{request.headers.get('host', '')}"
    origin = request.headers.get("origin")
    # Browsers send "Origin: null" on form posts from a page served with
    # Referrer-Policy: no-referrer, so Sec-Fetch-Site decides in that case.
    if origin and origin != "null":
        return origin == expected
    fetch_site = request.headers.get("sec-fetch-site")
    if fetch_site:
        return fetch_site == "same-origin"
    referer = request.headers.get("referer")
    if referer:
        return referer == expected or referer.startswith(expected + "/")
    return False


class GuardMiddleware(BaseHTTPMiddleware):
    """Host allowlist, session check, origin check, language and headers."""

    async def dispatch(self, request: Request, call_next) -> Response:
        state: AdminState = request.app.state.admin
        if request.headers.get("host", "") not in state.allowed_hosts:
            return self._secure(PlainTextResponse("Bad request: unexpected Host header.\n", status_code=400))
        if request.url.path not in PASSIVE_PATHS:
            state.touch()

        query_lang = request.query_params.get("lang")
        request.state.lang = i18n.negotiate(
            query_lang, request.cookies.get(LANG_COOKIE), request.headers.get("accept-language"),
        )
        request.state.session = None

        path = request.url.path
        if path.startswith("/static/") or path == "/auth":
            response = await call_next(request)
        else:
            session = state.sessions.get(request.cookies.get(state.session_cookie, ""))
            if session is None:
                response = _forbidden(request)
            else:
                request.state.session = session
                if request.method == "POST" and not _same_origin(request):
                    response = _rejected(request)
                else:
                    response = await call_next(request)

        if i18n.is_supported(query_lang):
            response.set_cookie(LANG_COOKIE, query_lang, max_age=365 * 24 * 3600,
                                path="/", httponly=True, samesite="strict")
        return self._secure(response)

    @staticmethod
    def _secure(response: Response) -> Response:
        for name, value in SECURITY_HEADERS.items():
            response.headers[name] = value
        return response


async def _checked_form(request: Request, **limits: Any):
    form = await request.form(**limits)
    sent = form.get("csrf_token", "")
    session: Session = request.state.session
    if not isinstance(sent, str) or not hmac.compare_digest(sent.encode(), session.csrf.encode()):
        raise RejectedRequest()
    return form


async def _on_rejected(request: Request, exc: Exception) -> Response:
    return GuardMiddleware._secure(_rejected(request))


async def _on_config_error(request: Request, exc: Exception) -> Response:
    t = _translator(request.state.lang)
    response = _render(request, "config_error.html", title=t("configerror.title"),
                       status=500, error=True, detail=str(exc), config_path=str(accounts.config_path()))
    return GuardMiddleware._secure(response)


# -----------------------------------------------------------------------------
# Account form
# -----------------------------------------------------------------------------

def _values_from_account(account: accounts.Account) -> dict[str, Any]:
    return {
        "display_name": account.display_name,
        "email": account.email,
        "imap_host": account.imap_host,
        "imap_port": str(account.imap_port),
        "imap_security": account.imap_security,
        "username": account.username,
        "smtp_host": account.smtp_host,
        "smtp_port": str(account.smtp_port),
        "smtp_security": account.smtp_security,
        "smtp_username": account.smtp_username,
        "sent_folder": account.sent_folder,
        "drafts_folder": account.drafts_folder,
        "trash_folder": account.trash_folder,
        "save_sent": account.save_sent.value,
        "read_marking": account.read_marking.value,
        "organise": account.permissions.organise,
        "save_attachments": account.permissions.save_attachments,
        "send_mode": account.permissions.send_mode.value,
        "send_approval": account.permissions.send_approval.value,
    }


def _blank_values() -> dict[str, Any]:
    return _values_from_account(accounts.Account(id="new", display_name="", email="", imap_host=""))


def _port(text: str, default: int) -> int:
    if not text:
        return default
    # Out-of-range and non-numeric input both become 0 so that
    # validate_account reports them with the same "enter a port" message.
    return int(text) if text.isdigit() else 0


def _account_from_form(form, account_id: str) -> tuple[accounts.Account, dict[str, Any], list[str]]:
    values: dict[str, Any] = {name: str(form.get(name, "")).strip() for name in TEXT_FIELDS}
    for name, default in (("imap_port", ""), ("smtp_port", "")):
        values[name] = str(form.get(name, default)).strip().replace(" ", "")
    for name in ("imap_security", "smtp_security", "save_sent", "read_marking", "send_mode", "send_approval"):
        values[name] = str(form.get(name, ""))
    # A real bool, never the posted string: accounts.Account.from_json
    # rejects anything else when the file is read back.
    values["organise"] = form.get("organise") == "yes"
    values["save_attachments"] = form.get("save_attachments") == "yes"

    problems: list[str] = []
    try:
        save_sent = accounts.SaveSent(values["save_sent"])
    except ValueError:
        problems.append("save_sent")
        save_sent = accounts.SaveSent.AUTO
    try:
        read_marking = accounts.ReadMarking(values["read_marking"])
    except ValueError:
        problems.append("read_marking")
        read_marking = accounts.ReadMarking.NEVER
    try:
        send_mode = accounts.SendMode(values["send_mode"])
    except ValueError:
        problems.append("send_mode")
        send_mode = accounts.SendMode.OFF
    try:
        send_approval = accounts.SendApproval(values["send_approval"] or "ask")
    except ValueError:
        problems.append("send_approval")
        send_approval = accounts.SendApproval.ASK

    account = accounts.Account(
        id=account_id,
        display_name=values["display_name"],
        email=values["email"],
        imap_host=values["imap_host"],
        imap_port=_port(values["imap_port"], 0),
        imap_security=values["imap_security"],
        username=values["username"],
        smtp_host=values["smtp_host"],
        smtp_port=_port(values["smtp_port"], 465),
        smtp_security=values["smtp_security"] or "ssl",
        smtp_username=values["smtp_username"],
        sent_folder=values["sent_folder"],
        drafts_folder=values["drafts_folder"],
        trash_folder=values["trash_folder"],
        save_sent=save_sent,
        read_marking=read_marking,
        permissions=accounts.Permissions(organise=values["organise"],
                                         save_attachments=values["save_attachments"],
                                         send_mode=send_mode, send_approval=send_approval),
    )
    problems += accounts.validate_account(account)
    return account, values, problems


def _error_messages(lang: str, problems: dict[str, str], account_id: str) -> dict[str, Markup]:
    """Map field name -> message; `problems` maps field name -> message key."""
    t = _translator(lang)
    env_imap = _code(accounts.secret_env_name(account_id, "imap"))
    env_smtp = _code(accounts.secret_env_name(account_id, "smtp"))
    messages = {}
    for field_name in FIELD_ANCHORS:
        if field_name in problems:
            var = env_smtp if field_name == "smtp_password" else env_imap
            messages[field_name] = t(problems[field_name], var=var)
    return messages


def _form_page(
    request: Request,
    *,
    account: accounts.Account | None,
    values: dict[str, Any],
    problems: dict[str, str] | None = None,
    account_id: str = "",
    form_error: str = "",
    status: int = 200,
    password_dropped: bool = False,
) -> HTMLResponse:
    lang = request.state.lang
    t = _translator(lang)
    problems = problems or {}
    errors = _error_messages(lang, problems, account_id or "<ID>")
    if account is None:
        title = t("form.title_new")
    else:
        title = t("form.title_edit", name=account.display_name)
    return _render(
        request, "account_form.html",
        title=title, status=status, error=bool(errors or form_error),
        nav="add" if account is None else "",
        account=account,
        values=values,
        errors=errors,
        error_list=[(FIELD_ANCHORS[name], message) for name, message in errors.items()],
        form_error=form_error,
        password_dropped=password_dropped,
        keyring=accounts.keyring_available(),
        has_imap_secret=bool(account and accounts.has_secret(account.id, "imap")),
        has_smtp_secret=bool(account and accounts.has_secret(account.id, "smtp")),
    )


async def _save_from_form(request: Request, existing: accounts.Account | None) -> Response:
    form = await _checked_form(request)
    if existing is None:
        name = str(form.get("display_name", "")).strip()
        account_id = accounts.new_account_id(name, set(accounts.load_accounts()))
    else:
        account_id = existing.id
    account, values, codes = _account_from_form(form, account_id)
    problems = {code: f"error.{code}" for code in codes}

    password = str(form.get("password", ""))
    smtp_password = str(form.get("smtp_password", ""))
    keyring = accounts.keyring_available()
    if password and not keyring:
        problems["password"] = "error.password_keychain"
    if smtp_password and not keyring:
        problems["smtp_password"] = "error.smtp_password"
    if existing is None and keyring and not password and not accounts.has_secret(account_id, "imap"):
        problems["password"] = "error.password"

    def again(**extra: Any) -> HTMLResponse:
        return _form_page(request, account=existing, values=values, problems=problems,
                          account_id=account_id, status=400,
                          password_dropped=bool(password or smtp_password), **extra)

    if problems:
        return again()
    # Save the account before its secrets: if saving fails (an id that
    # clashes in case, an unwritable file) no password is left behind in
    # the keychain for an account that does not exist.
    try:
        accounts.save_account(account)
    except (accounts.ConfigError, OSError) as exc:
        return again(form_error=str(exc))
    for kind, secret, field_name in (("imap", password, "password"),
                                     ("smtp", smtp_password, "smtp_password")):
        if not secret:
            continue
        try:
            accounts.set_secret(account_id, kind, secret)
        except accounts.SecretError:
            problems[field_name] = f"error.{field_name}_not_stored"
    if problems:
        # The account now exists, so the form must edit it from here on;
        # posting to /accounts/new again would create a second account.
        return _form_page(request, account=account, values=values, problems=problems,
                          account_id=account_id, status=500, password_dropped=True)
    _flash(request, "flash.saved", name=account.display_name)
    return _redirect("/")


def _find_account(request: Request) -> accounts.Account | None:
    return accounts.load_accounts().get(request.path_params["account_id"])


def _not_found(request: Request) -> HTMLResponse:
    t = _translator(request.state.lang)
    return _render(request, "not_found.html", title=t("notfound.title"), status=404,
                   account_id=request.path_params.get("account_id", ""))


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------

async def auth(request: Request) -> Response:
    state: AdminState = request.app.state.admin
    if not state.consume_token(request.query_params.get("token", "")):
        return _forbidden(request)
    response = _redirect("/")
    response.set_cookie(state.session_cookie, state.new_session(),
                        httponly=True, samesite="strict", path="/")
    return response


async def accounts_page(request: Request) -> Response:
    t = _translator(request.state.lang)
    lang = request.state.lang
    rows = [
        (account, accounts.has_secret(account.id, "imap"), _knowledge_summary(lang, account.id))
        for account in sorted(accounts.load_accounts().values(), key=lambda a: a.display_name.lower())
    ]
    return _render(
        request, "accounts.html", title=t("accounts.title"), nav="accounts",
        rows=rows, keyring=accounts.keyring_available(), config_path=str(accounts.config_path()),
        attachments_folder=str(accounts.attachments_root()),
    )


async def new_account(request: Request) -> Response:
    if request.method == "POST":
        return await _save_from_form(request, None)
    return _form_page(request, account=None, values=_blank_values())


async def edit_account(request: Request) -> Response:
    account = _find_account(request)
    if account is None:
        return _not_found(request)
    if request.method == "POST":
        return await _save_from_form(request, account)
    return _form_page(request, account=account, values=_values_from_account(account),
                      account_id=account.id)


def _run_test(account: accounts.Account) -> dict[str, Any]:
    try:
        result = imap_client.test_connection(account)
    except (imap_client.ImapError, accounts.SecretError) as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 - shown to the owner as text, never raised
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    # Keep only the summary fields; nothing from a mailbox is stored.
    special = result.get("special_folders") or {}
    return {
        "ok": True,
        "folder_count": int(result.get("folder_count", 0)),
        "gmail": bool(result.get("gmail")),
        "sent": special.get("sent"),
        "drafts": special.get("drafts"),
        "trash": special.get("trash"),
    }


async def test_account(request: Request) -> Response:
    account = _find_account(request)
    if account is None:
        return _not_found(request)
    session: Session = request.state.session
    if request.method == "POST":
        await _checked_form(request)
        session.test_results[account.id] = await run_in_threadpool(_run_test, account)
        return _redirect(f"/accounts/{account.id}/test")
    t = _translator(request.state.lang)
    result = session.test_results.pop(account.id, None)
    return _render(
        request, "test.html", title=t("test.title", name=account.display_name),
        error=bool(result and not result["ok"]), account=account, result=result,
    )


async def delete_account(request: Request) -> Response:
    account = _find_account(request)
    if account is None:
        return _not_found(request)
    if request.method == "POST":
        await _checked_form(request)
        accounts.delete_account(account.id)
        request.state.session.test_results.pop(account.id, None)
        _flash(request, "flash.deleted", name=account.display_name)
        return _redirect("/")
    t = _translator(request.state.lang)
    return _render(request, "delete.html", title=t("delete.title", name=account.display_name),
                   account=account)


# -----------------------------------------------------------------------------
# Attachments folder
# -----------------------------------------------------------------------------

def _default_attachments_root() -> str:
    """The folder used when the setting is empty."""
    return str(accounts.default_attachments_root())


def _check_attachments_root(text: str) -> tuple[str, str, str]:
    """Validate a typed folder; return (value to store, error key or "", path for the message).

    The folder itself need not exist, since attachment_store creates it on
    the first save, but its parent must: a typo in the middle of a path
    should be caught here rather than silently create a new tree.
    """
    value = text.strip()
    if len(value) > 1:
        value = value.rstrip("/")
    if not value:
        return "", "", ""
    if "\0" in value or not (value.startswith("/") or value.startswith("~")):
        return value, "error.attachments_root_relative", ""
    expanded = Path(value).expanduser()
    if not expanded.is_absolute():  # "~unknownuser" stays unexpanded
        return value, "error.attachments_root_relative", ""
    if expanded.exists() and not expanded.is_dir():
        return value, "error.attachments_root_not_folder", ""
    if not expanded.parent.is_dir():
        return value, "error.attachments_root_parent", str(expanded.parent)
    return value, "", ""


def _attachments_page(request: Request, *, value: str, error: Markup | None = None,
                      status: int = 200) -> HTMLResponse:
    t = _translator(request.state.lang)
    return _render(
        request, "attachments.html", title=t("attachments.title"), status=status,
        error=error is not None, nav="attachments",
        current=str(accounts.attachments_root()), default=_default_attachments_root(),
        value=value, field_error=error,
    )


async def attachments_folder(request: Request) -> Response:
    if request.method == "POST":
        form = await _checked_form(request)
        value, key, path = _check_attachments_root(str(form.get("attachments_root", "")))
        if key:
            t = _translator(request.state.lang)
            return _attachments_page(request, value=value, error=t(key, path=_code(path)), status=400)
        accounts.save_settings(attachments_root=value)
        _flash(request, "flash.attachments_saved", path=str(accounts.attachments_root()))
        return _redirect("/")
    stored = str(accounts.get_settings().get("attachments_root", "") or "")
    return _attachments_page(request, value=stored)


# -----------------------------------------------------------------------------
# Knowledge base
# -----------------------------------------------------------------------------

# knowledge_base raises KnowledgeError with English text only. These message
# starts identify the cases the owner can fix, so they can be shown in the
# page language; anything else is shown as the English original.
_KNOWLEDGE_ERRORS = (
    ("The file is larger than", "error.knowledge_too_large"),
    ("The file is not UTF-8", "error.knowledge_encoding"),
    ("No questions were found", "error.knowledge_no_questions"),
)


def _knowledge_error_key(message: str) -> str | None:
    for start, key in _KNOWLEDGE_ERRORS:
        if message.startswith(start):
            return key
    return None


def _local_time(iso: str | None) -> str:
    if not iso:
        return ""
    try:
        return datetime.fromisoformat(iso).astimezone().strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return iso


def _knowledge_state(account_id: str) -> tuple[knowledge_base.KnowledgeBase | None, str]:
    """(knowledge base or None, English error text when it cannot be read)."""
    try:
        return knowledge_base.load(account_id), ""
    except knowledge_base.KnowledgeError as exc:
        return None, str(exc)


def _knowledge_summary(lang: str, account_id: str) -> Markup:
    t = _translator(lang)
    kb, problem = _knowledge_state(account_id)
    if problem:
        return t("knowledge.unreadable")
    if kb is None:
        return t("knowledge.none")
    date = _local_time(kb.updated)
    if len(kb.entries) == 1:
        return t("knowledge.summary_one", date=date)
    count = _counter(lang)(len(kb.entries))
    # The count opens the sentence, and words such as "två" need a capital there.
    return t("knowledge.summary", count=count[:1].upper() + count[1:], date=date)


def _knowledge_page(request: Request, account: accounts.Account, *, error: Markup | None = None,
                    error_en: str = "", status: int = 200) -> HTMLResponse:
    t = _translator(request.state.lang)
    kb, problem = _knowledge_state(account.id)
    return _render(
        request, "knowledge.html", title=t("knowledge.title", name=account.display_name),
        status=status, error=error is not None, account=account, kb=kb, kb_problem=problem,
        summary=_knowledge_summary(request.state.lang, account.id),
        field_error=error, field_error_en=error_en,
        max_bytes=knowledge_base.MAX_FILE_BYTES,
    )


async def knowledge_page(request: Request) -> Response:
    account = _find_account(request)
    if account is None:
        return _not_found(request)
    if request.method == "GET":
        return _knowledge_page(request, account)
    t = _translator(request.state.lang)

    def failed(key: str, english: str = "") -> HTMLResponse:
        return _knowledge_page(request, account, error=t(key), error_en=english, status=400)

    # Refuse an oversized body before parsing it, so a huge file is never
    # spooled to disk. Browsers always send Content-Length for form posts.
    try:
        length = int(request.headers.get("content-length", "0"))
    except ValueError:
        length = 0
    if length > knowledge_base.MAX_FILE_BYTES + UPLOAD_OVERHEAD_BYTES:
        return failed("error.knowledge_too_large")
    form = await _checked_form(request, max_files=1, max_fields=4)
    upload = form.get("knowledge_file")
    filename = getattr(upload, "filename", "") or ""
    if upload is None or isinstance(upload, str) or not filename:
        return failed("error.knowledge_no_file")
    # One byte more than allowed is enough for import_text to say "too large".
    data = await upload.read(knowledge_base.MAX_FILE_BYTES + 1)
    await upload.close()
    try:
        kb = knowledge_base.import_text(account.id, data)
    except knowledge_base.KnowledgeError as exc:
        key = _knowledge_error_key(str(exc))
        return failed(key) if key else failed("error.knowledge_other", str(exc))
    except OSError as exc:
        return failed("error.knowledge_other", str(exc))
    if len(kb.entries) == 1:
        _flash(request, "flash.knowledge_imported_one", name=account.display_name)
    else:
        _flash(request, "flash.knowledge_imported", name=account.display_name,
               count=_counter(request.state.lang)(len(kb.entries)))
    return _redirect(f"/accounts/{account.id}/knowledge")


async def knowledge_delete(request: Request) -> Response:
    account = _find_account(request)
    if account is None:
        return _not_found(request)
    if request.method == "POST":
        await _checked_form(request)
        knowledge_base.remove(account.id)
        _flash(request, "flash.knowledge_removed", name=account.display_name)
        return _redirect(f"/accounts/{account.id}/knowledge")
    if not accounts.knowledge_path(account.id).exists():
        return _redirect(f"/accounts/{account.id}/knowledge")
    t = _translator(request.state.lang)
    return _render(request, "knowledge_delete.html",
                   title=t("knowledge.remove_title", name=account.display_name), account=account)


def _idle_json(state: AdminState) -> JSONResponse:
    left = state.seconds_left()
    return JSONResponse({
        "seconds_left": None if left is None else round(left),
        "idle_seconds": int(state.idle_minutes * 60),
    })


async def keepalive(request: Request) -> Response:
    """Count as activity; app.js posts here while the owner types or clicks.

    The guard middleware has already touched the idle clock and checked the
    Host header, the session and the origin; the CSRF check stops another
    page from keeping a forgotten server alive.
    """
    await _checked_form(request)
    return _idle_json(request.app.state.admin)


async def status(request: Request) -> Response:
    """Report the time left without counting as activity (see PASSIVE_PATHS)."""
    return _idle_json(request.app.state.admin)


async def close_settings(request: Request) -> Response:
    await _checked_form(request)
    state: AdminState = request.app.state.admin
    t = _translator(request.state.lang)
    response = _render(request, "closed.html", title=t("closed.title"), minimal=True,
                       command=START_COMMAND, background=BackgroundTask(state.shutdown))
    state.sessions.clear()
    return response


# -----------------------------------------------------------------------------
# Application and process
# -----------------------------------------------------------------------------

def create_app(port: int, token: str, idle_minutes: float = DEFAULT_IDLE_MINUTES,
               shutdown: Callable[[], None] = lambda: None) -> Starlette:
    methods = ["GET", "POST"]
    app = Starlette(
        routes=[
            Route("/auth", auth, methods=["GET"]),
            Route("/", accounts_page, methods=["GET"]),
            Route("/accounts/new", new_account, methods=methods),
            Route("/accounts/{account_id}/edit", edit_account, methods=methods),
            Route("/accounts/{account_id}/test", test_account, methods=methods),
            Route("/accounts/{account_id}/delete", delete_account, methods=methods),
            Route("/accounts/{account_id}/knowledge", knowledge_page, methods=methods),
            Route("/accounts/{account_id}/knowledge/delete", knowledge_delete, methods=methods),
            Route("/attachments", attachments_folder, methods=methods),
            Route("/close", close_settings, methods=["POST"]),
            Route("/keepalive", keepalive, methods=["POST"]),
            Route("/status", status, methods=["GET"]),
            Mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static"),
        ],
        middleware=[Middleware(GuardMiddleware)],
        exception_handlers={RejectedRequest: _on_rejected, accounts.ConfigError: _on_config_error},
    )
    app.state.admin = AdminState(port, token, idle_minutes, shutdown)
    return app


def _idle_minutes() -> float:
    raw = os.getenv("IMAP_ADMIN_IDLE_MINUTES", "").strip()
    if not raw:
        return DEFAULT_IDLE_MINUTES
    try:
        value = float(raw)
    except ValueError:
        print(f"IMAP_ADMIN_IDLE_MINUTES={raw!r} is not a number; using {DEFAULT_IDLE_MINUTES}.",
              file=sys.stderr)
        return DEFAULT_IDLE_MINUTES
    return max(value, 0.0)


def _bind() -> socket.socket:
    raw = os.getenv("IMAP_ADMIN_PORT", "").strip()
    port = int(raw) if raw else 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    # Listening before the browser opens means its first request waits in
    # the backlog instead of being refused while uvicorn starts.
    sock.listen(64)
    return sock


def _watch_idle(state: AdminState) -> None:
    limit = state.idle_minutes * 60
    while True:
        time.sleep(min(15.0, max(limit / 4, 1.0)))
        if time.monotonic() - state.last_activity > limit:
            state.shutdown()
            return


def main(argv: list[str] | None = None) -> int:
    import uvicorn

    parser = argparse.ArgumentParser(description="Local settings for the IMAP MCP Connector.")
    parser.add_argument("--no-browser", action="store_true", help="print the URL but do not open a browser")
    args = parser.parse_args(argv)

    sock = _bind()
    port = sock.getsockname()[1]
    token = secrets.token_urlsafe(32)
    holder: dict[str, uvicorn.Server] = {}

    def shutdown() -> None:
        holder["server"].should_exit = True

    app = create_app(port, token, _idle_minutes(), shutdown)
    # access_log stays off: the access log would record the start token.
    config = uvicorn.Config(app, log_level="warning", access_log=False, lifespan="off")
    holder["server"] = uvicorn.Server(config)

    state: AdminState = app.state.admin
    if state.idle_minutes > 0:
        threading.Thread(target=_watch_idle, args=(state,), daemon=True).start()

    url = f"http://127.0.0.1:{port}/auth?token={token}"
    print(f"IMAP MCP Connector settings: {url}", file=sys.stderr, flush=True)
    if not args.no_browser:
        webbrowser.open(url)
    holder["server"].run(sockets=[sock])
    return 0


def launch_in_background() -> None:
    """Start the admin UI as a detached process that opens the browser itself.

    Called from an MCP tool. Output goes to DEVNULL so the tokenised URL never
    reaches the caller; a second admin simply gets another port.
    """
    subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve())],
        cwd=str(BASE_DIR),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
    )


if __name__ == "__main__":
    sys.exit(main())
