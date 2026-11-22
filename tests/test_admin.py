# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""Tests for the admin UI: access control, forms, secrets and translations.

The keychain is replaced by an in-memory dict and the config file lives in
tmp_path, so the tests never touch the owner's real accounts or passwords.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import accounts  # noqa: E402
import admin_server  # noqa: E402
import i18n  # noqa: E402

PORT = 8765
BASE = f"http://127.0.0.1:{PORT}"
TOKEN = "start-token-for-tests"
SAME_ORIGIN = {"Origin": BASE}
PASSWORD = "Sekret-pw-4711"


@pytest.fixture
def secrets_store(monkeypatch, tmp_path):
    monkeypatch.setenv("IMAP_CONNECTOR_CONFIG", str(tmp_path / "accounts.json"))
    store: dict[tuple[str, str], str] = {}
    calls: list[tuple[str, str]] = []

    def set_secret(account_id, kind, value):
        calls.append((account_id, kind))
        store[(account_id, kind)] = value

    def delete_secret(account_id, kind):
        store.pop((account_id, kind), None)

    monkeypatch.setattr(accounts, "set_secret", set_secret)
    monkeypatch.setattr(accounts, "delete_secret", delete_secret)
    monkeypatch.setattr(accounts, "has_secret", lambda account_id, kind="imap": (account_id, kind) in store)
    monkeypatch.setattr(accounts, "keyring_available", lambda: True)
    store["_calls"] = calls  # type: ignore[assignment]
    return store


@pytest.fixture
def anon(secrets_store):
    """A client without a session."""
    app = admin_server.create_app(PORT, TOKEN)
    return TestClient(app, base_url=BASE, follow_redirects=False)


@pytest.fixture
def client(anon):
    """A client that has exchanged the start token for a session."""
    response = anon.get(f"/auth?token={TOKEN}")
    assert response.status_code == 303
    return anon


def csrf_of(client: TestClient, path: str = "/") -> str:
    html = client.get(path).text
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def account_form(**overrides) -> dict[str, str]:
    data = {
        "display_name": "Jobbet",
        "email": "anna@example.com",
        "imap_host": "imap.example.com",
        "imap_port": "993",
        "imap_security": "ssl",
        "username": "",
        "password": PASSWORD,
        "smtp_host": "",
        "smtp_port": "465",
        "smtp_security": "ssl",
        "save_sent": "auto",
        "read_marking": "never",
        "send_mode": "drafts",
    }
    data.update(overrides)
    return data


def create(client: TestClient, **overrides):
    data = account_form(**overrides)
    data["csrf_token"] = csrf_of(client)
    return client.post("/accounts/new", data=data, headers=SAME_ORIGIN)


# -----------------------------------------------------------------------------
# Access control
# -----------------------------------------------------------------------------

def test_token_is_single_use_and_redirects(anon):
    first = anon.get(f"/auth?token={TOKEN}")
    assert first.status_code == 303
    assert first.headers["location"] == "/"
    cookie = first.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie and "Path=/" in cookie

    fresh = TestClient(anon.app, base_url=BASE, follow_redirects=False)
    assert fresh.get(f"/auth?token={TOKEN}").status_code == 403
    assert anon.get("/").status_code == 200


def test_wrong_token_is_rejected(anon):
    assert anon.get("/auth?token=guess").status_code == 403
    # A failed guess must not burn the real token.
    assert anon.get(f"/auth?token={TOKEN}").status_code == 303


def test_no_session_gives_bilingual_403(anon):
    response = anon.get("/")
    assert response.status_code == 403
    assert 'lang="sv"' in response.text and 'lang="en"' in response.text
    assert "Start the IMAP MCP Connector settings again" in response.text
    assert "Starta inställningarna för IMAP MCP-brygga igen" in response.text


def test_bad_host_header_is_rejected(client):
    assert client.get("/", headers={"Host": "evil.example:8765"}).status_code == 400
    assert client.get("/", headers={"Host": "127.0.0.1:9999"}).status_code == 400
    assert client.get("/", headers={"Host": f"localhost:{PORT}"}).status_code == 200


def test_security_headers(client):
    response = client.get("/")
    csp = response.headers["content-security-policy"]
    assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp and "base-uri 'none'" in csp
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_post_without_csrf_is_rejected(client):
    response = client.post("/accounts/new", data=account_form(), headers=SAME_ORIGIN)
    assert response.status_code == 403
    assert accounts.load_accounts() == {}


def test_post_with_wrong_origin_is_rejected(client):
    data = account_form(csrf_token=csrf_of(client))
    assert client.post("/accounts/new", data=data, headers={"Origin": "http://evil.example"}).status_code == 403
    assert client.post("/accounts/new", data=data).status_code == 403  # no Origin, no Referer
    assert client.post("/accounts/new", data=data,
                       headers={"Origin": "null", "Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert accounts.load_accounts() == {}


def test_null_origin_with_same_origin_fetch_metadata_is_accepted(client):
    # What a browser sends for a form post under Referrer-Policy: no-referrer.
    data = account_form(csrf_token=csrf_of(client))
    response = client.post("/accounts/new", data=data,
                           headers={"Origin": "null", "Sec-Fetch-Site": "same-origin"})
    assert response.status_code == 303


# -----------------------------------------------------------------------------
# Accounts
# -----------------------------------------------------------------------------

def test_create_account_happy_path(client, secrets_store):
    response = create(client)
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    saved = accounts.load_accounts()
    assert list(saved) == ["jobbet"]
    assert saved["jobbet"].permissions.send_mode is accounts.SendMode.DRAFTS
    assert secrets_store[("jobbet", "imap")] == PASSWORD

    page = client.get("/")
    assert "Jobbet" in page.text and 'role="status"' in page.text
    assert PASSWORD not in Path(accounts.config_path()).read_text()


def test_validation_errors_render_summary_and_aria(client, secrets_store):
    response = create(client, display_name="", email="no-at-sign", imap_port="99999")
    assert response.status_code == 400
    html = response.text
    assert '<title>Error: ' in html
    assert 'class="error-summary"' in html and "autofocus" in html
    for name in ("display_name", "email", "imap_port"):
        assert f'href="#f-{name}"' in html
        field = re.search(rf'<input id="f-{name}"[^>]*>', html).group(0)
        assert 'aria-invalid="true"' in field
        assert f"f-{name}-error" in field
        assert f'id="f-{name}-error"' in html
    # Entered values are kept, the password is not.
    assert 'value="no-at-sign"' in html
    assert PASSWORD not in html
    assert accounts.load_accounts() == {}
    assert secrets_store["_calls"] == []


def test_send_without_smtp_host_is_an_error(client):
    response = create(client, send_mode="send", smtp_host="")
    assert response.status_code == 400
    assert 'href="#f-smtp_host"' in response.text


def test_password_never_appears_in_html(client):
    create(client)
    for path in ("/", "/accounts/jobbet/edit", "/accounts/jobbet/test", "/accounts/jobbet/delete"):
        assert PASSWORD not in client.get(path).text
    response = create(client, email="broken", display_name="Other")
    assert PASSWORD not in response.text


def test_edit_with_empty_password_keeps_secret(client, secrets_store):
    create(client)
    secrets_store["_calls"].clear()
    data = account_form(display_name="Jobbet nytt namn", password="", send_mode="off")
    data["csrf_token"] = csrf_of(client)
    response = client.post("/accounts/jobbet/edit", data=data, headers=SAME_ORIGIN)
    assert response.status_code == 303
    assert secrets_store["_calls"] == []
    assert secrets_store[("jobbet", "imap")] == PASSWORD
    account = accounts.get_account("jobbet")
    assert account.display_name == "Jobbet nytt namn"
    assert account.permissions.send_mode is accounts.SendMode.OFF


def test_edit_shows_id_read_only(client):
    create(client)
    html = client.get("/accounts/jobbet/edit").text
    field = re.search(r'<input id="f-account_id"[^>]*>', html).group(0)
    assert "readonly" in field and "name=" not in field
    assert "Leave the field empty to keep the current password" in html


def test_delete_flow(client, secrets_store):
    create(client)
    confirm = client.get("/accounts/jobbet/delete")
    assert confirm.status_code == 200
    assert "No mail is deleted from the server" in confirm.text
    response = client.post("/accounts/jobbet/delete", data={"csrf_token": csrf_of(client)}, headers=SAME_ORIGIN)
    assert response.status_code == 303
    assert accounts.load_accounts() == {}
    assert ("jobbet", "imap") not in secrets_store
    assert "The account Jobbet has been deleted." in client.get("/").text


def test_connection_test_success_and_failure(client, monkeypatch):
    create(client)
    monkeypatch.setattr(admin_server.imap_client, "test_connection", lambda account: {
        "ok": True, "folder_count": 7, "gmail": False,
        "special_folders": {"sent": "Sent", "drafts": "Drafts", "trash": None},
    })
    response = client.post("/accounts/jobbet/test", data={"csrf_token": csrf_of(client)}, headers=SAME_ORIGIN)
    assert response.status_code == 303
    html = client.get("/accounts/jobbet/test").text
    assert 'role="status"' in html and ">7<" in html and "Not found" in html

    def fail(account):
        raise admin_server.imap_client.ImapError("Login to imap.example.com failed for <anna>.")
    monkeypatch.setattr(admin_server.imap_client, "test_connection", fail)
    client.post("/accounts/jobbet/test", data={"csrf_token": csrf_of(client)}, headers=SAME_ORIGIN)
    html = client.get("/accounts/jobbet/test").text
    assert 'role="alert"' in html
    assert "failed for &lt;anna&gt;." in html  # shown as text, escaped
    assert "<title>Error: " in html


def test_unknown_account_is_404(client):
    assert client.get("/accounts/nobody/edit").status_code == 404


def test_close_settings_stops_server(secrets_store):
    stopped = []
    app = admin_server.create_app(PORT, TOKEN, shutdown=lambda: stopped.append(True))
    client = TestClient(app, base_url=BASE, follow_redirects=False)
    client.get(f"/auth?token={TOKEN}")
    response = client.post("/close", data={"csrf_token": csrf_of(client)}, headers=SAME_ORIGIN)
    assert response.status_code == 200
    assert "You can close this tab now." in response.text
    assert stopped == [True]
    assert client.get("/").status_code == 403


def test_read_marking_defaults_to_never_and_is_saved(client):
    html = client.get("/accounts/new").text
    never = re.search(r'<input type="radio" id="f-read_marking-never"[^>]*>', html).group(0)
    assert "checked" in never
    assert create(client, read_marking="user_open").status_code == 303
    assert accounts.get_account("jobbet").read_marking is accounts.ReadMarking.USER_OPEN
    edit = client.get("/accounts/jobbet/edit").text
    assert "checked" in re.search(r'<input type="radio" id="f-read_marking-user_open"[^>]*>', edit).group(0)
    assert "Marks as read when you open a message" in client.get("/").text


def test_invalid_read_marking_is_a_field_error(client):
    response = create(client, read_marking="always")
    assert response.status_code == 400
    assert 'href="#f-read_marking-never"' in response.text
    assert 'id="f-read_marking-error"' in response.text
    assert accounts.load_accounts() == {}


def test_organise_is_written_as_a_real_boolean(client):
    create(client, organise="yes")
    create(client, display_name="Privat")
    data = json.loads(Path(accounts.config_path()).read_text())
    by_id = {entry["id"]: entry for entry in data["accounts"]}
    assert by_id["jobbet"]["permissions"]["organise"] is True
    assert by_id["privat"]["permissions"]["organise"] is False


def test_save_attachments_is_written_as_a_real_boolean_and_shown(client):
    create(client, save_attachments="yes")
    create(client, display_name="Privat")
    data = json.loads(Path(accounts.config_path()).read_text())
    by_id = {entry["id"]: entry for entry in data["accounts"]}
    assert by_id["jobbet"]["permissions"]["save_attachments"] is True
    assert by_id["privat"]["permissions"]["save_attachments"] is False
    edit = client.get("/accounts/jobbet/edit").text
    box = re.search(r'<input type="checkbox" id="f-save_attachments"[^>]*>', edit).group(0)
    assert "checked" in box and 'aria-describedby="f-save_attachments-hint1"' in box
    assert 'id="f-save_attachments-hint1"' in edit
    overview = client.get("/?lang=en").text
    assert "May save attachments on the computer" in overview and "May not save attachments" in overview

    # Unticking turns it off again rather than keeping the stored value.
    data = account_form(password="")
    data["csrf_token"] = csrf_of(client)
    assert client.post("/accounts/jobbet/edit", data=data, headers=SAME_ORIGIN).status_code == 303
    assert accounts.get_account("jobbet").permissions.save_attachments is False


# -----------------------------------------------------------------------------
# Attachments folder
# -----------------------------------------------------------------------------

def post_folder(client: TestClient, value: str):
    return client.post("/attachments", data={"attachments_root": value, "csrf_token": csrf_of(client)},
                       headers=SAME_ORIGIN)


def test_attachments_folder_page_shows_current_folder(client):
    html = client.get("/attachments?lang=sv").text
    assert "<h1>Mapp för bilagor</h1>" in html
    assert 'aria-current="page"' in re.search(r'<a href="/attachments"[^>]*>', html).group(0)
    assert str(accounts.attachments_root()) in html
    assert str(accounts.attachments_root()) in client.get("/").text


def test_attachments_folder_is_validated_and_saved(client, tmp_path):
    response = post_folder(client, "relative/folder")
    assert response.status_code == 400
    html = response.text
    assert 'class="error-summary"' in html and 'href="#f-attachments_root"' in html
    field = re.search(r'<input id="f-attachments_root"[^>]*>', html).group(0)
    assert 'aria-invalid="true"' in field and "f-attachments_root-error" in field
    assert 'value="relative/folder"' in html

    missing = tmp_path / "nowhere" / "Bilagor"
    response = post_folder(client, str(missing))
    assert response.status_code == 400
    assert str(missing.parent) in response.text

    a_file = tmp_path / "file.txt"
    a_file.write_text("x")
    assert post_folder(client, str(a_file)).status_code == 400
    assert "attachments_root" not in accounts.get_settings()

    target = tmp_path / "Bilagor"  # need not exist, its parent does
    response = post_folder(client, str(target) + "/")
    assert response.status_code == 303 and response.headers["location"] == "/"
    assert accounts.attachments_root() == target
    assert str(target) in client.get("/").text

    # "~" is accepted and kept as typed; empty goes back to the default.
    assert post_folder(client, "~").status_code == 303
    assert accounts.get_settings()["attachments_root"] == "~"
    assert post_folder(client, "").status_code == 303
    assert accounts.get_settings()["attachments_root"] == ""


def test_attachments_folder_requires_csrf(client, tmp_path):
    response = client.post("/attachments", data={"attachments_root": str(tmp_path)}, headers=SAME_ORIGIN)
    assert response.status_code == 403
    assert "attachments_root" not in accounts.get_settings()


# -----------------------------------------------------------------------------
# Knowledge base
# -----------------------------------------------------------------------------

KNOWLEDGE = """---
ton: vänlig
signatur: Styrelsen
---

## Hur blir jag medlem?
Nyckelord: medlemskap
Fyll i formuläret. <!-- intern anteckning -->

## Vad kostar det?
300 kronor per år.
"""


def upload(client: TestClient, content: bytes, *, filename: str = "faq.md", csrf: bool = True, lang: str = "en"):
    data = {"csrf_token": csrf_of(client)} if csrf else {}
    return client.post(f"/accounts/jobbet/knowledge?lang={lang}", data=data,
                       files={"knowledge_file": (filename, content, "text/markdown")}, headers=SAME_ORIGIN)


def test_knowledge_upload_happy_path(client):
    create(client)
    page = client.get("/accounts/jobbet/knowledge?lang=en").text
    assert 'enctype="multipart/form-data"' in page
    assert 'accept=".md,.markdown,.txt,text/markdown,text/plain"' in page
    assert "No knowledge base" in page
    assert "<details" in page and "&lt;!--" in page  # the example is text, not markup
    assert "No knowledge base" in client.get("/").text

    response = upload(client, KNOWLEDGE.encode())
    assert response.status_code == 303
    assert response.headers["location"] == "/accounts/jobbet/knowledge"
    stored = accounts.knowledge_path("jobbet").read_text(encoding="utf-8")
    assert "Hur blir jag medlem?" in stored
    html = client.get("/accounts/jobbet/knowledge").text
    assert "The knowledge base for Jobbet is uploaded. It contains two questions." in html
    assert "signatur, ton" in html
    assert "Remove the knowledge base" in html
    assert "Two questions, updated" in client.get("/").text


def test_knowledge_upload_rejects_bad_files(client):
    create(client)
    cases = (
        (b"Just some text without questions.\n", "The file contains no questions."),
        ("## Fråga\nSvar på latin-1.\n".encode("latin-1"), "The file is not saved as UTF-8."),
        (b"## Q\nA\n" + b"x" * (1024 * 1024), "The file is larger than 1 MB."),
    )
    for content, message in cases:
        response = upload(client, content)
        assert response.status_code == 400, message
        assert message in response.text
        assert 'class="error-summary"' in response.text and 'href="#f-knowledge_file"' in response.text
        field = re.search(r'<input id="f-knowledge_file"[^>]*>', response.text).group(0)
        assert 'aria-invalid="true"' in field and "f-knowledge_file-error" in field
    assert not accounts.knowledge_path("jobbet").exists()

    sv = upload(client, "Ingen fråga alls.\n".encode(), lang="sv")
    assert "Filen innehåller inga frågor." in sv.text

    response = upload(client, b"", filename="")
    assert response.status_code == 400 and "Choose a file to upload." in response.text


def test_knowledge_too_large_body_is_refused_before_parsing(client, monkeypatch):
    create(client)
    calls = []
    monkeypatch.setattr(admin_server.knowledge_base, "import_text", lambda *a: calls.append(a))
    response = upload(client, b"## Q\nA\n" + b"x" * (2 * 1024 * 1024))
    assert response.status_code == 400
    assert "The file is larger than 1 MB." in response.text
    assert calls == []


def test_knowledge_unknown_error_is_shown_in_english(client, monkeypatch):
    create(client)

    def fail(account_id, data):
        raise admin_server.knowledge_base.KnowledgeError("Disk <full>.")
    monkeypatch.setattr(admin_server.knowledge_base, "import_text", fail)
    html = upload(client, KNOWLEDGE.encode(), lang="sv").text
    assert "Filen kunde inte laddas upp." in html
    assert '<span class="server-message" lang="en">Disk &lt;full&gt;.</span>' in html


def test_knowledge_upload_requires_csrf(client):
    create(client)
    assert upload(client, KNOWLEDGE.encode(), csrf=False).status_code == 403
    assert not accounts.knowledge_path("jobbet").exists()


def test_knowledge_remove_flow(client):
    create(client)
    # Nothing to remove yet: the confirmation step is skipped.
    assert client.get("/accounts/jobbet/knowledge/delete").status_code == 303
    upload(client, KNOWLEDGE.encode())
    confirm = client.get("/accounts/jobbet/knowledge/delete?lang=en")
    assert confirm.status_code == 200
    assert "Do you want to remove the knowledge base for the account Jobbet?" in confirm.text
    assert 'class="danger"' in confirm.text
    assert client.post("/accounts/jobbet/knowledge/delete", data={}, headers=SAME_ORIGIN).status_code == 403
    assert accounts.knowledge_path("jobbet").exists()
    response = client.post("/accounts/jobbet/knowledge/delete", data={"csrf_token": csrf_of(client)},
                           headers=SAME_ORIGIN)
    assert response.status_code == 303
    assert not accounts.knowledge_path("jobbet").exists()
    html = client.get("/accounts/jobbet/knowledge").text
    assert "The knowledge base for Jobbet is removed." in html and "No knowledge base" in html


def test_knowledge_for_unknown_account_is_404(client):
    assert client.get("/accounts/nobody/knowledge").status_code == 404
    assert client.get("/accounts/nobody/knowledge/delete").status_code == 404


def test_names_with_quotes_and_ampersands_are_escaped_once(client):
    assert create(client, display_name="O'Brien & Co").status_code == 303
    account_id = next(iter(accounts.load_accounts()))
    for path in (f"/accounts/{account_id}/edit", f"/accounts/{account_id}/delete",
                 f"/accounts/{account_id}/test"):
        html = client.get(path).text
        title = re.search(r"<title>(.*?)</title>", html).group(1)
        heading = re.search(r"<h1>(.*?)</h1>", html).group(1)
        for text in (title, heading):
            assert "O&#39;Brien &amp; Co" in text, text
            assert "&amp;#39;" not in text and "&amp;amp;" not in text


def test_failed_save_leaves_no_secret_behind(client, secrets_store, monkeypatch):
    def refuse(account):
        raise accounts.ConfigError("Account id 'jobbet' differs only in case from 'Jobbet'.")
    monkeypatch.setattr(accounts, "save_account", refuse)
    response = create(client)
    assert response.status_code == 400
    assert "differs only in case" in response.text
    assert secrets_store["_calls"] == []


def test_secret_failure_after_save_is_reported_on_the_edit_form(client, secrets_store, monkeypatch):
    def broken(account_id, kind, value):
        raise accounts.SecretError("keychain locked")
    monkeypatch.setattr(accounts, "set_secret", broken)
    response = create(client)
    assert response.status_code == 500
    assert list(accounts.load_accounts()) == ["jobbet"]
    html = response.text
    assert 'action="/accounts/jobbet/edit"' in html
    assert 'href="#f-password"' in html
    assert "the password could not be stored in the computer&#39;s keychain" in html
    assert PASSWORD not in html


def test_form_accessibility_markup(client):
    html = client.get("/accounts/new").text
    for name in ("display_name", "email", "imap_host", "imap_port", "password"):
        assert 'aria-required="true"' in re.search(rf'<input id="f-{name}"[^>]*>', html).group(0)
    for name in ("username", "smtp_host", "smtp_port", "sent_folder"):
        assert "aria-required" not in re.search(rf'<input id="f-{name}"[^>]*>', html).group(0)
    # Each field has its own name in a screen reader's list of controls.
    for label in ("IMAP server", "IMAP port", "SMTP server", "SMTP port", "IMAP encryption", "SMTP encryption"):
        assert label in html
    assert re.search(r'for="f-smtp_port">SMTP port <span class="optional">', html)

    response = create(client, display_name="", email="x")
    html = response.text
    summary = re.search(r'<div class="error-summary"[^>]*>', html).group(0)
    assert 'role="alert"' in summary and 'tabindex="-1"' in summary and "data-focus-on-load" in summary
    assert "There are two problems to fix" in html
    assert '<span class="field-error-prefix">Error: </span>' in html
    assert "data-dirty=\"true\"" in html


def test_swedish_error_count_uses_words(client):
    data = account_form(display_name="", csrf_token=csrf_of(client))
    html = client.post("/accounts/new?lang=sv", data=data, headers=SAME_ORIGIN).text
    assert "Det finns ett fel att rätta" in html
    data = account_form(display_name="", email="x", csrf_token=csrf_of(client))
    html = client.post("/accounts/new", data=data, headers=SAME_ORIGIN).text
    assert "Det finns två fel att rätta" in html
    assert "<span class=\"field-error-prefix\">Fel: </span>" in html


def test_accounts_table_keeps_explicit_roles(client):
    create(client)
    html = client.get("/").text
    assert '<table class="stack" role="table">' in html
    assert 'role="rowheader"' in html and 'role="columnheader"' in html and 'role="cell"' in html
    assert html.count('<tr role="row">') == 2


def test_script_is_external_and_allowed_by_csp(client):
    response = client.get("/accounts/new")
    assert "script-src 'self'" in response.headers["content-security-policy"]
    scripts = re.findall(r"<script[^>]*>", response.text)
    assert scripts == ['<script src="/static/app.js" defer>']
    assert client.get("/static/app.js").status_code == 200
    # Without a session nothing but the static page is served.
    anon = TestClient(client.app, base_url=BASE, follow_redirects=False)
    assert "<script" not in anon.get("/").text


def test_footer_has_no_environment_variable(client):
    assert "IMAP_ADMIN_IDLE_MINUTES" not in client.get("/").text
    sv = client.get("/?lang=sv").text
    assert "Den här sidan fungerar bara på den här datorn." in sv
    assert "efter 15 minuter utan aktivitet" in sv


def test_swedish_copy_uses_e_post_and_short_name():
    sv = json.loads((i18n.LOCALES_DIR / "sv.json").read_text(encoding="utf-8"))
    assert not [k for k, v in sv.items() if "mejl" in v.lower()]
    # Placeholders such as {id} are code, not copy.
    assert not [k for k, v in sv.items() if re.search(r"\bid(:t)?\b", re.sub(r"\{\w+\}", "", v))]
    assert sv["delete.title"].startswith("Vill du ta bort kontot") and sv["delete.title"].endswith("?")


# -----------------------------------------------------------------------------
# Idle timeout
# -----------------------------------------------------------------------------

def test_keepalive_requires_session_csrf_and_host(client):
    anon = TestClient(client.app, base_url=BASE, follow_redirects=False)
    assert anon.post("/keepalive", data={"csrf_token": "x"}, headers=SAME_ORIGIN).status_code == 403
    assert client.post("/keepalive", data={}, headers=SAME_ORIGIN).status_code == 403
    token = csrf_of(client)
    assert client.post("/keepalive", data={"csrf_token": token},
                       headers={"Origin": "http://evil.example"}).status_code == 403
    assert client.post("/keepalive", data={"csrf_token": token},
                       headers={**SAME_ORIGIN, "Host": "evil.example"}).status_code == 400
    response = client.post("/keepalive", data={"csrf_token": token}, headers=SAME_ORIGIN)
    assert response.status_code == 200
    assert response.json() == {"seconds_left": 15 * 60, "idle_seconds": 15 * 60}


def test_keepalive_moves_the_deadline_and_status_does_not(client):
    state = client.app.state.admin
    token = csrf_of(client)
    state.last_activity -= 600
    status = client.get("/status")
    assert status.status_code == 200
    assert 299 <= status.json()["seconds_left"] <= 300
    assert 299 <= state.seconds_left() <= 300  # polling did not count as activity

    client.post("/keepalive", data={"csrf_token": token}, headers=SAME_ORIGIN)
    assert state.seconds_left() > 899
    assert client.get("/status").json()["seconds_left"] == 900


def test_status_reports_off_when_idle_timeout_is_disabled(secrets_store):
    app = admin_server.create_app(PORT, TOKEN, idle_minutes=0)
    client = TestClient(app, base_url=BASE, follow_redirects=False)
    client.get(f"/auth?token={TOKEN}")
    assert client.get("/status").json() == {"seconds_left": None, "idle_seconds": 0}
    assert 'data-idle-seconds="0"' in client.get("/").text


def test_form_states_the_time_limit(client):
    html = client.get("/accounts/new?lang=sv").text
    note = html.index("stängs inställningarna efter 15 minuter utan aktivitet")
    assert note < html.index('<div class="button-row">')
    assert 'id="idle-dialog"' in html and 'role="alertdialog"' in html


# -----------------------------------------------------------------------------
# Language
# -----------------------------------------------------------------------------

def test_language_switch_sets_lang_and_cookie(client):
    english = client.get("/", headers={"Accept-Language": "en-GB,en;q=0.8"})
    assert '<html lang="en">' in english.text

    swedish = client.get("/?lang=sv")
    assert '<html lang="sv">' in swedish.text
    assert "<title>Konton – IMAP MCP-brygga</title>" in swedish.text
    assert "imap_admin_lang=sv" in swedish.headers["set-cookie"]
    assert 'hreflang="en" lang="en"' in swedish.text or ('lang="en" hreflang="en"' in swedish.text)

    # The cookie now wins over Accept-Language.
    again = client.get("/", headers={"Accept-Language": "en"})
    assert '<html lang="sv">' in again.text


def test_accept_language_negotiation():
    assert i18n.negotiate(None, None, "sv-SE,sv;q=0.9,en;q=0.5") == "sv"
    assert i18n.negotiate(None, None, "de-DE,de;q=0.9") == "en"
    assert i18n.negotiate("xx", "sv", None) == "sv"
    assert i18n.negotiate("en", "sv", "sv") == "en"


def test_locale_files_have_identical_keys():
    sv = json.loads((i18n.LOCALES_DIR / "sv.json").read_text(encoding="utf-8"))
    en = json.loads((i18n.LOCALES_DIR / "en.json").read_text(encoding="utf-8"))
    assert set(sv) == set(en)
    assert sv["_meta.language_name"] == "Svenska"


def test_swedish_copy_has_no_exclamation_marks():
    sv = json.loads((i18n.LOCALES_DIR / "sv.json").read_text(encoding="utf-8"))
    # "<!--" is the HTML comment syntax shown in the knowledge base help, not punctuation.
    assert not [k for k, v in sv.items() if "!" in v.replace("<!--", "")]


def test_missing_key_falls_back_to_english_then_key(monkeypatch):
    catalogs = {"en": {"only.en": "English text"}, "sv": {}}
    monkeypatch.setattr(i18n, "_catalogs", lambda: catalogs)
    assert i18n.translate("sv", "only.en") == "English text"
    assert i18n.translate("sv", "nowhere.at.all") == "nowhere.at.all"


def test_new_language_file_is_discovered(monkeypatch, tmp_path):
    (tmp_path / "en.json").write_text('{"_meta.language_name": "English"}', encoding="utf-8")
    (tmp_path / "de.json").write_text('{"_meta.language_name": "Deutsch"}', encoding="utf-8")
    monkeypatch.setattr(i18n, "LOCALES_DIR", tmp_path)
    i18n.reload()
    try:
        assert ("de", "Deutsch") in i18n.available_languages()
    finally:
        monkeypatch.undo()
        i18n.reload()
