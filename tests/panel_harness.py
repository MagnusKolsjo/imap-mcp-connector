# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""A stand-in MCP Apps host for developing and checking the panels in a browser.

Real MCP Apps hosts cache panels aggressively and are
slow to iterate against. This harness serves a host page that embeds a
panel in a sandboxed iframe and speaks the same JSON-RPC over postMessage:
`ui/initialize`, tool results, host context (theme, locale) and
`tools/call`, which it forwards to the real MCP server object. The mailbox
behind it is the in-process fake IMAP server from the test suite, seeded
with the test fixtures, and the account config lives in a temporary folder.

Native macOS dialogs are replaced by a fake that answers from the harness
page, so nothing is written to the real Keychain.

Run:
    .venv/bin/python tests/panel_harness.py [--port 8765]
then open http://127.0.0.1:8765/?panel=mailbox (or panel=settings) and use
the controls at the top to switch theme, language and width.

Not part of the test suite and never imported by the server.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

# Isolate configuration and secrets before the server modules are imported.
_tmp = Path(tempfile.mkdtemp(prefix="imap-panel-harness-"))
os.environ["IMAP_CONNECTOR_CONFIG"] = str(_tmp / "accounts.json")
os.environ["MCP_TRANSPORT"] = "stdio"

import keyring  # noqa: E402
from keyring.backend import KeyringBackend  # noqa: E402


class _MemoryKeyring(KeyringBackend):
    priority = 1

    def __init__(self):
        super().__init__()
        self.store: dict[tuple[str, str], str] = {}

    def get_password(self, service, username):
        return self.store.get((service, username))

    def set_password(self, service, username, password):
        self.store[(service, username)] = password

    def delete_password(self, service, username):
        self.store.pop((service, username), None)


keyring.set_keyring(_MemoryKeyring())

from imapclient import IMAPClient  # noqa: E402
from starlette.applications import Starlette  # noqa: E402
from starlette.requests import Request  # noqa: E402
from starlette.responses import HTMLResponse, JSONResponse  # noqa: E402
from starlette.routing import Route  # noqa: E402

import accounts  # noqa: E402
import imap_client  # noqa: E402
import mcp_server  # noqa: E402
import native_dialog  # noqa: E402
from fake_imap import FakeImapServer  # noqa: E402

USER, PASSWORD = "test@example.com", "correct horse battery staple"
FIXTURES = HERE / "fixtures"

# Answers for the fake native dialogs, set from the harness page.
# "knowledge" picks the file the fake file dialog returns: "good" is a valid
# knowledge base, "bad" has no questions (to see the error message).
DIALOG = {"confirm": True, "password": "correct horse battery staple", "knowledge": "good"}

SAMPLE_KNOWLEDGE = {
    "good": "---\nton: vänlig\nsignatur: Styrelsen\n---\n\n## Hur blir jag medlem?\n"
            "Nyckelord: medlemskap\nFyll i formuläret. <!-- intern anteckning -->\n\n"
            "## Vad kostar det?\n300 kronor per år.\n",
    "bad": "Bara text, inga frågor.\n",
}


def _seed(server: FakeImapServer) -> None:
    store = server.store
    for name, flag in (("INBOX", None), ("Sent", "\\Sent"), ("Drafts", "\\Drafts"),
                       ("Trash", "\\Trash"), ("Archive", None), ("Projekt/2026", None)):
        store.add_folder(name, flag) if flag else store.add_folder(name)
    now = datetime.now(timezone.utc)
    seeds = [
        ("INBOX", "plain.eml", (), 1), ("INBOX", "html_hidden.eml", (), 2),
        ("INBOX", "multipart_attachments.eml", (), 3), ("INBOX", "swedish.eml", (), 4),
        ("INBOX", "thread_original.eml", ("\\Seen",), 10), ("INBOX", "newsletter.eml", ("\\Seen", "\\Flagged"), 40),
        ("Sent", "thread_reply.eml", ("\\Seen",), 9),
    ]
    for folder, filename, flags, age in seeds:
        store.add_message(folder, (FIXTURES / filename).read_bytes(), flags, now - timedelta(days=age))
    # Enough filler to exercise paging in the message list.
    for i in range(60):
        raw = (
            f"From: Nyhetsbrev {i} <brev{i}@example.se>\r\nTo: {USER}\r\n"
            f"Subject: Utskick nummer {i}\r\nMessage-ID: <fill-{i}@example.se>\r\n"
            f"Date: Mon, 2 Nov 2026 09:00:00 +0100\r\n\r\nText {i}.\r\n"
        ).encode()
        store.add_message("Archive", raw, ("\\Seen",) if i % 3 else (), now - timedelta(days=20 + i))


def _setup_accounts(port: int) -> None:
    for acc in (
        accounts.Account(id="jobbet", display_name="Jobbet", email=USER, imap_host="127.0.0.1",
                         imap_port=port, imap_security="starttls", smtp_host="smtp.example.se",
                         permissions=accounts.Permissions(organise=True, send_mode=accounts.SendMode.DRAFTS)),
        accounts.Account(id="privat", display_name="Privat", email=USER, imap_host="127.0.0.1",
                         imap_port=port, imap_security="starttls",
                         read_marking=accounts.ReadMarking.USER_OPEN),
    ):
        accounts.save_account(acc)
        accounts.set_secret(acc.id, "imap", PASSWORD)

    imap_client._connect = lambda account: IMAPClient("127.0.0.1", port=port, ssl=False, timeout=10)


def _install_fake_dialogs() -> None:
    native_dialog.available = lambda: True
    def confirm(title, message, ok, cancel):
        print(f"[native dialog: {title}]\n{message}\n[{cancel}] [{ok}] -> {'OK' if DIALOG['confirm'] else 'cancel'}",
              file=sys.stderr, flush=True)
        return DIALOG["confirm"]

    def choose(title, message, buttons):
        print(f"[native dialog: {title}]\n{message}\n{buttons}", file=sys.stderr, flush=True)
        return buttons[-1] if DIALOG["confirm"] else None

    def choose_folder(prompt):
        print(f"[native folder dialog]\n{prompt}", file=sys.stderr, flush=True)
        if not DIALOG["confirm"]:
            return None
        folder = _tmp / "Bilagor"
        folder.mkdir(exist_ok=True)
        return str(folder)

    def choose_file(prompt):
        print(f"[native file dialog]\n{prompt}", file=sys.stderr, flush=True)
        if not DIALOG["confirm"]:
            return None
        path = _tmp / f"kunskapsbank-{DIALOG['knowledge']}.md"
        path.write_text(SAMPLE_KNOWLEDGE.get(DIALOG["knowledge"], SAMPLE_KNOWLEDGE["good"]), encoding="utf-8")
        return str(path)

    native_dialog.confirm = confirm
    native_dialog.choose = choose
    native_dialog.choose_folder = choose_folder
    native_dialog.choose_file = choose_file
    native_dialog.ask_password = lambda title, message, ok, cancel: DIALOG["password"] or None


HOST_PAGE = """<!doctype html>
<html lang="en"><meta charset="utf-8"><title>Panel harness</title>
<style>
 body{font:14px system-ui;margin:0;background:#ddd}
 header{display:flex;flex-wrap:wrap;gap:12px;align-items:center;padding:8px 12px;background:#333;color:#fff}
 header label{display:flex;gap:4px;align-items:center}
 #frame-wrap{margin:12px auto;background:#fff;border:1px solid #999}
 iframe{display:block;width:100%;border:0;min-height:200px}
 #log{font:12px ui-monospace,monospace;white-space:pre-wrap;max-height:200px;overflow:auto;background:#111;color:#9f9;margin:0;padding:8px}
</style>
<header>
 <strong>Panel harness</strong>
 <label>Panel <select id="panel"><option>mailbox</option><option>settings</option></select></label>
 <label>Theme <select id="theme"><option>light</option><option>dark</option></select></label>
 <label>Locale <select id="locale"><option>sv-SE</option><option>en-US</option></select></label>
 <label>Width <select id="width"><option value="420">420</option><option value="720" selected>720</option><option value="1100">1100</option></select></label>
 <label><input type="checkbox" id="confirm" checked> native dialogs answer OK</label>
 <button id="reload">Reload panel</button>
</header>
<div id="frame-wrap"><iframe id="app" sandbox="allow-scripts allow-forms" title="Panel"></iframe></div>
<pre id="log" aria-label="Protocol log"></pre>
<script>
const $ = id => document.getElementById(id);
const params = new URLSearchParams(location.search);
for (const k of ["panel","theme","locale","width"]) if (params.get(k)) $(k).value = params.get(k);
const log = m => { $("log").textContent = m + "\\n" + $("log").textContent.slice(0, 20000); };
const frame = $("app");
let openingResult = null;
function hostContext() {
  return {theme: $("theme").value, locale: $("locale").value, displayMode: "inline",
          containerDimensions: {maxWidth: +$("width").value}, platform: "desktop"};
}
async function rpc(path, body) {
  const r = await fetch(path, {method: "POST", headers: {"content-type": "application/json"}, body: JSON.stringify(body)});
  return r.json();
}
async function load() {
  $("frame-wrap").style.width = $("width").value + "px";
  const opening = $("panel").value === "mailbox" ? "imap_open_mailbox" : "imap_open_settings";
  openingResult = await rpc("/call", {name: opening, arguments: {}});
  const html = await (await fetch("/panel/" + $("panel").value)).text();
  frame.srcdoc = html;
}
const send = msg => frame.contentWindow.postMessage(msg, "*");
window.addEventListener("message", async e => {
  if (e.source !== frame.contentWindow) return;
  const m = e.data || {};
  log("app → host " + JSON.stringify(m).slice(0, 400));
  if (m.method === "ui/initialize") {
    send({jsonrpc: "2.0", id: m.id, result: {protocolVersion: m.params.protocolVersion,
          hostInfo: {name: "harness", version: "1"}, hostCapabilities: {openLinks: {}, serverTools: {}},
          hostContext: hostContext()}});
  } else if (m.method === "ui/notifications/initialized") {
    send({jsonrpc: "2.0", method: "ui/notifications/tool-result", params: openingResult});
  } else if (m.method === "tools/call") {
    const result = await rpc("/call", m.params);
    log("host → app " + JSON.stringify(result).slice(0, 400));
    send({jsonrpc: "2.0", id: m.id, result});
  } else if (m.method === "ui/notifications/size-changed") {
    frame.style.height = Math.max(200, m.params.height) + "px";
  } else if (m.method === "ui/message" || m.method === "ui/open-link" || m.method === "ui/request-display-mode" || m.method === "ui/update-model-context") {
    log("HOST WOULD HANDLE " + m.method + ": " + JSON.stringify(m.params));
    if (m.id !== undefined) send({jsonrpc: "2.0", id: m.id, result: m.method === "ui/request-display-mode" ? {mode: "inline"} : {}});
  } else if (m.id !== undefined) {
    send({jsonrpc: "2.0", id: m.id, error: {code: -32601, message: "not supported by harness: " + m.method}});
  }
});
for (const id of ["theme","locale","width"]) $(id).addEventListener("change", () => {
  $("frame-wrap").style.width = $("width").value + "px";
  send({jsonrpc: "2.0", method: "ui/notifications/host-context-changed", params: hostContext()});
});
$("confirm").addEventListener("change", () => rpc("/dialog", {confirm: $("confirm").checked}));
$("panel").addEventListener("change", load);
$("reload").addEventListener("click", load);
load();
</script>
</html>"""


async def host_page(request: Request):
    return HTMLResponse(HOST_PAGE)


async def panel(request: Request):
    contents = await mcp_server.mcp.read_resource(f"ui://imap-mcp-connector/{request.path_params['name']}.html")
    return HTMLResponse(contents[0].content)


async def call(request: Request):
    body = await request.json()
    try:
        result = await mcp_server.mcp.call_tool(body["name"], body.get("arguments") or {})
        return JSONResponse(result.model_dump(by_alias=True, exclude_none=True, mode="json"))
    except Exception as exc:  # noqa: BLE001 - surfaced to the panel as an error result
        return JSONResponse({"isError": True, "content": [{"type": "text", "text": str(exc)}]})


async def dialog(request: Request):
    DIALOG.update(await request.json())
    return JSONResponse(DIALOG)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    server = FakeImapServer(user=USER, password=PASSWORD).start()
    _seed(server)
    _setup_accounts(server.port)
    _install_fake_dialogs()
    app = Starlette(routes=[
        Route("/", host_page), Route("/panel/{name}", panel),
        Route("/call", call, methods=["POST"]), Route("/dialog", dialog, methods=["POST"]),
    ])
    import uvicorn

    print(f"Panel harness on http://127.0.0.1:{args.port}/?panel=mailbox", file=sys.stderr)
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
