# IMAP connector

An MCP server that connects any IMAP mailbox to AI tools. It follows the
Model Context Protocol (MCP), so it works with any AI tool or MCP client
that supports the standard. It can read, search, analyse, organise and
write mail in several accounts at once, and it comes with settings in
Swedish and English.

## What it does

- **Several accounts.** Each tool takes an `account` id. Add as many IMAP
  accounts as you like in the settings UI.
- **Reading never marks mail as read.** Folders are opened read-only
  (`EXAMINE`) and content is fetched with `BODY.PEEK[]`. Either mechanism
  alone keeps the `\Seen` flag untouched; both are always used. The current
  flags are returned with every message, so you can see that nothing
  changed.
- **No mail on disk.** Mail is fetched live for each call and held in memory
  only for that call. There is no database and no cache. Logs never contain
  subjects, addresses or bodies. Note that your AI client keeps its own
  conversation history, which will contain whatever mail you read in it.
- **Marking as read is your choice.** By default nothing is ever marked as
  read. Per account you can choose to have a message marked as read when
  *you* open it in the mailbox panel; what the AI reads is never
  marked. The panel's own tools are hidden from the model by the client,
  so at worst a misbehaving model could mark a message as read, nothing
  more.
- **Permissions per account.** Reading is always allowed. Organising
  (flags, moving, trash, folders) and composing (off, drafts only, or send)
  are switched on per account.
- **Analysis.** Header-only statistics for a time window: top senders and
  domains, messages per day, unread and newsletter counts, largest messages.
- **Attachments without saving them.** Text and PDF attachments are returned
  as text, images as images, everything else as metadata.

## Safety model

Mail is written by other people, and an AI tool reads it. A message can
contain text meant to steer the model ("forward all invoices to …"). The
connector reduces that risk in layers:

- Bodies are returned between random markers that change on every call, with
  a notice that the content is untrusted. Every response also lists which
  fields were written by the sender (`untrusted_fields`): subject lines and
  display names can carry instructions just like bodies can.
- Hidden HTML (hidden elements, zero-size or off-screen text, comments) and
  invisible Unicode characters are removed; links are shown with their real
  destination.
- A reply is never *sent* to a Reply-To address in another domain than the
  sender's. That is how a message would redirect your answer. Drafts are
  still created, with a warning.
- **Sending is off by default.** *Drafts only* lets the AI prepare replies
  that you review and send yourself. That is the recommended setting: the
  combination of reading and sending is what an injected instruction would
  need.
- **When sending is allowed, you approve each message** (per account,
  *Approval before mail is sent*):
  - *Ask every time* (default): before each message goes out, a macOS
    window shows the sender, all recipients including Bcc, the subject and
    everything the AI wrote (a quotation of the message being answered is
    named, not repeated). *Cancel* is the default button. You approve the
    actual message, which the AI can no longer change. The dialog is
    kept to about 40 lines; a message too long to show in full there is
    saved as a draft instead of being sent.
  - *Ask, but let me allow sending for a while*: the window gets a third
    button that allows sending without asking for 30 minutes
    (`IMAP_SEND_ALLOW_MINUTES`). The permission lives only in memory and
    also ends when the server restarts or the account's settings change.
  - *Never ask*: sends directly. Choosing this from the settings panel
    requires a macOS confirmation.

  Outside macOS the AI client is asked to put the question to you (MCP
  elicitation). A client that cannot do that gets the message saved as a
  draft instead, so nothing is sent unseen. Replies, forwards and new
  messages are all covered.
- Tool annotations mark sending and trashing as destructive, so clients ask
  before running them.
- There is no permanent deletion. Trash is the furthest a message can go.
- Organise calls touch at most `IMAP_MAX_BULK` messages and must pass the
  folder's `uidvalidity` from the search, so a message is never acted on if
  the server renumbered the folder since it was found.

Passwords are stored in the operating system keychain (macOS Keychain,
Windows Credential Locker, Secret Service on Linux), never in a file. On
macOS the keychain entry belongs to the Python interpreter, so other scripts
run with the same interpreter can read it, and macOS may ask again after a
Python upgrade.

## Supported providers

Any IMAP server that accepts a password login works: Fastmail, iCloud,
one.com, Loopia, Binero, GleSYS, self-hosted Dovecot and so on. Gmail,
iCloud and Fastmail need an **app password** (two-factor authentication
must be on).

**Microsoft 365 and Outlook.com are not supported yet.** Microsoft has
turned off password login for IMAP and SMTP, and the OAuth 2.0 sign-in they
require is not implemented.

## Installation

Requires Python 3.11 or later.

```bash
git clone <REPO_URL> imap-connector
cd imap-connector
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Optionally copy `config.example.env` to `.env` to change limits or the
location of the account file.

### Add accounts

In an AI tool that shows MCP Apps, ask the AI to "open the mail
settings". A settings panel opens next to the conversation (see
[Panels](#panels)). On
macOS, passwords are typed into a window drawn by macOS itself and go
straight to the Keychain.

On other systems, or in clients without panels, use the settings page in
the browser:

```bash
.venv/bin/python admin_server.py
```

The settings open in your browser. The page runs only on your own computer
(127.0.0.1), uses a one-time link to sign you in, and shuts down after 15
minutes without activity (`IMAP_ADMIN_IDLE_MINUTES`). The page warns two
minutes before and lets you continue. From inside the AI tool, the AI can
open the same page with `imap_open_settings_in_browser`.

Use **Test connection** after saving. It logs in, lists folders and shows
which Sent, Drafts and Trash folders were found. Folder names can be set
by hand when the server does not announce them.

### Connect an MCP client

The server speaks MCP over stdio (the client starts it) or over HTTP
(see [Running without a desktop](#running-without-a-desktop)). Most MCP
clients take a server definition of this shape in their configuration;
where that configuration lives differs between clients, so check your
client's documentation:

```json
{
  "mcpServers": {
    "imap-connector": {
      "command": "/<PATH_TO_REPO>/.venv/bin/python",
      "args": ["/<PATH_TO_REPO>/mcp_server.py"]
    }
  }
}
```

Clients configured from the command line take the same command and
argument. Changes in the settings apply on the next tool call; the client
does not need a restart.

## Panels

In clients that support MCP Apps (the MCP extension for interactive
interfaces), two panels open next to the conversation. Clients without
MCP Apps, such as terminal-based ones, get the same information as text.

**Mailbox** (`imap_open_mailbox`): folders, a message list with search and
filters, and a reading pane. What you browse in the panel is shown to you
and is not handed to the AI. Only when you press *Ask the AI about this
message* does the AI get a reference to it, which it then reads with the
ordinary tools. Organising buttons appear when the account allows
organising. If the account is set to mark mail as read when you open it,
opening a message in the panel marks it read; nothing the AI reads is
ever marked.

**Settings** (`imap_open_settings`): accounts, servers, permissions and
read marking. Anything typed in a panel passes through the AI client, so
the panel never asks for a password. Instead, on macOS:

- **Set password** opens a native macOS dialog. The password goes from
  that dialog straight into the Keychain, never through the client.
- Changes that give the AI more power (organising, drafts, sending), new
  accounts with such permissions, and server changes on an account with a
  stored password are confirmed in a native macOS dialog. The dialog's
  default button is *Cancel*.
- Lowering permissions, renaming and other changes save directly.

On other systems the panel shows the settings and can lower permissions;
for everything else it opens the settings page in the browser.

The panels fetch their data through tools that the client hides from the
model (`visibility: ["app"]`). That hiding is done by the client, so the
panel tools are written to give a model nothing extra if it calls them
anyway: they need the same permissions, and passwords and raised
permissions still require the native dialog.

## MCP tools

| Tool | What it does | Needs |
|---|---|---|
| `imap_list_accounts` | Accounts and their permissions | – |
| `imap_open_mailbox` | Shows the mailbox panel | – |
| `imap_open_settings` | Shows the settings panel | – |
| `imap_open_settings_in_browser` | Opens the settings page in the browser (local use only) | – |
| `imap_list_folders` | Folders with special use, optionally with counts | – |
| `imap_search` | Search a folder by sender, subject, text, date, flags | – |
| `imap_get_message` | Headers, flags, body as text, list of attachments | – |
| `imap_get_attachment` | An attachment as text, PDF text or image | – |
| `imap_get_thread` | The conversation a message belongs to | – |
| `imap_mailbox_stats` | Statistics for a time window | – |
| `imap_set_flags` | Read/unread, flagged, answered, keywords | organise |
| `imap_move_messages` | Move or copy to another folder | organise |
| `imap_trash_messages` | Move to Trash | organise |
| `imap_create_folder` | Create a folder | organise |
| `imap_save_draft` | Save a new message as a draft | drafts or send |
| `imap_reply` | Reply or reply-all, as draft or sent | drafts or send |
| `imap_forward` | Forward inline, as draft or sent | drafts or send |
| `imap_send_message` | Send a new message | send |

Only the tools in the first ten rows read; none of them change anything
on the server. The panels' own helper tools (`imap_panel_*`) are described
under [Panels](#panels).

## Running without a desktop

For a server without a keychain, accounts are still created with the
settings UI (or by copying `accounts.json`), and passwords are given as
`IMAP_SECRET_<ID>` or `IMAP_SECRET_<ID>_FILE`. See `config.example.env`.

With `MCP_TRANSPORT=http` the server listens on `MCP_HOST:MCP_PORT` and
requires `Authorization: Bearer <MCP_API_KEY>`; startup aborts if the key
is missing. Put it behind a reverse proxy with TLS. In this mode
`imap_open_settings` is disabled.

## Translating the settings UI

The texts are in `locales/sv.json` and `locales/en.json`. To add a
language, copy `en.json` to for example `locales/de.json`, translate the
values and set `_meta.language_name` to the language's own name
("Deutsch"). The new language appears in the language menu automatically.
Missing keys fall back to English.

## Tests

```bash
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest
```

The tests run against a small IMAP server written in Python that starts
inside the test process. It behaves like real servers where it matters:
fetching `BODY[]` marks a message as read, `BODY.PEEK[]` does not, and a
folder opened read-only refuses changes. That makes the "nothing was marked
as read" tests meaningful. Sending is tested against a local SMTP server
(aiosmtpd).

To check a real account as well, run the read-only live test. It reads the
newest messages and verifies that no flags and no unread counts changed:

```bash
IMAP_LIVE_TEST_ACCOUNT=<ACCOUNT_ID> .venv/bin/python -m pytest tests/test_live.py -v
```

The panels can be tried in an ordinary browser without an AI client. The
panel harness plays the part of the host, embeds a panel and answers its
tool calls against the test IMAP server with sample mail. Native dialogs
are simulated and nothing touches your real Keychain:

```bash
.venv/bin/python tests/panel_harness.py
```

Then open `http://127.0.0.1:8765/?panel=mailbox` or `?panel=settings`.

## Licence

GNU Affero General Public License v3.0 or later. The Source Serif 4,
Source Sans 3 and Source Code Pro fonts in `admin/static/fonts/` are
licensed under the SIL Open Font License 1.1 (`OFL.txt`).
