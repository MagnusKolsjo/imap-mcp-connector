# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions
follow [Semantic Versioning](https://semver.org/).

## [1.0.1] – 2026-11-22

### Security
- A trusted sender is no longer verified by text the sender chose: quoted
  values in the Authentication-Results header cannot start a result of
  their own, and a DMARC pass must name the From domain.
- Creating an account whose name already has a stored password (an
  `IMAP_SECRET_<ID>` variable or a keychain entry) is confirmed in the
  native dialog.
- The confirmation dialog names the servers a stored password is sent to,
  before and after the change, and account names are shown on one line.
- Adding a trusted sender or domain is confirmed in the native dialog.
  Where there is none, the mailbox panel no longer adds them itself: the
  settings page in the browser has a form for it, and the panel opens
  that page.
- Older Office formats (`.doc`, `.xls`, `.ppt` and their templates) and
  RTF files are saved to quarantine, like the macro-enabled formats.
- The settings page's idle timeout only counts requests that carry a
  session.
- In http mode, startup aborts when `MCP_API_KEY` is shorter than 32
  characters, and a warning is logged when `MCP_HOST` is not a local
  address.
- Text hidden by a simple rule in a message's style sheet is removed like
  other hidden text.

- Installation uses `requirements.lock`, which pins every dependency to an
  exact version with a checksum for each file.

### Fixed
- An account in a hand-edited `accounts.json` that breaks the rules of the
  settings UI (port, security, sending without an outgoing server) is
  skipped and reported instead of loaded, and such an account can no
  longer be saved. A file whose top level is not an object gives a
  readable error.
- Fetching a message's remote images has one deadline for all of them
  (`IMAP_IMAGE_TOTAL_TIMEOUT`), so a slow server cannot hold the panel up.
- Saving attachments keeps one message in memory at a time.
- Text extraction from a PDF attachment stops after `IMAP_PDF_MAX_PAGES`
  pages or two million characters.

## [1.0.0] – 2026-11-22

First public release.

### Reading and analysis
- Any number of IMAP accounts, each addressed by an `account` id.
- Reading never marks mail as read: folders are opened read-only and
  content is fetched with `BODY.PEEK[]`. Optionally, a message can be
  marked as read when the user opens it in the mailbox panel.
- Search, threads, folder listings and header-only mailbox statistics.
- Text and PDF attachments returned as text, images as images.
- Mail content is marked as untrusted, hidden HTML text is removed, and
  bodies are returned between random markers.

### Organising and writing
- Flags, moving, trash and folders, switched on per account.
- Composing per account: off, drafts only, or send. Sending asks for the
  user's approval every time, allows it for a while, or not at all, as
  set per account.
- Replies follow the format of the original (HTML or plain text); new
  messages use the format set per account. Every outgoing HTML part is
  cleaned and has a plain-text version.
- Suggested replies are saved as drafts and opened in the mailbox panel
  for review.

### Panels (MCP Apps)
- Mailbox panel: folders, message list, reading pane, organising,
  reply, reply all, forward, new message and draft editing with a
  formatting toolbar. Sending is enabled only after the whole text has
  been scrolled through.
- Formatted reading of HTML mail. Images that are part of the message
  are always shown; remote images and the sender's layout load on request,
  or automatically for trusted senders and domains whose messages the
  user's mail server verified (DMARC, DKIM or SPF).
- Settings panel with native macOS dialogs for passwords and for raising
  permissions; a local web interface for other systems.

### Attachments and knowledge base
- Opt-in saving of attachments per account into
  `<account>/<year>/<month>/dokument|karantän`, with allowlist-based
  quarantine.
- A Markdown knowledge base per account for approved answers.

### Interface
- Swedish and English throughout, translatable through language files.
- Accessible according to WCAG 2.1 AA.
