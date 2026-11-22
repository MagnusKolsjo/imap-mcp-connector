# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""Tool annotations and caching hints for the MCP server.

MCP's four hints (readOnlyHint, destructiveHint, idempotentHint,
openWorldHint) are hints to the client, not guarantees. Clients use them to
decide what may run without asking the user. For a mail tool this matters
more than usual: reading must be cheap to allow, sending must not be.

Every tool belongs to exactly one class:

    READ_LOCAL    Reads only the local account configuration.
    READ_MAILBOX  Reads from an IMAP server. Never changes a flag: folders
                  are opened read-only and content is fetched with PEEK.
    ORGANISE      Changes flags or moves/copies messages. Reversible by the
                  user in any mail client, so not marked destructive.
    TRASH         Moves messages to Trash. Recoverable, but marked
                  destructive so clients ask first.
    DRAFT         Appends a draft. Adds, never removes.
    SEND          Sends mail to other people. Cannot be undone.
    LOCAL_ACTION  Starts the local settings UI. Touches no mailbox.
    SAVE_LOCAL    Writes attachments to the user's disk under the folder the
                  user chose. Adds files, never overwrites or deletes.

Entry points:
    READ_LOCAL, READ_MAILBOX, ORGANISE, TRASH, DRAFT, SEND, LOCAL_ACTION, SAVE_LOCAL
    CACHE_HINTS
"""

from __future__ import annotations

from mcp.server.caching import CacheHint
from mcp.types import ToolAnnotations

READ_LOCAL = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False
)

READ_MAILBOX = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True
)

ORGANISE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True
)

TRASH = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True
)

DRAFT = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True
)

SEND = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True
)

LOCAL_ACTION = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False
)

SAVE_LOCAL = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True
)

# Tool definitions only change when the code is deployed, which requires a
# client restart anyway, so an hour is ample. `public` holds because the
# tool list does not vary with who is calling.
CACHE_HINTS = {
    "tools/list": CacheHint(ttl_ms=3_600_000, scope="public"),
    "prompts/list": CacheHint(ttl_ms=3_600_000, scope="public"),
    "server/discover": CacheHint(ttl_ms=3_600_000, scope="public"),
}
