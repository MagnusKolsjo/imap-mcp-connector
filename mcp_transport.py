# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""Startup and transport selection for the MCP server: stdio or http.

stdio and http are symmetric choices. stdio suits a local MCP client that
starts the process itself. http suits shared operation behind a reverse
proxy, where one server process serves several clients.

http mode is fail-closed: without MCP_API_KEY, or with one shorter than
MIN_API_KEY_LENGTH characters, startup aborts with exit code 2. An open endpoint with access to somebody's mailboxes must never
come into existence by accident. stdio mode is never affected by this.

This module does not read .env. The server does that itself before it
imports its configuration, because a server started by an MCP client does
not inherit the user's shell environment.

Environment variables:
    MCP_TRANSPORT  stdio | http            (stdio when unset)
    MCP_HOST       bind address for http   (127.0.0.1 when unset)
    MCP_PORT       port for http           (the server's own port when unset)
    MCP_API_KEY    Bearer key, required in http mode (at least 32 characters)

Entry point:
    start(mcp, default_port, initialise=None) -> None
"""

from __future__ import annotations

import hmac
import logging
import os
import sys
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

logger = logging.getLogger(__name__)

# The key is the only thing between the network and the mailboxes, and
# nothing limits how often it may be guessed. 32 characters is what the
# documented way of generating one (secrets.token_hex(16) or longer) gives.
MIN_API_KEY_LENGTH = 32
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def start(
    mcp: "MCPServer",
    default_port: int,
    initialise: Callable[[], None] | None = None,
) -> None:
    """Run optional initialisation and start the transport MCP_TRANSPORT names.

    `initialise` runs in both modes inside try/except. The server should
    still come up in the MCP client when, say, the configuration file is
    broken; tool calls then fail with a readable message, which is a
    clearer signal than a server missing from the client's list.
    """
    if initialise is not None:
        try:
            initialise()
        except Exception as exc:  # noqa: BLE001 - startup must survive
            logger.warning("Initialisation failed: %s. Continuing anyway.", exc)

    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()

    if transport == "stdio":
        mcp.run(transport="stdio")
        return

    if transport == "http":
        api_key = os.getenv("MCP_API_KEY", "").strip()
        if not api_key:
            logger.error(
                "MCP_API_KEY is missing. Aborting http startup. "
                "Set the key in .env or use MCP_TRANSPORT=stdio."
            )
            sys.exit(2)
        if len(api_key) < MIN_API_KEY_LENGTH:
            logger.error(
                "MCP_API_KEY is shorter than %d characters. Aborting http startup. Generate one "
                "with: python3 -c \"import secrets; print(secrets.token_hex(32))\"",
                MIN_API_KEY_LENGTH,
            )
            sys.exit(2)
        host = os.getenv("MCP_HOST", "127.0.0.1")
        if host.strip().lower() not in _LOOPBACK_HOSTS:
            logger.warning(
                "MCP_HOST=%s makes the server reachable from other computers, and this "
                "process does not encrypt the connection. Put a reverse proxy with TLS in "
                "front of it, or the key and all mail travel in the clear.", host,
            )
        port = int(os.getenv("MCP_PORT", str(default_port)))
        _start_http(mcp, host=host, port=port, api_key=api_key)
        return

    logger.error(
        "Unknown value for MCP_TRANSPORT: %r. Allowed values: stdio, http.",
        transport,
    )
    sys.exit(2)


def _start_http(mcp: "MCPServer", host: str, port: int, api_key: str) -> None:
    """Start Streamable HTTP via uvicorn behind Bearer authentication.

    uvicorn and starlette are imported here so that stdio mode works on
    installations where they are absent.
    """
    import uvicorn
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse

    key_bytes = api_key.encode()

    class BearerAuth(BaseHTTPMiddleware):
        """Require `Authorization: Bearer <key>` on every request."""

        async def dispatch(self, request: Request, call_next):
            auth = request.headers.get("authorization", "")
            if not auth.lower().startswith("bearer "):
                return JSONResponse(
                    {"error": "Missing Authorization header."}, status_code=401
                )
            given = auth.split(" ", 1)[1].strip().encode()
            # Constant-time comparison, so the key cannot be guessed one
            # character at a time from response timings.
            if not hmac.compare_digest(given, key_bytes):
                return JSONResponse({"error": "Invalid API key."}, status_code=403)
            return await call_next(request)

    app = mcp.streamable_http_app(host=host)
    app.add_middleware(BearerAuth)
    logger.info("MCP server listening on http://%s:%s/mcp", host, port)
    uvicorn.run(app, host=host, port=port, log_level="info")
