# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""Opening a TCP connection to a mail server within a fixed time.

A mail server that a VPN or firewall silently blocks gives no answer at
all, and a host name often has several addresses that are tried one after
another. Without a limit for the whole attempt, a call can wait longer
than an MCP client waits for an answer, and the user never sees why.

Here the name is looked up once, with a deadline, and the addresses from
that one lookup are tried against the same deadline. IMAP and SMTP both
connect through this module, so they behave and fail alike.

Entry points:
    open_socket(host, port, budget) -> socket.socket
    budget_from_env(name, default) -> float
    unreachable_text(host, port, exc) -> str
    not_found_text(host) -> str
    NameNotFound
"""

from __future__ import annotations

import os
import socket
import threading
import time
from typing import Any

# getaddrinfo has no timeout of its own, so each lookup runs in a thread of
# its own that the caller stops waiting for. A lookup that hangs only holds
# its own thread until the system resolver gives up; it never queues later
# lookups behind it. Past this many unfinished lookups the resolver is
# clearly not answering: no new lookup is started and the call fails at
# once, as one whose lookup timed out would.
_MAX_OPEN_LOOKUPS = 16
_open_lookups = 0
_lookups_lock = threading.Lock()

# An address gets an equal share of the time that is left, but not less
# than this while that much remains: a share of a few hundred milliseconds
# would give up on a server that is only far away.
_MIN_PER_ADDRESS = 1.0

# getaddrinfo's codes for "there is no such name". Not every platform has
# all of them.
_NO_SUCH_NAME = {
    code for code in (getattr(socket, "EAI_NONAME", None), getattr(socket, "EAI_NODATA", None))
    if code is not None
}


class NameNotFound(OSError):
    """The host name could not be resolved to any address."""


def budget_from_env(name: str, default: float = 15.0) -> float:
    """Seconds from an environment variable; the default when unset, not a number or not positive."""
    try:
        value = float(os.getenv(name, ""))
    except ValueError:
        return default
    return value if value > 0 else default


def _release_lookup() -> None:
    global _open_lookups
    with _lookups_lock:
        _open_lookups -= 1


def lookup(host: str, port: int, wait: float) -> list:
    """getaddrinfo with a deadline. Raises NameNotFound, TimeoutError or another OSError, nothing else."""
    global _open_lookups
    with _lookups_lock:
        if _open_lookups >= _MAX_OPEN_LOOKUPS:
            raise TimeoutError(f"the name server is not answering ({_open_lookups} lookups still waiting)")
        _open_lookups += 1
    outcome: dict[str, Any] = {}
    done = threading.Event()

    def run() -> None:
        try:
            outcome["infos"] = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except BaseException as exc:  # noqa: BLE001 - handed to the caller
            outcome["error"] = exc
        finally:
            _release_lookup()
            done.set()

    try:
        threading.Thread(target=run, name="mail-dns", daemon=True).start()
    except BaseException as exc:
        _release_lookup()  # the thread never ran, so it cannot release its place
        if isinstance(exc, RuntimeError):  # "can't start new thread"
            raise OSError(f"the name lookup for {host} could not be started: {exc}") from exc
        raise
    if not done.wait(wait):
        raise TimeoutError(f"looking up {host} took longer than {wait:.0f} s")
    if outcome.get("infos"):
        return outcome["infos"]
    error = outcome.get("error")
    if isinstance(error, socket.gaierror) and error.errno in _NO_SUCH_NAME:
        raise NameNotFound(str(error)) from error
    if isinstance(error, OSError):
        raise error
    raise OSError(f"name lookup for {host} failed: {error!r}")


def open_socket(host: str, port: int, budget: float) -> socket.socket:
    """Connect to the first of the host's addresses that answers, within `budget` seconds.

    The lookup may use a third of the budget. Each address then gets an
    equal share of what is left, and an address that fails early leaves its
    time to the others. The returned socket has a timeout of what remains
    of the budget, at least a third of it, so that a TLS handshake and the
    server's greeting are bounded too; the caller sets its own timeout for
    the conversation after that.
    """
    deadline = time.monotonic() + budget
    infos = lookup(host, port, budget / 3)
    last_error: OSError | None = None
    for index, (family, kind, proto, _canonical, address) in enumerate(infos):
        left = deadline - time.monotonic()
        if left <= 0:
            break
        share = max(left / (len(infos) - index), min(left, _MIN_PER_ADDRESS))
        sock = None
        try:
            sock = socket.socket(family, kind, proto)
            sock.settimeout(share)
            sock.connect(address)
        except OSError as exc:
            last_error = exc
            if sock is not None:
                sock.close()
            continue
        sock.settimeout(max(deadline - time.monotonic(), budget / 3))
        return sock
    if last_error is None:
        raise TimeoutError(f"no answer from {host} within {budget:.0f} s")
    raise last_error


def unreachable_text(host: str, port: int, exc: BaseException) -> str:
    """What to tell the user when no connection could be opened. The panels match the first words."""
    reason = str(exc)
    reason = reason if len(reason) <= 300 else reason[:300] + "…"
    return (
        f"Cannot reach the mail server {host}:{port} ({reason or 'no answer'}). "
        "The network may be down, or a VPN, firewall or security program may be blocking mail "
        f"(port {port}). Mail programs on this computer are probably affected too."
    )


def not_found_text(host: str) -> str:
    """What to tell the user when the server's name does not resolve. The panels match the first words."""
    return (
        f"Cannot find the mail server {host}: there is no server with that name. "
        "Check the spelling of the server name in the settings. If it is right, "
        "the network or its name server may be down."
    )
