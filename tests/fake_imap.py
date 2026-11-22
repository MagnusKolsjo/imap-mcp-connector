# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""An in-process IMAP4rev1 server for tests.

It speaks plain text on 127.0.0.1 and implements the subset of IMAP that
imapclient sends on behalf of imap_client.py. It is a test double, not a
product, but it copies real servers on the points the tests are about:

  * A non-PEEK body fetch (BODY[...], RFC822, RFC822.TEXT) in a folder opened
    with SELECT sets \\Seen and reports the new FLAGS in the same response.
    BODY.PEEK[...] never does, and nothing sets \\Seen under EXAMINE.
  * Under EXAMINE, STORE, MOVE and EXPUNGE are refused with NO [READ-ONLY].
  * UID EXPUNGE removes only the given UIDs; plain EXPUNGE removes every
    message flagged \\Deleted, which is why the client must avoid it.
  * Capabilities (MOVE, UIDPLUS, SPECIAL-USE, X-GM-EXT-1, ...) are set per
    server instance, and commands behind a missing capability are rejected.

Tests seed and inspect the MailStore directly, never through IMAP, so an
assertion about flags cannot be fooled by a bug in the protocol layer.
"""

from __future__ import annotations

import email
import itertools
import re
import socketserver
import threading
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from email import policy
from email.header import decode_header, make_header
from typing import Any, Callable

DEFAULT_CAPABILITIES = (
    "IMAP4rev1", "UIDPLUS", "MOVE", "SPECIAL-USE", "NAMESPACE", "UNSELECT", "ID", "ENABLE",
)
SYSTEM_FLAGS = {f.lower(): f for f in ("\\Seen", "\\Answered", "\\Flagged", "\\Deleted", "\\Draft")}
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


class BadCommand(Exception):
    """Answered with a tagged BAD."""


class NoResponse(Exception):
    """Answered with a tagged NO; the text may start with a response code."""


# -----------------------------------------------------------------------------
# Mail store
# -----------------------------------------------------------------------------

@dataclass
class StoredMessage:
    raw: bytes
    flags: set[str]
    internaldate: datetime
    gm_msgid: int = 0
    gm_thrid: int = 0


@dataclass
class Folder:
    name: str
    uidvalidity: int
    special_use: str | None = None
    uidnext: int = 1
    subscribed: bool = True
    messages: dict[int, StoredMessage] = field(default_factory=dict)

    def sorted_uids(self) -> list[int]:
        return sorted(self.messages)


def normalise_flag(flag: str) -> str:
    # System flags are case-insensitive in IMAP; keywords keep their case.
    return SYSTEM_FLAGS.get(flag.lower(), flag)


def to_crlf(raw: bytes) -> bytes:
    return re.sub(rb"\r?\n", b"\r\n", raw)


class MailStore:
    """Folders and messages shared by every connection to one server."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.folders: dict[str, Folder] = {}
        self._validity = itertools.count(1000)
        self._gm_ids = itertools.count(1_700_000_000_000)

    def reset(self) -> None:
        with self.lock:
            self.folders.clear()

    def key(self, name: str) -> str:
        return "INBOX" if name.upper() == "INBOX" else name

    def get(self, name: str) -> Folder | None:
        return self.folders.get(self.key(name))

    def folder(self, name: str) -> Folder:
        found = self.get(name)
        if found is None:
            raise KeyError(name)
        return found

    def add_folder(self, name: str, special_use: str | None = None) -> Folder:
        with self.lock:
            name = self.key(name)
            if name not in self.folders:
                self.folders[name] = Folder(name, next(self._validity), special_use)
            return self.folders[name]

    def add_message(self, folder: str, raw: bytes, flags=(), internaldate: datetime | None = None,
                    gm_thrid: int | None = None) -> int:
        with self.lock:
            box = self.add_folder(folder)
            uid = box.uidnext
            box.uidnext += 1
            msgid = next(self._gm_ids)
            box.messages[uid] = StoredMessage(
                raw=to_crlf(raw),
                flags={normalise_flag(f) for f in flags},
                internaldate=internaldate or datetime.now(timezone.utc).replace(microsecond=0),
                gm_msgid=msgid,
                gm_thrid=gm_thrid or msgid,
            )
            return uid

    def flags(self, folder: str, uid: int) -> set[str]:
        with self.lock:
            return set(self.folder(folder).messages[uid].flags)

    def all_flags(self, folder: str) -> dict[int, set[str]]:
        with self.lock:
            return {uid: set(m.flags) for uid, m in self.folder(folder).messages.items()}

    def uids(self, folder: str) -> list[int]:
        with self.lock:
            return self.folder(folder).sorted_uids()

    def unseen(self, folder: str) -> int:
        with self.lock:
            return sum("\\Seen" not in m.flags for m in self.folder(folder).messages.values())

    def renumber(self, folder: str) -> int:
        """Simulate a server that rebuilt its index: new UIDVALIDITY, same mail."""
        with self.lock:
            box = self.folder(folder)
            box.uidvalidity = next(self._validity)
            return box.uidvalidity


# -----------------------------------------------------------------------------
# Wire format helpers
# -----------------------------------------------------------------------------

class Literal(bytes):
    """A string token that arrived as {n} literal."""


def tokenize(data: bytes) -> list[Any]:
    """Split a command into atoms, strings and nested lists."""
    pos = 0
    stack: list[list[Any]] = [[]]
    while pos < len(data):
        ch = data[pos:pos + 1]
        if ch in (b" ", b"\r", b"\n"):
            pos += 1
        elif ch == b"(":
            stack.append([])
            pos += 1
        elif ch == b")":
            if len(stack) == 1:
                raise BadCommand("unbalanced parenthesis")
            done = stack.pop()
            stack[-1].append(done)
            pos += 1
        elif ch == b'"':
            pos += 1
            out = bytearray()
            while data[pos:pos + 1] != b'"':
                if pos >= len(data):
                    raise BadCommand("unterminated string")
                if data[pos:pos + 1] == b"\\":
                    pos += 1
                out += data[pos:pos + 1]
                pos += 1
            stack[-1].append(bytes(out))
            pos += 1
        elif ch == b"{":
            m = re.match(rb"\{(\d+)\+?\}\r\n", data[pos:])
            if not m:
                raise BadCommand("bad literal")
            start = pos + m.end()
            size = int(m.group(1))
            stack[-1].append(Literal(data[start:start + size]))
            pos = start + size
        else:
            start = pos
            depth = 0
            # Brackets belong to the atom, so BODY.PEEK[HEADER.FIELDS (A B)]
            # stays one token even though it contains spaces and parens.
            while pos < len(data):
                c = data[pos:pos + 1]
                if c == b"[":
                    depth += 1
                elif c == b"]":
                    depth -= 1
                elif depth == 0 and c in (b" ", b"(", b")", b"\r", b"\n"):
                    break
                pos += 1
            stack[-1].append(data[start:pos])
    if len(stack) != 1:
        raise BadCommand("unbalanced parenthesis")
    return stack[0]


def quote(value: str | bytes) -> bytes:
    if isinstance(value, str):
        value = value.encode()
    return b'"' + value.replace(b"\\", b"\\\\").replace(b'"', b'\\"') + b'"'


def literal(data: bytes) -> bytes:
    return b"{%d}\r\n" % len(data) + data


def imap_datetime(dt: datetime) -> bytes:
    offset = dt.utcoffset() or timedelta(0)
    minutes = int(offset.total_seconds() // 60)
    sign = "+" if minutes >= 0 else "-"
    minutes = abs(minutes)
    text = (f"{dt.day:02d}-{_MONTHS[dt.month - 1]}-{dt.year} {dt:%H:%M:%S} "
            f"{sign}{minutes // 60:02d}{minutes % 60:02d}")
    return quote(text)


def parse_imap_date(token: bytes) -> date:
    try:
        return datetime.strptime(token.decode(), "%d-%b-%Y").date()
    except ValueError as exc:
        raise BadCommand(f"bad date {token!r}") from exc


def resolve_set(spec: bytes, values: list[int]) -> list[int]:
    """Members of `values` (UIDs or sequence numbers) named by an IMAP set."""
    if not values:
        return []
    top = max(values)
    wanted: set[int] = set()
    for piece in spec.decode().split(","):
        lo, _, hi = piece.partition(":")
        a = top if lo == "*" else int(lo)
        b = a if not hi else (top if hi == "*" else int(hi))
        lo_v, hi_v = min(a, b), max(a, b)
        wanted.update(v for v in values if lo_v <= v <= hi_v)
    return sorted(wanted)


def split_header(raw: bytes) -> tuple[bytes, bytes]:
    idx = raw.find(b"\r\n\r\n")
    if idx < 0:
        return raw, b""
    return raw[:idx + 4], raw[idx + 4:]


def header_fields(header: bytes, names: list[str], negate: bool) -> bytes:
    wanted = {n.lower() for n in names}
    out: list[bytes] = []
    keep = False
    for line in header.split(b"\r\n"):
        if not line:
            continue
        if line[:1] in (b" ", b"\t"):
            if keep:
                out.append(line)
            continue
        name = line.split(b":", 1)[0].strip().decode("ascii", "replace").lower()
        keep = (name in wanted) != negate
        if keep:
            out.append(line)
    return b"".join(l + b"\r\n" for l in out) + b"\r\n"


def decoded(value: Any) -> str:
    if value is None:
        return ""
    try:
        return str(make_header(decode_header(str(value))))
    except Exception:  # noqa: BLE001 - search must not crash on odd headers
        return str(value)


def body_text(msg: email.message.Message) -> str:
    parts = []
    for part in msg.walk():
        if part.get_content_maintype() == "text":
            try:
                parts.append(part.get_content())
            except Exception:  # noqa: BLE001
                payload = part.get_payload(decode=True) or b""
                parts.append(payload.decode("utf-8", "replace"))
    return "\n".join(parts)


# -----------------------------------------------------------------------------
# Search
# -----------------------------------------------------------------------------

Predicate = Callable[[int, int, StoredMessage, Any], bool]


class SearchParser:
    """Turns SEARCH keys into one predicate(uid, seq, message, parsed)."""

    FLAG_KEYS = {
        b"SEEN": ("\\Seen", True), b"UNSEEN": ("\\Seen", False),
        b"FLAGGED": ("\\Flagged", True), b"UNFLAGGED": ("\\Flagged", False),
        b"ANSWERED": ("\\Answered", True), b"UNANSWERED": ("\\Answered", False),
        b"DELETED": ("\\Deleted", True), b"UNDELETED": ("\\Deleted", False),
        b"DRAFT": ("\\Draft", True), b"UNDRAFT": ("\\Draft", False),
    }
    HEADER_KEYS = {b"FROM": "From", b"TO": "To", b"CC": "Cc", b"BCC": "Bcc", b"SUBJECT": "Subject"}

    def __init__(self, tokens: list[Any], charset: str, gmail: bool, all_uids: list[int]):
        self.tokens, self.pos = tokens, 0
        self.charset, self.gmail, self.all_uids = charset, gmail, all_uids

    def parse(self) -> Predicate:
        preds = []
        while self.pos < len(self.tokens):
            preds.append(self.key())
        return lambda *a: all(p(*a) for p in preds)

    def next(self) -> Any:
        if self.pos >= len(self.tokens):
            raise BadCommand("missing search argument")
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def text(self) -> str:
        return self.next().decode(self.charset, "replace").casefold()

    def key(self) -> Predicate:
        tok = self.next()
        if isinstance(tok, list):
            sub = SearchParser(tok, self.charset, self.gmail, self.all_uids).parse()
            return sub
        word = tok.upper()
        if word == b"ALL":
            return lambda *a: True
        if word in self.FLAG_KEYS:
            flag, present = self.FLAG_KEYS[word]
            return lambda uid, seq, m, p: (flag in m.flags) == present
        if word in (b"KEYWORD", b"UNKEYWORD"):
            kw, present = self.next().decode(), word == b"KEYWORD"
            return lambda uid, seq, m, p: (kw in m.flags) == present
        if word in self.HEADER_KEYS:
            name, needle = self.HEADER_KEYS[word], self.text()
            return lambda uid, seq, m, p: needle in decoded(p[name]).casefold()
        if word == b"HEADER":
            name, needle = self.next().decode(), self.text()
            return lambda uid, seq, m, p: (
                name in p and needle in " ".join(decoded(v) for v in p.get_all(name, [])).casefold()
            )
        if word == b"BODY":
            needle = self.text()
            return lambda uid, seq, m, p: needle in body_text(p).casefold()
        if word == b"TEXT":
            needle = self.text()
            return lambda uid, seq, m, p: needle in (
                " ".join(f"{k}: {decoded(v)}" for k, v in p.items()) + "\n" + body_text(p)
            ).casefold()
        if word in (b"SINCE", b"BEFORE", b"ON"):
            day = parse_imap_date(self.next())
            # RFC 3501: compare the date part of INTERNALDATE, ignoring time zone.
            ops = {b"SINCE": lambda d: d >= day, b"BEFORE": lambda d: d < day, b"ON": lambda d: d == day}
            op = ops[word]
            return lambda uid, seq, m, p: op(m.internaldate.date())
        if word in (b"LARGER", b"SMALLER"):
            size = int(self.next())
            if word == b"LARGER":
                return lambda uid, seq, m, p: len(m.raw) > size
            return lambda uid, seq, m, p: len(m.raw) < size
        if word == b"UID":
            spec = self.next()
            members = set(resolve_set(spec, self.all_uids))
            return lambda uid, seq, m, p: uid in members
        if word == b"NOT":
            inner = self.key()
            return lambda *a: not inner(*a)
        if word == b"OR":
            left, right = self.key(), self.key()
            return lambda *a: left(*a) or right(*a)
        if word == b"X-GM-THRID" and self.gmail:
            thrid = int(self.next())
            return lambda uid, seq, m, p: m.gm_thrid == thrid
        if re.fullmatch(rb"[0-9*:,]+", tok):
            seqs = set(resolve_set(tok, list(range(1, len(self.all_uids) + 1))))
            return lambda uid, seq, m, p: seq in seqs
        raise BadCommand(f"unsupported search key {tok!r}")


# -----------------------------------------------------------------------------
# Connection handler
# -----------------------------------------------------------------------------

_BODY_ITEM = re.compile(rb"^(BODY(?:\.PEEK)?)\[([^\]]*)\](?:<(\d+)(?:\.(\d+))?>)?$", re.IGNORECASE)


class Session(socketserver.StreamRequestHandler):
    server: "_TCPServer"

    def setup(self) -> None:
        super().setup()
        self.fake: FakeImapServer = self.server.fake
        self.store = self.fake.store
        self.authenticated = False
        self.selected: str | None = None
        self.readonly = False

    # --- I/O --------------------------------------------------------------

    def send(self, data: bytes) -> None:
        self.wfile.write(data + b"\r\n")

    def read_command(self) -> bytes | None:
        buf = b""
        while True:
            line = self.rfile.readline()
            if not line:
                return None
            buf += line
            m = re.search(rb"\{(\d+)(\+?)\}\r\n$", line)
            if not m:
                # Strip only the command's own line end: a literal at the end
                # of the command may legitimately end with CRLF itself.
                return buf[:-2] if buf.endswith(b"\r\n") else buf.rstrip(b"\n")
            if not m.group(2):
                self.send(b"+ Ready for literal data")
            buf += self.rfile.read(int(m.group(1)))

    def handle(self) -> None:
        self.send(b"* OK Fake IMAP4rev1 server ready")
        while True:
            line = self.read_command()
            if line is None:
                return
            tag = b"*"
            try:
                tokens = tokenize(line)
                tag = tokens[0] if tokens else b"*"
                if len(tokens) < 2:
                    raise BadCommand("missing command")
                command = tokens[1].upper()
                elided = re.sub(rb"\{\d+\+?\}\r\n.*", b"{literal}", line, flags=re.S)
                self.fake.log.append(elided.decode("utf-8", "replace"))
                done = self.dispatch(tag, command, tokens[2:])
                if done:
                    return
            except NoResponse as exc:
                self.send(tag + b" NO " + str(exc).encode())
            except BadCommand as exc:
                self.send(tag + b" BAD " + str(exc).encode())
            except (ValueError, IndexError, KeyError) as exc:
                self.send(tag + b" BAD " + repr(exc).encode())

    # --- dispatch ---------------------------------------------------------

    def dispatch(self, tag: bytes, command: bytes, args: list[Any]) -> bool:
        caps = self.fake.capabilities
        if command == b"CAPABILITY":
            self.send(b"* CAPABILITY " + " ".join(caps).encode())
        elif command == b"NOOP":
            pass
        elif command == b"LOGOUT":
            self.send(b"* BYE Fake IMAP server logging out")
            self.send(tag + b" OK LOGOUT completed")
            return True
        elif command == b"LOGIN":
            user, password = (a.decode() for a in args[:2])
            self.fake.login_attempts.append(user)
            if user != self.fake.user or password != self.fake.password:
                raise NoResponse("[AUTHENTICATIONFAILED] Invalid credentials")
            self.authenticated = True
        elif not self.authenticated:
            raise BadCommand("Not authenticated")
        else:
            handler = getattr(self, "cmd_" + command.decode().lower().replace("-", "_"), None)
            if handler is None:
                raise BadCommand(f"Unknown command {command.decode()}")
            required = {b"MOVE": "MOVE", b"NAMESPACE": "NAMESPACE", b"UNSELECT": "UNSELECT",
                        b"ID": "ID", b"ENABLE": "ENABLE"}.get(command)
            if required and required not in caps:
                raise BadCommand(f"Unknown command {command.decode()}")
            text = handler(args)
            self.send(tag + b" OK " + (text or command + b" completed"))
            return False
        self.send(tag + b" OK " + command + b" completed")
        return False

    def folder_name(self, token: bytes) -> str:
        return self.store.key(token.decode("ascii"))

    def require_selected(self) -> Folder:
        if self.selected is None:
            raise BadCommand("No mailbox selected")
        box = self.store.get(self.selected)
        if box is None:
            raise BadCommand("Mailbox vanished")
        return box

    def require_writable(self) -> None:
        if self.readonly:
            raise NoResponse("[READ-ONLY] Mailbox is open read-only (EXAMINE)")

    # --- mailbox commands -------------------------------------------------

    def cmd_id(self, args):
        self.send(b'* ID ("name" "fake-imap")')

    def cmd_enable(self, args):
        self.send(b"* ENABLED")

    def cmd_namespace(self, args):
        self.send(b'* NAMESPACE (("" "/")) NIL NIL')

    def _list(self, args, subscribed_only: bool):
        reference, pattern = (a.decode("ascii") for a in args[:2])
        regex = re.compile(
            "^" + "".join(".*" if c == "*" else "[^/]*" if c == "%" else re.escape(c)
                          for c in reference + pattern) + "$",
            re.IGNORECASE,
        )
        verb = b"LSUB" if subscribed_only else b"LIST"
        with self.store.lock:
            for box in self.store.folders.values():
                if not regex.match(box.name) or (subscribed_only and not box.subscribed):
                    continue
                attrs = ["\\HasNoChildren"]
                if box.special_use and "SPECIAL-USE" in self.fake.capabilities and not subscribed_only:
                    attrs.append(box.special_use)
                self.send(b"* " + verb + b" (" + " ".join(attrs).encode() + b') "/" ' + quote(box.name))

    def cmd_list(self, args):
        self._list(args, subscribed_only=False)

    def cmd_lsub(self, args):
        self._list(args, subscribed_only=True)

    def cmd_create(self, args):
        name = self.folder_name(args[0])
        with self.store.lock:
            if self.store.get(name):
                raise NoResponse("[ALREADYEXISTS] Mailbox already exists")
            self.store.add_folder(name).subscribed = False

    def cmd_subscribe(self, args):
        box = self.store.get(self.folder_name(args[0]))
        if box is None:
            raise NoResponse("[NONEXISTENT] No such mailbox")
        box.subscribed = True

    def cmd_unsubscribe(self, args):
        box = self.store.get(self.folder_name(args[0]))
        if box is not None:
            box.subscribed = False

    def cmd_status(self, args):
        box = self.store.get(self.folder_name(args[0]))
        if box is None:
            raise NoResponse("[NONEXISTENT] No such mailbox")
        with self.store.lock:
            values = {
                b"MESSAGES": len(box.messages),
                b"UNSEEN": sum("\\Seen" not in m.flags for m in box.messages.values()),
                b"RECENT": 0,
                b"UIDNEXT": box.uidnext,
                b"UIDVALIDITY": box.uidvalidity,
            }
        items = [i.upper() for i in args[1]]
        body = b" ".join(b"%s %d" % (i, values[i]) for i in items)
        self.send(b"* STATUS " + quote(box.name) + b" (" + body + b")")

    def _open(self, args, readonly: bool):
        self.selected = None
        box = self.store.get(self.folder_name(args[0]))
        if box is None:
            raise NoResponse("[NONEXISTENT] No such mailbox")
        with self.store.lock:
            self.send(b"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)")
            self.send(b"* OK [PERMANENTFLAGS (" + (b"" if readonly else b"\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*") + b")] Flags")
            self.send(b"* %d EXISTS" % len(box.messages))
            self.send(b"* 0 RECENT")
            self.send(b"* OK [UIDVALIDITY %d] UIDs valid" % box.uidvalidity)
            self.send(b"* OK [UIDNEXT %d] Predicted next UID" % box.uidnext)
        self.selected, self.readonly = box.name, readonly
        return b"[READ-ONLY] EXAMINE completed" if readonly else b"[READ-WRITE] SELECT completed"

    def cmd_select(self, args):
        return self._open(args, readonly=False)

    def cmd_examine(self, args):
        return self._open(args, readonly=True)

    def cmd_close(self, args):
        box = self.require_selected()
        if not self.readonly:
            self._expunge(box, None, announce=False)
        self.selected = None

    def cmd_unselect(self, args):
        self.require_selected()
        self.selected = None

    def cmd_append(self, args):
        box = self.store.get(self.folder_name(args[0]))
        if box is None:
            raise NoResponse("[TRYCREATE] No such mailbox")
        flags = next((a for a in args[1:-1] if isinstance(a, list)), [])
        uid = self.store.add_message(box.name, bytes(args[-1]), [f.decode() for f in flags])
        if "UIDPLUS" in self.fake.capabilities:
            return b"[APPENDUID %d %d] APPEND completed" % (box.uidvalidity, uid)
        return None

    # --- message commands -------------------------------------------------

    def cmd_uid(self, args):
        sub = args[0].upper()
        if sub not in (b"FETCH", b"STORE", b"COPY", b"MOVE", b"SEARCH", b"EXPUNGE"):
            raise BadCommand("Unknown UID command")
        if sub == b"MOVE" and "MOVE" not in self.fake.capabilities:
            raise BadCommand("Unknown command UID MOVE")
        if sub == b"EXPUNGE" and "UIDPLUS" not in self.fake.capabilities:
            raise BadCommand("Unknown command UID EXPUNGE")
        getattr(self, "msg_" + sub.decode().lower())(args[1:], uid_mode=True)
        return b"UID " + sub + b" completed"

    def cmd_fetch(self, args):
        self.msg_fetch(args, uid_mode=False)

    def cmd_store(self, args):
        self.msg_store(args, uid_mode=False)

    def cmd_copy(self, args):
        self.msg_copy(args, uid_mode=False)

    def cmd_move(self, args):
        self.msg_move(args, uid_mode=False)

    def cmd_search(self, args):
        self.msg_search(args, uid_mode=False)

    def cmd_expunge(self, args):
        box = self.require_selected()
        self.require_writable()
        self._expunge(box, None, announce=True)

    def _targets(self, box: Folder, spec: bytes, uid_mode: bool) -> list[tuple[int, int]]:
        """(seq, uid) pairs named by a UID set or a sequence set."""
        uids = box.sorted_uids()
        seq_of = {uid: i + 1 for i, uid in enumerate(uids)}
        if uid_mode:
            return [(seq_of[u], u) for u in resolve_set(spec, uids)]
        return [(s, uids[s - 1]) for s in resolve_set(spec, list(range(1, len(uids) + 1)))]

    def msg_fetch(self, args, uid_mode: bool):
        box = self.require_selected()
        items = args[1] if isinstance(args[1], list) else [args[1]]
        macros = {b"FAST": [b"FLAGS", b"INTERNALDATE", b"RFC822.SIZE"],
                  b"ALL": [b"FLAGS", b"INTERNALDATE", b"RFC822.SIZE"]}
        if len(items) == 1 and items[0].upper() in macros:
            items = macros[items[0].upper()]
        gmail = "X-GM-EXT-1" in self.fake.capabilities
        with self.store.lock:
            for seq, uid in self._targets(box, args[0], uid_mode):
                msg = box.messages[uid]
                parts: list[bytes] = []
                marks_seen = False
                want_flags = False
                for item in items:
                    upper = item.upper()
                    m = _BODY_ITEM.match(item)
                    if upper == b"UID":
                        continue
                    if upper == b"FLAGS":
                        want_flags = True
                    elif upper == b"INTERNALDATE":
                        parts.append(b"INTERNALDATE " + imap_datetime(msg.internaldate))
                    elif upper == b"RFC822.SIZE":
                        parts.append(b"RFC822.SIZE %d" % len(msg.raw))
                    elif upper == b"RFC822":
                        parts.append(b"RFC822 " + literal(msg.raw))
                        marks_seen = True
                    elif upper == b"RFC822.HEADER":
                        parts.append(b"RFC822.HEADER " + literal(split_header(msg.raw)[0]))
                    elif upper == b"RFC822.TEXT":
                        parts.append(b"RFC822.TEXT " + literal(split_header(msg.raw)[1]))
                        marks_seen = True
                    elif m:
                        section = m.group(2).upper()
                        data = self._section(msg, section)
                        if m.group(3) is not None:
                            start = int(m.group(3))
                            length = int(m.group(4)) if m.group(4) else len(data)
                            data = data[start:start + length]
                        key = b"BODY[" + section + b"]" + (b"<%s>" % m.group(3) if m.group(3) else b"")
                        parts.append(key + b" " + literal(data))
                        marks_seen = marks_seen or m.group(1).upper() == b"BODY"
                    elif gmail and upper == b"X-GM-MSGID":
                        parts.append(b"X-GM-MSGID %d" % msg.gm_msgid)
                    elif gmail and upper == b"X-GM-THRID":
                        parts.append(b"X-GM-THRID %d" % msg.gm_thrid)
                    elif gmail and upper == b"X-GM-LABELS":
                        parts.append(b"X-GM-LABELS ()")
                    else:
                        raise BadCommand(f"unsupported fetch item {item!r}")
                # A real server marks the message read as a side effect of
                # handing out its body, and tells the client in the same
                # response, unless the folder was opened with EXAMINE.
                if marks_seen and not self.readonly and "\\Seen" not in msg.flags:
                    msg.flags.add("\\Seen")
                    want_flags = True
                if want_flags:
                    parts.insert(0, b"FLAGS (" + " ".join(sorted(msg.flags)).encode() + b")")
                if uid_mode or b"UID" in [i.upper() for i in items]:
                    parts.insert(0, b"UID %d" % uid)
                self.send(b"* %d FETCH (" % seq + b" ".join(parts) + b")")

    def _section(self, msg: StoredMessage, section: bytes) -> bytes:
        header, text = split_header(msg.raw)
        if section == b"":
            return msg.raw
        if section == b"HEADER":
            return header
        if section == b"TEXT":
            return text
        m = re.fullmatch(rb"HEADER\.FIELDS(\.NOT)? \((.*)\)", section)
        if m:
            names = [n.decode() for n in m.group(2).split()]
            return header_fields(header, names, negate=bool(m.group(1)))
        if re.fullmatch(rb"\d+(\.\d+)*", section):
            part: Any = email.message_from_bytes(msg.raw, policy=policy.compat32)
            for index in (int(n) for n in section.split(b".")):
                if part.is_multipart():
                    part = part.get_payload()[index - 1]
                elif index != 1:
                    return b""
            return to_crlf(split_header(to_crlf(part.as_bytes()))[1]) if part.is_multipart() else \
                to_crlf(part.get_payload(decode=False).encode("ascii", "replace"))
        raise BadCommand(f"unsupported section {section!r}")

    def msg_store(self, args, uid_mode: bool):
        box = self.require_selected()
        self.require_writable()
        spec, mode, flag_tok = args[0], args[1].upper(), args[2]
        flags = {normalise_flag(f.decode()) for f in (flag_tok if isinstance(flag_tok, list) else [flag_tok])}
        silent = mode.endswith(b".SILENT")
        mode = mode.removesuffix(b".SILENT")
        with self.store.lock:
            for seq, uid in self._targets(box, spec, uid_mode):
                msg = box.messages[uid]
                if mode == b"+FLAGS":
                    msg.flags |= flags
                elif mode == b"-FLAGS":
                    msg.flags -= flags
                elif mode == b"FLAGS":
                    msg.flags = set(flags)
                else:
                    raise BadCommand("bad STORE mode")
                if not silent:
                    uid_part = b"UID %d " % uid if uid_mode else b""
                    self.send(b"* %d FETCH (%sFLAGS (%s))" % (seq, uid_part, " ".join(sorted(msg.flags)).encode()))

    def _copy_into(self, box: Folder, targets, dest_token: bytes) -> bytes | None:
        dest = self.store.get(self.folder_name(dest_token))
        if dest is None:
            raise NoResponse("[TRYCREATE] No such mailbox")
        new_uids = []
        for _, uid in targets:
            src = box.messages[uid]
            new = self.store.add_message(dest.name, src.raw, src.flags, src.internaldate, src.gm_thrid)
            new_uids.append(new)
        if "UIDPLUS" in self.fake.capabilities and targets:
            return b"[COPYUID %d %s %s]" % (
                dest.uidvalidity,
                ",".join(str(u) for _, u in targets).encode(),
                ",".join(str(u) for u in new_uids).encode(),
            )
        return None

    def msg_copy(self, args, uid_mode: bool):
        # COPY from an EXAMINEd folder is legal: it changes only the destination.
        box = self.require_selected()
        with self.store.lock:
            code = self._copy_into(box, self._targets(box, args[0], uid_mode), args[1])
        if code:
            self.send(b"* OK " + code + b" Copied")

    def msg_move(self, args, uid_mode: bool):
        box = self.require_selected()
        self.require_writable()
        with self.store.lock:
            targets = self._targets(box, args[0], uid_mode)
            code = self._copy_into(box, targets, args[1])
            if code:
                self.send(b"* OK " + code + b" Moved")
            for seq, uid in sorted(targets, reverse=True):
                del box.messages[uid]
                self.send(b"* %d EXPUNGE" % seq)

    def msg_expunge(self, args, uid_mode: bool):
        box = self.require_selected()
        self.require_writable()
        with self.store.lock:
            only = {uid for _, uid in self._targets(box, args[0], uid_mode=True)}
            self._expunge(box, only, announce=True)

    def _expunge(self, box: Folder, only: set[int] | None, announce: bool) -> None:
        with self.store.lock:
            uids = box.sorted_uids()
            doomed = [(i + 1, u) for i, u in enumerate(uids)
                      if "\\Deleted" in box.messages[u].flags and (only is None or u in only)]
            for seq, uid in reversed(doomed):
                del box.messages[uid]
                if announce:
                    self.send(b"* %d EXPUNGE" % seq)

    def msg_search(self, args, uid_mode: bool):
        box = self.require_selected()
        charset = "us-ascii"
        if args and isinstance(args[0], bytes) and args[0].upper() == b"CHARSET":
            charset = args[1].decode()
            if charset.upper() not in ("UTF-8", "US-ASCII"):
                raise NoResponse("[BADCHARSET (UTF-8 US-ASCII)] Unsupported charset")
            args = args[2:]
        with self.store.lock:
            uids = box.sorted_uids()
            pred = SearchParser(args, charset, "X-GM-EXT-1" in self.fake.capabilities, uids).parse()
            hits = []
            for seq, uid in enumerate(uids, start=1):
                msg = box.messages[uid]
                parsed = email.message_from_bytes(msg.raw, policy=policy.default)
                if pred(uid, seq, msg, parsed):
                    hits.append(uid if uid_mode else seq)
        self.send(b"* SEARCH" + b"".join(b" %d" % h for h in hits))


# -----------------------------------------------------------------------------
# Server
# -----------------------------------------------------------------------------

class _TCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
    fake: "FakeImapServer"


class FakeImapServer:
    """Owns the listening socket, the shared store and the settings tests change."""

    def __init__(self, user: str = "test@example.com", password: str = "secret",
                 capabilities=DEFAULT_CAPABILITIES, store: MailStore | None = None):
        self.user, self.password = user, password
        self.capabilities = list(capabilities)
        self.store = store or MailStore()
        self.log: list[str] = []            # command lines, literals elided
        self.login_attempts: list[str] = []
        self._server: _TCPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        assert self._server is not None
        return self._server.server_address[1]

    def set_capabilities(self, *, add=(), remove=()) -> None:
        self.capabilities = [c for c in self.capabilities if c not in remove] + \
            [c for c in add if c not in self.capabilities]

    def commands(self, verb: str) -> list[str]:
        """Logged command lines whose command (after tag and UID) is `verb`."""
        out = []
        for line in self.log:
            words = line.split(" ")
            rest = words[2:] if len(words) > 2 and words[1].upper() == "UID" else words[1:]
            if rest and rest[0].upper() == verb.upper():
                out.append(line)
        return out

    def start(self) -> "FakeImapServer":
        self._server = _TCPServer(("127.0.0.1", 0), Session)
        self._server.fake = self
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
