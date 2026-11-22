# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""Account configuration and secret storage.

Accounts live in one JSON file that never contains a password. Secrets are
resolved through exactly two providers:

    keyring   the operating system keychain (macOS Keychain, Windows
              Credential Locker, Secret Service on Linux). Used by the admin
              UI on a desktop.
    env/file  IMAP_SECRET_<ID> or IMAP_SECRET_<ID>_FILE, for headless
              installations where no keychain exists. The _FILE variant
              reads a file that only the service user can read.

A plaintext keyring backend is never accepted. If no usable keychain exists
and no env/file secret is set, resolving the secret fails with an
explanation instead of silently degrading.

The MCP server keeps running while the admin UI edits the file, so
`load_accounts()` re-reads the file whenever its modification time changes.
Writes are atomic (temporary file + os.replace) and the file is created
with mode 0600.

Entry points:
    Account, Permissions, SendMode, SaveSent
    config_path() -> Path
    load_accounts() -> dict[str, Account]
    get_account(account_id) -> Account
    save_account(account), delete_account(account_id)
    get_secret(account_id, kind) / set_secret / delete_secret / has_secret
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

APP_NAME = "imap-mcp-connector"
KEYRING_SERVICE = "imap-mcp-connector"

# Account ids end up in env variable names (IMAP_SECRET_<ID>), so they are
# restricted to characters that are valid there and need no escaping.
ACCOUNT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_]{1,40}$")


class ConfigError(Exception):
    """Configuration is missing, malformed or refers to an unknown account."""


class SecretError(Exception):
    """A password could not be stored or resolved."""


class SendMode(str, Enum):
    """How far the AI tool may go when composing mail for an account."""

    OFF = "off"          # no composing tools at all
    DRAFTS = "drafts"    # may only save drafts; a human sends them
    SEND = "send"        # may send directly through SMTP


class SaveSent(str, Enum):
    """Whether a copy of sent mail is appended to the Sent folder."""

    AUTO = "auto"        # skip when the server files sent mail itself (Gmail)
    ALWAYS = "always"
    NEVER = "never"


class ReadMarking(str, Enum):
    """Whether opening a message marks it as read.

    Applies only when the user opens a message in the mailbox panel. The AI
    tool's own reading never marks anything as read, whatever this says.
    """

    NEVER = "never"            # nothing is ever marked read by this connector
    USER_OPEN = "user_open"    # mark read when the user opens it in the panel


class SendApproval(str, Enum):
    """Who approves each message when send_mode is SEND.

    The approval is asked for outside the AI client (a native macOS dialog,
    or the client's own user prompt where that is unavailable), so a model
    cannot answer it on the user's behalf.
    """

    ASK = "ask"                      # approve every message
    ASK_OR_WINDOW = "ask_or_window"  # approve, or allow for a while
    NEVER = "never"                  # send without asking


@dataclass
class Permissions:
    """What the MCP tools may do with an account beyond reading."""

    organise: bool = False          # flags, move, copy, trash, create folders
    send_mode: SendMode = SendMode.OFF
    send_approval: SendApproval = SendApproval.ASK
    # Saving attachments is the one exception to "no mail on disk", so it is
    # off until the user turns it on for the account.
    save_attachments: bool = False


@dataclass
class Account:
    """One mailbox. Hostnames and ports for IMAP and SMTP, never a password."""

    id: str
    display_name: str
    email: str
    imap_host: str
    imap_port: int = 993
    imap_security: str = "ssl"      # ssl | starttls
    username: str = ""
    smtp_host: str = ""
    smtp_port: int = 465
    smtp_security: str = "ssl"      # ssl | starttls
    smtp_username: str = ""         # empty means same as username
    sent_folder: str = ""           # empty means detect via SPECIAL-USE
    drafts_folder: str = ""
    trash_folder: str = ""
    save_sent: SaveSent = SaveSent.AUTO
    read_marking: ReadMarking = ReadMarking.NEVER
    # Format for new messages; replies always follow the message they answer.
    new_mail_format: str = "html"   # html | text
    permissions: Permissions = field(default_factory=Permissions)

    @property
    def login(self) -> str:
        return self.username or self.email

    @property
    def smtp_login(self) -> str:
        return self.smtp_username or self.login

    @property
    def smtp_configured(self) -> bool:
        return bool(self.smtp_host)

    def to_json(self) -> dict[str, Any]:
        data = asdict(self)
        data["save_sent"] = self.save_sent.value
        data["read_marking"] = self.read_marking.value
        data["permissions"]["send_mode"] = self.permissions.send_mode.value
        data["permissions"]["send_approval"] = self.permissions.send_approval.value
        return data

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "Account":
        data = dict(data)
        perms = data.pop("permissions", {}) or {}
        known = {f for f in cls.__dataclass_fields__}  # tolerate unknown keys
        clean = {k: v for k, v in data.items() if k in known}
        account = cls(**clean)
        account.imap_port = int(account.imap_port)
        account.smtp_port = int(account.smtp_port)
        account.save_sent = SaveSent(data.get("save_sent", "auto"))
        account.read_marking = ReadMarking(data.get("read_marking", "never"))
        organise = perms.get("organise", False)
        save_attachments = perms.get("save_attachments", False)
        for name, value in (("organise", organise), ("save_attachments", save_attachments)):
            if not isinstance(value, bool):
                # A hand-edited "false" string must not grant the permission.
                raise ConfigError(f"permissions.{name} must be true or false, got {value!r}")
        account.permissions = Permissions(
            organise=organise,
            save_attachments=save_attachments,
            send_mode=SendMode(perms.get("send_mode", "off")),
            send_approval=SendApproval(perms.get("send_approval", "ask")),
        )
        validate_account(account)
        return account


def validate_account(account: Account) -> list[str]:
    """Return a list of problem codes; raise ConfigError for unusable ids.

    The codes are translation keys used by the admin UI, so the same
    validation serves both the UI and the server.
    """
    if not ACCOUNT_ID_PATTERN.match(account.id or ""):
        raise ConfigError(f"Invalid account id: {account.id!r}")
    if account.id.lower().endswith("_smtp"):
        # IMAP_SECRET_<ID>_SMTP is the SMTP secret of account <ID>; an id
        # ending in _smtp would collide with that name.
        raise ConfigError(f"Account id {account.id!r} may not end in '_smtp'.")
    problems = []
    if not account.display_name.strip():
        problems.append("display_name")
    if "@" not in account.email:
        problems.append("email")
    if not account.imap_host.strip():
        problems.append("imap_host")
    if not 1 <= account.imap_port <= 65535:
        problems.append("imap_port")
    if account.imap_security not in ("ssl", "starttls"):
        problems.append("imap_security")
    if account.smtp_host and not 1 <= account.smtp_port <= 65535:
        problems.append("smtp_port")
    if account.smtp_security not in ("ssl", "starttls"):
        problems.append("smtp_security")
    if account.new_mail_format not in ("html", "text"):
        problems.append("new_mail_format")
    if account.permissions.send_mode is SendMode.SEND and not account.smtp_host:
        problems.append("smtp_host")
    return problems


# -----------------------------------------------------------------------------
# Config file
# -----------------------------------------------------------------------------

def config_path() -> Path:
    """Location of accounts.json; IMAP_CONNECTOR_CONFIG overrides it."""
    override = os.getenv("IMAP_CONNECTOR_CONFIG", "").strip()
    if override:
        return Path(override).expanduser()
    from platformdirs import user_config_dir

    return Path(user_config_dir(APP_NAME, appauthor=False)) / "accounts.json"


# Re-entrant: save/delete read the current file and write it under one lock.
_lock = threading.RLock()
_cache: tuple[Path, float, dict[str, Account]] | None = None
_load_errors: list[str] = []
_settings: dict[str, Any] = {}


def load_accounts() -> dict[str, Account]:
    """Return all accounts, re-reading the file when it has changed."""
    global _cache
    path = config_path()
    with _lock:
        try:
            mtime = path.stat().st_mtime
        except FileNotFoundError:
            _cache = (path, 0.0, {})
            _settings.clear()
            return {}
        if _cache and _cache[0] == path and _cache[1] == mtime:
            return dict(_cache[2])
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(f"Cannot read {path}: {exc}") from exc
        accounts = {}
        errors: list[str] = []
        # A broken entry is skipped and reported, so one hand-edited mistake
        # does not make every other account unusable.
        for index, item in enumerate(raw.get("accounts", [])):
            try:
                account = Account.from_json(item)
            except (ConfigError, TypeError, ValueError, KeyError) as exc:
                label = item.get("id", f"#{index + 1}") if isinstance(item, dict) else f"#{index + 1}"
                errors.append(f"Account {label} in {path.name} is invalid and was skipped: {exc}")
                continue
            if account.id.lower() in {a.lower() for a in accounts}:
                errors.append(f"Account {account.id} duplicates another id (ids are case-insensitive) and was skipped.")
                continue
            accounts[account.id] = account
        _load_errors[:] = errors
        settings = raw.get("settings", {})
        _settings.clear()
        _settings.update(settings if isinstance(settings, dict) else {})
        _cache = (path, mtime, accounts)
        return dict(accounts)


def get_settings() -> dict[str, Any]:
    """Settings shared by all accounts (currently the attachments folder)."""
    load_accounts()
    return dict(_settings)


def save_settings(**changes: Any) -> None:
    with _lock:
        accounts = load_accounts()
        settings = {**_settings, **changes}
        _write_accounts(accounts, settings)


def default_attachments_root() -> Path:
    from platformdirs import user_documents_dir

    return Path(user_documents_dir()) / "IMAP MCP-brygga" / "Bilagor"


def attachments_root() -> Path:
    """Folder that saved attachments go under: <root>/<account>/<year>/<month>/."""
    configured = str(get_settings().get("attachments_root", "") or "").strip()
    return Path(configured).expanduser() if configured else default_attachments_root()


def knowledge_dir() -> Path:
    """Where imported knowledge bases are kept: one Markdown file per account."""
    return config_path().parent / "knowledge"


def knowledge_path(account_id: str) -> Path:
    if not ACCOUNT_ID_PATTERN.match(account_id or ""):
        raise ConfigError(f"Invalid account id: {account_id!r}")
    return knowledge_dir() / f"{account_id}.md"


def load_errors() -> list[str]:
    """Problems found in the config file during the last load_accounts()."""
    return list(_load_errors)


def get_account(account_id: str) -> Account:
    accounts = load_accounts()
    if account_id not in accounts:
        known = ", ".join(sorted(accounts)) or "none configured"
        raise ConfigError(f"Unknown account {account_id!r}. Known accounts: {known}.")
    return accounts[account_id]


def _write_accounts(accounts: dict[str, Account], settings: dict[str, Any] | None = None) -> None:
    global _cache
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = {
        "version": 1,
        "settings": dict(_settings if settings is None else settings),
        "accounts": [a.to_json() for a in sorted(accounts.values(), key=lambda a: a.id)],
    }
    # Atomic replace: a reader in the MCP server never sees a half-written file.
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".accounts-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    _cache = None


def save_account(account: Account) -> None:
    validate_account(account)
    with _lock:
        accounts = load_accounts()
        # Ids map onto env variable names in upper case, so Work and work
        # would share IMAP_SECRET_WORK.
        clash = [a for a in accounts if a.lower() == account.id.lower() and a != account.id]
        if clash:
            raise ConfigError(f"Account id {account.id!r} differs only in case from {clash[0]!r}.")
        accounts[account.id] = account
        _write_accounts(accounts)


def delete_account(account_id: str) -> None:
    with _lock:
        accounts = load_accounts()
        accounts.pop(account_id, None)
        _write_accounts(accounts)
    for kind in ("imap", "smtp"):
        try:
            delete_secret(account_id, kind)
        except SecretError:
            pass
    try:
        knowledge_path(account_id).unlink()
    except (FileNotFoundError, ConfigError):
        pass


def new_account_id(display_name: str, existing: set[str]) -> str:
    """Derive a readable, unique id from a display name."""
    base = re.sub(r"[^A-Za-z0-9]+", "_", display_name).strip("_").lower()[:30] or "account"
    if base.endswith("_smtp"):
        base = base[: -len("_smtp")] + "_mail"
    candidate, n = base, 2
    while candidate in existing:
        candidate, n = f"{base}_{n}", n + 1
    return candidate


# -----------------------------------------------------------------------------
# Secrets
# -----------------------------------------------------------------------------

def secret_env_name(account_id: str, kind: str = "imap") -> str:
    """Name of the environment variable that holds this account's secret."""
    # The SMTP secret falls back to the IMAP one in get_secret(), so the
    # plain name stays the IMAP secret for the common one-password case.
    suffix = "" if kind == "imap" else "_SMTP"
    return f"IMAP_SECRET_{account_id.upper()}{suffix}"


def _keyring_user(account_id: str, kind: str) -> str:
    return f"{account_id}:{kind}"


def _usable_keyring():
    """Return the keyring module if a secure backend is active, else None."""
    try:
        import keyring
        from keyring.backends import fail
    except ImportError:
        return None
    backend = keyring.get_keyring()
    name = type(backend).__module__ + "." + type(backend).__name__
    # keyrings.alt plaintext/encrypted-file backends store secrets in files
    # next to the config, which would defeat the point of a keychain.
    if isinstance(backend, fail.Keyring) or "keyrings.alt" in name or "PlaintextKeyring" in name:
        return None
    if getattr(backend, "priority", 1) <= 0:
        return None
    return keyring


def keyring_available() -> bool:
    return _usable_keyring() is not None


def _secret_from_env(account_id: str, kind: str) -> str | None:
    name = secret_env_name(account_id, kind)
    value = os.getenv(name)
    if value:
        return value
    file_name = os.getenv(name + "_FILE")
    if file_name:
        try:
            return Path(file_name).expanduser().read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise SecretError(f"Cannot read {name}_FILE: {exc}") from exc
    return None


def get_secret(account_id: str, kind: str = "imap") -> str:
    """Resolve the IMAP or SMTP password. SMTP falls back to the IMAP one."""
    value = _secret_from_env(account_id, kind)
    if value:
        return value
    kr = _usable_keyring()
    if kr is not None:
        try:
            value = kr.get_password(KEYRING_SERVICE, _keyring_user(account_id, kind))
        except Exception as exc:  # noqa: BLE001 - backend errors vary widely
            raise SecretError(f"Keychain lookup failed: {exc}") from exc
        if value:
            return value
    if kind == "smtp":
        return get_secret(account_id, "imap")
    where = "the system keychain" if kr is not None else "the environment (no usable keychain found)"
    raise SecretError(
        f"No password stored for account {account_id!r} in {where}. "
        f"Set it in the admin UI or via {secret_env_name(account_id, kind)}."
    )


def has_secret(account_id: str, kind: str = "imap") -> bool:
    try:
        if kind == "smtp":
            # Only an explicitly stored SMTP secret counts here.
            if _secret_from_env(account_id, "smtp"):
                return True
            kr = _usable_keyring()
            return bool(kr and kr.get_password(KEYRING_SERVICE, _keyring_user(account_id, "smtp")))
        get_secret(account_id, kind)
        return True
    except SecretError:
        return False
    except Exception:  # noqa: BLE001 - keyring backends raise their own types
        return False


def set_secret(account_id: str, kind: str, value: str) -> None:
    kr = _usable_keyring()
    if kr is None:
        raise SecretError(
            "No secure system keychain is available. "
            f"Set {secret_env_name(account_id, kind)} or {secret_env_name(account_id, kind)}_FILE instead."
        )
    try:
        kr.set_password(KEYRING_SERVICE, _keyring_user(account_id, kind), value)
    except Exception as exc:  # noqa: BLE001
        raise SecretError(f"Could not store the password in the keychain: {exc}") from exc


def delete_secret(account_id: str, kind: str) -> None:
    kr = _usable_keyring()
    if kr is None:
        return
    try:
        kr.delete_password(KEYRING_SERVICE, _keyring_user(account_id, kind))
    except Exception:  # noqa: BLE001 - missing entry is not an error here
        pass
