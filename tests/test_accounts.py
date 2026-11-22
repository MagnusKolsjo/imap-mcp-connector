# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""Tests for accounts: the config file, validation and secret resolution."""

from __future__ import annotations

import json
import os
import stat

import keyring
import pytest
from keyring.backend import KeyringBackend

import accounts
from accounts import Account, ConfigError, Permissions, SaveSent, SecretError, SendMode


def make_account(**overrides) -> Account:
    values = dict(
        id="work",
        display_name="Work",
        email="me@example.com",
        imap_host="imap.example.com",
        smtp_host="smtp.example.com",
    )
    values.update(overrides)
    return Account(**values)


# -----------------------------------------------------------------------------
# Config file
# -----------------------------------------------------------------------------

def test_round_trip(config_file):
    original = make_account(
        imap_port=143, imap_security="starttls", username="login-name", smtp_port=587,
        smtp_security="starttls", sent_folder="Skickat", save_sent=SaveSent.NEVER,
        permissions=Permissions(organise=True, send_mode=SendMode.DRAFTS),
    )
    accounts.save_account(original)
    accounts.save_account(make_account(id="private", display_name="Private"))
    loaded = accounts.load_accounts()
    assert set(loaded) == {"work", "private"}
    assert loaded["work"] == original
    assert loaded["work"].login == "login-name"
    assert loaded["work"].smtp_login == "login-name"
    raw = json.loads(config_file.read_text(encoding="utf-8"))
    assert raw["version"] == 1
    assert raw["accounts"][1]["permissions"]["send_mode"] == "drafts"
    assert "password" not in config_file.read_text(encoding="utf-8").lower()


def test_delete_account(config_file):
    accounts.save_account(make_account())
    accounts.delete_account("work")
    assert accounts.load_accounts() == {}


def test_file_mode_is_0600(config_file):
    accounts.save_account(make_account())
    assert stat.S_IMODE(config_file.stat().st_mode) == 0o600


def test_atomic_write_leaves_no_temp_files(config_file):
    for i in range(3):
        accounts.save_account(make_account(id=f"a{i}"))
    assert [p.name for p in config_file.parent.iterdir()] == ["accounts.json"]


def test_failed_write_cleans_up_and_keeps_old_file(config_file, monkeypatch):
    accounts.save_account(make_account())
    before = config_file.read_bytes()

    def boom(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(accounts.os, "replace", boom)
    with pytest.raises(OSError):
        accounts.save_account(make_account(id="other"))
    assert config_file.read_bytes() == before
    assert [p.name for p in config_file.parent.iterdir()] == ["accounts.json"]


def test_reload_after_external_change(config_file):
    accounts.save_account(make_account())
    assert accounts.get_account("work").display_name == "Work"

    data = json.loads(config_file.read_text(encoding="utf-8"))
    data["accounts"][0]["display_name"] = "Edited elsewhere"
    config_file.write_text(json.dumps(data), encoding="utf-8")
    # Filesystems with coarse timestamps could leave the mtime unchanged
    # within one test; push it forward so the test checks the logic only.
    st = config_file.stat()
    os.utime(config_file, (st.st_atime, st.st_mtime + 5))

    assert accounts.get_account("work").display_name == "Edited elsewhere"


def test_missing_file_means_no_accounts(config_file):
    assert accounts.load_accounts() == {}
    with pytest.raises(ConfigError, match="none configured"):
        accounts.get_account("nope")


def test_malformed_file_raises_config_error(config_file):
    config_file.parent.mkdir(parents=True)
    config_file.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigError):
        accounts.load_accounts()


def test_unknown_keys_are_tolerated(config_file):
    data = make_account().to_json() | {"future_option": True}
    config_file.parent.mkdir(parents=True)
    config_file.write_text(json.dumps({"version": 1, "accounts": [data]}), encoding="utf-8")
    assert accounts.get_account("work").email == "me@example.com"


@pytest.mark.parametrize("bad_id", ["", "has space", "dash-ed", "åäö", "x" * 41, "../etc"])
def test_invalid_id_rejected(config_file, bad_id):
    with pytest.raises(ConfigError):
        accounts.save_account(make_account(id=bad_id))
    with pytest.raises(ConfigError):
        Account.from_json(make_account(id="ok").to_json() | {"id": bad_id})


def test_validate_account_codes():
    assert accounts.validate_account(make_account()) == []
    bad = make_account(
        display_name="  ", email="no-at-sign", imap_host="", imap_port=0, imap_security="tls",
        smtp_host="", smtp_security="plain", permissions=Permissions(send_mode=SendMode.SEND),
    )
    assert set(accounts.validate_account(bad)) == {
        "display_name", "email", "imap_host", "imap_port", "imap_security", "smtp_security", "smtp_host",
    }
    assert accounts.validate_account(make_account(smtp_port=70000)) == ["smtp_port"]


def test_new_account_id():
    assert accounts.new_account_id("Min Jobbmejl!", set()) == "min_jobbmejl"
    assert accounts.new_account_id("Work", {"work", "work_2"}) == "work_3"
    assert accounts.new_account_id("åäö", set()) == "account"


# -----------------------------------------------------------------------------
# Secrets
# -----------------------------------------------------------------------------

@pytest.fixture
def clean_env(monkeypatch):
    for name in list(os.environ):
        if name.startswith("IMAP_SECRET_"):
            monkeypatch.delenv(name)
    return monkeypatch


def test_secret_from_env(clean_env):
    clean_env.setenv("IMAP_SECRET_WORK", "from-env")
    assert accounts.get_secret("work", "imap") == "from-env"
    assert accounts.has_secret("work")


def test_secret_from_file(clean_env, tmp_path):
    secret_file = tmp_path / "pw"
    secret_file.write_text("from-file\n", encoding="utf-8")
    clean_env.setenv("IMAP_SECRET_WORK_FILE", str(secret_file))
    assert accounts.get_secret("work") == "from-file"


def test_secret_file_unreadable(clean_env, tmp_path):
    clean_env.setenv("IMAP_SECRET_WORK_FILE", str(tmp_path / "missing"))
    with pytest.raises(SecretError, match="IMAP_SECRET_WORK_FILE"):
        accounts.get_secret("work")


def test_env_takes_precedence_over_keyring(clean_env, isolated_keyring):
    accounts.set_secret("work", "imap", "from-keyring")
    assert accounts.get_secret("work") == "from-keyring"
    clean_env.setenv("IMAP_SECRET_WORK", "from-env")
    assert accounts.get_secret("work") == "from-env"


def test_smtp_secret_falls_back_to_imap(clean_env):
    clean_env.setenv("IMAP_SECRET_WORK", "shared")
    assert accounts.get_secret("work", "smtp") == "shared"
    # has_secret only counts an explicitly stored SMTP secret.
    assert not accounts.has_secret("work", "smtp")
    clean_env.setenv("IMAP_SECRET_WORK_SMTP", "separate")
    assert accounts.get_secret("work", "smtp") == "separate"
    assert accounts.get_secret("work", "imap") == "shared"
    assert accounts.has_secret("work", "smtp")


def test_missing_secret_is_explained(clean_env):
    with pytest.raises(SecretError, match="IMAP_SECRET_WORK"):
        accounts.get_secret("work")
    assert not accounts.has_secret("work")


def test_keyring_round_trip(clean_env, isolated_keyring):
    assert accounts.keyring_available()
    accounts.set_secret("work", "smtp", "kr-smtp")
    assert isolated_keyring.store[(accounts.KEYRING_SERVICE, "work:smtp")] == "kr-smtp"
    assert accounts.get_secret("work", "smtp") == "kr-smtp"
    assert accounts.has_secret("work", "smtp")
    accounts.delete_secret("work", "smtp")
    assert not accounts.has_secret("work", "smtp")


class PlaintextKeyring(KeyringBackend):
    """Stands in for keyrings.alt.file.PlaintextKeyring without the dependency."""

    priority = 1

    def __init__(self):
        super().__init__()
        self.written: list[str] = []

    def get_password(self, service, username):
        return "leaked"

    def set_password(self, service, username, password):
        self.written.append(password)

    def delete_password(self, service, username):
        pass


class LowPriorityKeyring(PlaintextKeyring):
    """A backend keyring itself would not choose (priority <= 0)."""

    priority = 0


@pytest.mark.parametrize("backend_cls", [PlaintextKeyring, LowPriorityKeyring])
def test_insecure_keyring_is_refused(clean_env, backend_cls):
    backend = backend_cls()
    keyring.set_keyring(backend)  # the autouse fixture restores the previous one
    assert not accounts.keyring_available()
    with pytest.raises(SecretError, match="No secure system keychain"):
        accounts.set_secret("work", "imap", "secret")
    assert backend.written == []
    # Its stored value must not be used either.
    with pytest.raises(SecretError, match="no usable keychain"):
        accounts.get_secret("work")


def test_fail_keyring_is_refused(clean_env):
    from keyring.backends import fail

    keyring.set_keyring(fail.Keyring())
    assert not accounts.keyring_available()
