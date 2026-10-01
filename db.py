"""
Storage for saved Gmail accounts. Each account belongs to one admin (owner)
and is only visible to them.

Uses Postgres when DATABASE_URL is set (e.g. a free Neon database in
production), otherwise a local SQLite file (accounts.db) for development.
App passwords and Amazon PINs are encrypted with a key derived from SECRET_KEY
before they are written, so a leaked database alone doesn't expose them.
"""
import base64
import hashlib
import os
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
SQLITE_PATH = os.environ.get("SQLITE_PATH", "accounts.db")

_POSTGRES_SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id SERIAL PRIMARY KEY,
    owner TEXT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    app_password_enc TEXT NOT NULL,
    amazon_pin_enc TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""

_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner TEXT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    app_password_enc TEXT NOT NULL,
    amazon_pin_enc TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)
"""


class DuplicateAccountError(Exception):
    pass


@dataclass
class Account:
    id: int
    name: str
    email: str
    amazon_pin: str | None = None


def _fernet() -> Fernet:
    secret = os.environ.get("SECRET_KEY", "")
    if not secret:
        raise RuntimeError("Set the SECRET_KEY environment variable.")
    key = hashlib.sha256(b"otp-accounts:" + secret.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


@contextmanager
def _connect():
    if DATABASE_URL:
        import psycopg

        with psycopg.connect(DATABASE_URL) as conn:
            yield conn
    else:
        conn = sqlite3.connect(SQLITE_PATH)
        try:
            with conn:
                yield conn
        finally:
            conn.close()


def _sql(query: str) -> str:
    """Queries are written with %s placeholders; SQLite wants ?."""
    return query if DATABASE_URL else query.replace("%s", "?")


def _is_unique_violation(exc: Exception) -> bool:
    if isinstance(exc, sqlite3.IntegrityError):
        return True
    return type(exc).__name__ == "UniqueViolation"


def _encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def _decrypt(value: str) -> str:
    try:
        return _fernet().decrypt(value.encode()).decode()
    except InvalidToken as exc:
        raise RuntimeError(
            "Saved data can't be decrypted - was SECRET_KEY changed?"
        ) from exc


def init_db(default_owner: str) -> None:
    """Create or upgrade the table. Accounts saved before admins had separate
    lists are given to default_owner."""
    with _connect() as conn:
        if DATABASE_URL:
            conn.execute(_POSTGRES_SCHEMA)
            conn.execute("ALTER TABLE accounts ADD COLUMN IF NOT EXISTS amazon_pin_enc TEXT")
            conn.execute("ALTER TABLE accounts ADD COLUMN IF NOT EXISTS owner TEXT")
            # Emails used to be unique across everyone; now they're unique per admin.
            conn.execute("ALTER TABLE accounts DROP CONSTRAINT IF EXISTS accounts_email_key")
        else:
            conn.execute(_SQLITE_SCHEMA)
            columns = {row[1] for row in conn.execute("PRAGMA table_info(accounts)")}
            if "amazon_pin_enc" not in columns:
                conn.execute("ALTER TABLE accounts ADD COLUMN amazon_pin_enc TEXT")
            if "owner" not in columns:
                conn.execute("ALTER TABLE accounts ADD COLUMN owner TEXT")
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS accounts_owner_email ON accounts (owner, email)"
        )
        conn.execute(_sql("UPDATE accounts SET owner = %s WHERE owner IS NULL"), (default_owner,))


def list_accounts(owner: str) -> list[Account]:
    with _connect() as conn:
        rows = conn.execute(
            _sql(
                "SELECT id, name, email, amazon_pin_enc FROM accounts "
                "WHERE owner = %s ORDER BY lower(name)"
            ),
            (owner,),
        ).fetchall()
    return [Account(id, name, email, _decrypt(pin) if pin else None) for id, name, email, pin in rows]


def add_account(
    owner: str, name: str, email: str, app_password: str, amazon_pin: str | None = None
) -> None:
    try:
        with _connect() as conn:
            conn.execute(
                _sql(
                    "INSERT INTO accounts (owner, name, email, app_password_enc, amazon_pin_enc) "
                    "VALUES (%s, %s, %s, %s, %s)"
                ),
                (
                    owner,
                    name,
                    email,
                    _encrypt(app_password),
                    _encrypt(amazon_pin) if amazon_pin else None,
                ),
            )
    except Exception as exc:
        if _is_unique_violation(exc):
            raise DuplicateAccountError(f"{email} is already saved.") from exc
        raise


def get_credentials(owner: str, account_id: int) -> tuple[Account, str] | None:
    with _connect() as conn:
        row = conn.execute(
            _sql(
                "SELECT id, name, email, app_password_enc FROM accounts "
                "WHERE id = %s AND owner = %s"
            ),
            (account_id, owner),
        ).fetchone()
    if row is None:
        return None
    return Account(row[0], row[1], row[2]), _decrypt(row[3])


def update_account(owner: str, account_id: int, name: str, amazon_pin: str | None) -> None:
    with _connect() as conn:
        conn.execute(
            _sql(
                "UPDATE accounts SET name = %s, amazon_pin_enc = %s "
                "WHERE id = %s AND owner = %s"
            ),
            (name, _encrypt(amazon_pin) if amazon_pin else None, account_id, owner),
        )


def copy_account(owner: str, account_id: int, target_owner: str) -> str | None:
    """Copy one of owner's accounts into target_owner's list, or refresh the
    target's copy if it already has that email. Returns "added", "updated",
    or None if owner has no such account."""
    with _connect() as conn:
        row = conn.execute(
            _sql(
                "SELECT name, email, app_password_enc, amazon_pin_enc FROM accounts "
                "WHERE id = %s AND owner = %s"
            ),
            (account_id, owner),
        ).fetchone()
        if row is None:
            return None
        name, email, app_password_enc, amazon_pin_enc = row
        # Encrypted values are copied as-is: every row uses the same key.
        updated = conn.execute(
            _sql(
                "UPDATE accounts SET name = %s, app_password_enc = %s, amazon_pin_enc = %s "
                "WHERE owner = %s AND email = %s"
            ),
            (name, app_password_enc, amazon_pin_enc, target_owner, email),
        ).rowcount
        if updated:
            return "updated"
        conn.execute(
            _sql(
                "INSERT INTO accounts (owner, name, email, app_password_enc, amazon_pin_enc) "
                "VALUES (%s, %s, %s, %s, %s)"
            ),
            (target_owner, name, email, app_password_enc, amazon_pin_enc),
        )
        return "added"


def delete_account(owner: str, account_id: int) -> None:
    with _connect() as conn:
        conn.execute(
            _sql("DELETE FROM accounts WHERE id = %s AND owner = %s"), (account_id, owner)
        )
