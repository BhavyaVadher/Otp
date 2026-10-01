"""
Storage for saved Gmail accounts.

Uses Postgres when DATABASE_URL is set (e.g. a free Neon database in
production), otherwise a local SQLite file (accounts.db) for development.
App passwords are encrypted with a key derived from SECRET_KEY before they
are written, so a leaked database alone doesn't expose them.
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
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    app_password_enc TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""

_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    app_password_enc TEXT NOT NULL,
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


def init_db() -> None:
    with _connect() as conn:
        conn.execute(_POSTGRES_SCHEMA if DATABASE_URL else _SQLITE_SCHEMA)


def list_accounts() -> list[Account]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, name, email FROM accounts ORDER BY lower(name)"
        ).fetchall()
    return [Account(*row) for row in rows]


def add_account(name: str, email: str, app_password: str) -> None:
    encrypted = _fernet().encrypt(app_password.encode()).decode()
    try:
        with _connect() as conn:
            conn.execute(
                _sql("INSERT INTO accounts (name, email, app_password_enc) VALUES (%s, %s, %s)"),
                (name, email, encrypted),
            )
    except Exception as exc:
        if _is_unique_violation(exc):
            raise DuplicateAccountError(f"{email} is already saved.") from exc
        raise


def get_credentials(account_id: int) -> tuple[Account, str] | None:
    with _connect() as conn:
        row = conn.execute(
            _sql("SELECT id, name, email, app_password_enc FROM accounts WHERE id = %s"),
            (account_id,),
        ).fetchone()
    if row is None:
        return None
    try:
        app_password = _fernet().decrypt(row[3].encode()).decode()
    except InvalidToken as exc:
        raise RuntimeError(
            "Saved password can't be decrypted - was SECRET_KEY changed?"
        ) from exc
    return Account(row[0], row[1], row[2]), app_password


def delete_account(account_id: int) -> None:
    with _connect() as conn:
        conn.execute(_sql("DELETE FROM accounts WHERE id = %s"), (account_id,))
