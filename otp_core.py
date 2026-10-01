"""
Core Gmail-IMAP OTP-fetching logic, shared by the CLI script (otp_fetch.py)
and the Telegram bot (bot.py). Takes credentials as arguments instead of
hardcoding them, so callers can fetch OTPs for any account.
"""
import email
import email.message
import imaplib
import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from email.header import decode_header
from zoneinfo import ZoneInfo

EST = ZoneInfo("America/New_York")
IMAP_HOST = "imap.gmail.com"
LOOKBACK_DAYS = 3

AMAZON_SENDER_HINTS = ("amazon.com", "amazon.jobs", "hiring.amazon.com", "amazon.co")

OTP_SUBJECT_HINTS = (
    "verification code",
    "one time password",
    "one-time password",
    "otp",
    "sign-in code",
    "security code",
)

CODE_PATTERN = re.compile(r"\b(\d{4,8})\b")


class OtpFetchError(Exception):
    """Raised for any expected failure (bad login, no emails found, etc.)."""


@dataclass
class OtpResult:
    when: datetime
    code: str | None
    subject: str


def decode_str(value) -> str:
    if not value:
        return ""
    parts = decode_header(value)
    decoded = ""
    for text, charset in parts:
        if isinstance(text, bytes):
            decoded += text.decode(charset or "utf-8", errors="replace")
        else:
            decoded += text
    return decoded


def get_body_text(msg: email.message.Message) -> str:
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition") or "")
            if content_type == "text/plain" and "attachment" not in disposition:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    return payload.decode(charset, errors="replace")
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    return payload.decode(charset, errors="replace")
        return ""
    payload = msg.get_payload(decode=True)
    if payload:
        charset = msg.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")
    return ""


def extract_code(subject: str, body: str) -> str | None:
    text = f"{subject}\n{body}"
    for line in text.splitlines():
        if any(hint in line.lower() for hint in ("code", "otp", "password")):
            match = CODE_PATTERN.search(line)
            if match:
                return match.group(1)
    match = CODE_PATTERN.search(text)
    return match.group(1) if match else None


def check_login(gmail_address: str, app_password: str) -> None:
    """Raise OtpFetchError if the credentials can't log into Gmail."""
    try:
        imap = imaplib.IMAP4_SSL(IMAP_HOST)
        imap.login(gmail_address, app_password)
    except imaplib.IMAP4.error as exc:
        raise OtpFetchError(f"Login failed: {exc}") from exc
    except OSError as exc:
        raise OtpFetchError(f"Could not connect to Gmail: {exc}") from exc
    imap.logout()


def fetch_latest_otp(
    gmail_address: str,
    app_password: str,
    lookback_days: int = LOOKBACK_DAYS,
    max_results: int = 2,
) -> list[OtpResult]:
    """Log into gmail_address via IMAP and return the most recent OTP emails.

    Raises OtpFetchError on any expected failure (bad credentials, no
    matching emails, etc.) with a message safe to show to the caller.
    """
    try:
        imap = imaplib.IMAP4_SSL(IMAP_HOST)
        imap.login(gmail_address, app_password)
    except imaplib.IMAP4.error as exc:
        raise OtpFetchError(f"Login failed: {exc}") from exc
    except OSError as exc:
        raise OtpFetchError(f"Could not connect to Gmail: {exc}") from exc

    try:
        imap.select("INBOX", readonly=True)

        since = (date.today() - timedelta(days=lookback_days)).strftime("%d-%b-%Y")

        ids = set()
        for hint in AMAZON_SENDER_HINTS:
            status, data = imap.search(None, f'(SINCE {since} FROM "{hint}")')
            if status == "OK" and data and data[0]:
                ids.update(data[0].split())

        if not ids:
            raise OtpFetchError(
                f"No recent Amazon emails found in the last {lookback_days} day(s)."
            )

        candidates = []
        for msg_id in ids:
            status, msg_data = imap.fetch(msg_id, "(RFC822)")
            if status != "OK" or not msg_data or not msg_data[0]:
                continue
            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)

            subject = decode_str(msg.get("Subject"))
            if not any(hint in subject.lower() for hint in OTP_SUBJECT_HINTS):
                body_preview = get_body_text(msg)[:500].lower()
                if not any(hint in body_preview for hint in OTP_SUBJECT_HINTS):
                    continue

            date_tuple = email.utils.parsedate_to_datetime(msg.get("Date"))
            candidates.append((date_tuple, msg, subject))

        if not candidates:
            raise OtpFetchError(
                "Found Amazon emails, but none looked like a verification/OTP email."
            )

        candidates.sort(key=lambda item: item[0], reverse=True)

        results = []
        for when, msg, subject in candidates[:max_results]:
            body = get_body_text(msg)
            code = extract_code(subject, body)
            results.append(OtpResult(when=when.astimezone(EST), code=code, subject=subject))
        return results
    finally:
        imap.logout()
