"""
Password-protected website for saving Gmail accounts and pulling their latest
Amazon OTP with one click. Also hosts the Telegram bot (bot.py) in the same
process, so a single Render web service runs both.

Environment variables:
  ADMIN_USERNAME / ADMIN_PASSWORD - required, the main admin login. Accounts
                        saved before multi-admin support belong to this admin.
  ADMINS              - optional, more admin logins as "user:password" pairs
                        separated by commas, e.g. "priya:pass1,amit:pass2".
                        Each admin only sees the accounts they added.
  SECRET_KEY          - required, long random string; signs the login cookie and
                        encrypts saved app passwords. Changing it makes saved
                        passwords unreadable.
  DATABASE_URL        - Postgres URL (e.g. Neon). Unset = local accounts.db file.
  TELEGRAM_BOT_TOKEN  - optional; when set the Telegram bot runs too (webhook
                        mode on Render, polling locally). See bot.py for its
                        other settings.

Run locally:  python app.py   (then open http://localhost:8000)
"""
import hashlib
import hmac
import logging
import os
import re
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

from fastapi import FastAPI, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from telegram import Update

import db
from bot import ALLOWED_IDS, build_application
from otp_core import OtpFetchError, check_login, fetch_latest_otp

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
SECRET_KEY = os.environ.get("SECRET_KEY", "")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
EXTERNAL_URL = os.environ.get("RENDER_EXTERNAL_URL", "").rstrip("/")

if not (ADMIN_USERNAME and ADMIN_PASSWORD and SECRET_KEY):
    raise SystemExit("Set ADMIN_USERNAME, ADMIN_PASSWORD and SECRET_KEY environment variables.")


def _load_admins() -> dict[str, str]:
    admins = {ADMIN_USERNAME: ADMIN_PASSWORD}
    for entry in os.environ.get("ADMINS", "").split(","):
        username, sep, password = entry.strip().partition(":")
        if not entry.strip():
            continue
        if not (sep and username.strip() and password):
            raise SystemExit(f'ADMINS entry "{username}" must look like user:password.')
        admins[username.strip()] = password
    return admins


ADMINS = _load_admins()

WEBHOOK_PATH = "/telegram/webhook"
WEBHOOK_SECRET = hashlib.sha256(f"webhook:{TELEGRAM_BOT_TOKEN}".encode()).hexdigest()

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
PIN_RE = re.compile(r"^\d{6}$")
AMAZON_LOGIN_URL = "https://auth.hiring.amazon.com/#/login"

# Brute-force protection for the login form: per-IP failure count.
MAX_LOGIN_FAILURES = 5
LOGIN_LOCKOUT_SECONDS = 15 * 60
_login_failures: dict[str, tuple[int, float]] = {}

templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db(default_owner=ADMIN_USERNAME)

    telegram = None
    if TELEGRAM_BOT_TOKEN:
        if ALLOWED_IDS is None:
            log.warning("ALLOWED_TELEGRAM_IDS is not set - anyone who finds the bot can use it.")
        telegram = build_application(TELEGRAM_BOT_TOKEN)
        await telegram.initialize()
        if EXTERNAL_URL:
            await telegram.bot.set_webhook(
                url=f"{EXTERNAL_URL}{WEBHOOK_PATH}",
                secret_token=WEBHOOK_SECRET,
                allowed_updates=Update.ALL_TYPES,
            )
            log.info("Telegram bot running in webhook mode")
        else:
            await telegram.updater.start_polling(allowed_updates=Update.ALL_TYPES)
            log.info("Telegram bot running in polling mode")
        await telegram.start()
    app.state.telegram = telegram

    yield

    if telegram:
        if telegram.updater.running:
            await telegram.updater.stop()
        await telegram.stop()
        await telegram.shutdown()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie="otp_session",
    max_age=7 * 24 * 3600,
    same_site="lax",
    https_only=bool(EXTERNAL_URL),
)


def _current_admin(request: Request) -> str | None:
    """The logged-in admin's username, or None. Re-checked against ADMINS on
    every request, so removing an admin from the settings logs them out."""
    user = request.session.get("user")
    return user if user in ADMINS else None


def _check_login(username: str, password: str) -> bool:
    ok = False
    # Compare against every admin so the response time doesn't reveal which usernames exist.
    for admin_user, admin_password in ADMINS.items():
        user_ok = hmac.compare_digest(username.encode(), admin_user.encode())
        pass_ok = hmac.compare_digest(password.encode(), admin_password.encode())
        ok |= user_ok and pass_ok
    return ok


def _flash(request: Request, message: str, kind: str = "error") -> None:
    request.session["flash"] = {"message": message, "kind": kind}


def _client_ip(request: Request) -> str:
    # Render's proxy appends the real client IP last; earlier entries can be spoofed.
    forwarded = request.headers.get("x-forwarded-for", "")
    return forwarded.split(",")[-1].strip() or (request.client.host if request.client else "?")


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/login")
def login_page(request: Request):
    if _current_admin(request):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(
        request, "login.html", {"flash": request.session.pop("flash", None)}
    )


@app.post("/login")
def login(request: Request, username: str = Form(""), password: str = Form("")):
    ip = _client_ip(request)
    failures, last = _login_failures.get(ip, (0, 0.0))
    if failures >= MAX_LOGIN_FAILURES and time.monotonic() - last < LOGIN_LOCKOUT_SECONDS:
        _flash(request, "Too many failed attempts. Try again in 15 minutes.")
        return RedirectResponse("/login", status_code=303)

    username = username.strip()
    if not _check_login(username, password):
        _login_failures[ip] = (failures + 1, time.monotonic())
        log.warning("Failed login from %s", ip)
        _flash(request, "Wrong username or password.")
        return RedirectResponse("/login", status_code=303)

    _login_failures.pop(ip, None)
    request.session.clear()
    request.session["user"] = username
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/")
def index(request: Request):
    owner = _current_admin(request)
    if owner is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "accounts": db.list_accounts(owner),
            "admin": owner,
            "flash": request.session.pop("flash", None),
            "amazon_login_url": AMAZON_LOGIN_URL,
        },
    )


@app.post("/accounts")
def add_account(
    request: Request,
    name: str = Form(""),
    email: str = Form(""),
    app_password: str = Form(""),
    amazon_pin: str = Form(""),
):
    owner = _current_admin(request)
    if owner is None:
        return RedirectResponse("/login", status_code=303)

    amazon_pin = amazon_pin.strip()
    email = email.strip().lower()
    name = name.strip() or email
    # Google shows app passwords as 'abcd efgh ijkl mnop'; they're used without spaces.
    app_password = re.sub(r"\s+", "", app_password)

    if not EMAIL_RE.match(email):
        _flash(request, "That doesn't look like a valid email address.")
    elif len(app_password) != 16:
        _flash(request, "App password must be 16 characters (spaces are ignored).")
    elif amazon_pin and not PIN_RE.match(amazon_pin):
        _flash(request, "Amazon PIN must be exactly 6 digits.")
    else:
        try:
            check_login(email, app_password)
            db.add_account(owner, name, email, app_password, amazon_pin or None)
            _flash(request, f"Saved {name}.", "success")
        except OtpFetchError as exc:
            _flash(request, f"Not saved - {exc}")
        except db.DuplicateAccountError as exc:
            _flash(request, str(exc))
    return RedirectResponse("/", status_code=303)


@app.post("/accounts/{account_id}/edit")
def edit_account(
    request: Request, account_id: int, name: str = Form(""), amazon_pin: str = Form("")
):
    owner = _current_admin(request)
    if owner is None:
        return RedirectResponse("/login", status_code=303)

    name = name.strip()
    amazon_pin = amazon_pin.strip()
    if not name:
        _flash(request, "Name can't be empty.")
    elif amazon_pin and not PIN_RE.match(amazon_pin):
        _flash(request, "Amazon PIN must be exactly 6 digits.")
    else:
        db.update_account(owner, account_id, name, amazon_pin or None)
        _flash(request, f"Updated {name}.", "success")
    return RedirectResponse("/", status_code=303)


@app.post("/accounts/{account_id}/delete")
def delete_account(request: Request, account_id: int):
    owner = _current_admin(request)
    if owner is None:
        return RedirectResponse("/login", status_code=303)
    db.delete_account(owner, account_id)
    _flash(request, "Account removed.", "success")
    return RedirectResponse("/", status_code=303)


@app.get("/api/accounts/{account_id}/otp")
def account_otp(request: Request, account_id: int):
    owner = _current_admin(request)
    if owner is None:
        return JSONResponse({"error": "Session expired - please log in again."}, status_code=401)

    found = db.get_credentials(owner, account_id)
    if found is None:
        return JSONResponse({"error": "Account not found."}, status_code=404)
    account, app_password = found

    try:
        results = fetch_latest_otp(account.email, app_password, max_results=1)
    except OtpFetchError as exc:
        return JSONResponse({"error": str(exc)})
    except Exception:
        log.exception("Unexpected error fetching OTP for %s", account.email)
        return JSONResponse({"error": "Unexpected error while checking that inbox."})

    latest = results[0]
    age = (datetime.now(timezone.utc) - latest.when).total_seconds()
    return {
        "code": latest.code,
        "timestamp": int(latest.when.timestamp()),
        "subject": latest.subject,
        "when": latest.when.strftime("%b %d, %I:%M:%S %p %Z"),
        "age_seconds": max(0, int(age)),
    }


@app.post(WEBHOOK_PATH)
async def telegram_webhook(request: Request):
    telegram = request.app.state.telegram
    secret = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
    if telegram is None or not hmac.compare_digest(secret, WEBHOOK_SECRET):
        return Response(status_code=403)
    await telegram.update_queue.put(Update.de_json(await request.json(), telegram.bot))
    return Response(status_code=200)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
    )
