"""
Telegram bot front-end for otp_core.fetch_latest_otp.

Message the bot with an email address and Gmail App Password (whitespace
between them, in either order or on separate lines) and it replies with the
most recent Amazon OTP found in that inbox.

Environment variables:
  TELEGRAM_BOT_TOKEN     - required, token from @BotFather
  ALLOWED_TELEGRAM_IDS   - optional, comma-separated Telegram user IDs allowed
                           to use the bot. Leave unset to allow anyone.
  RATE_LIMIT_SECONDS     - optional, minimum seconds between requests from the
                           same user (default 10), to slow down automated abuse.
  MAX_USERS              - optional, max number of distinct Telegram users
                           allowed to use the bot, first-come-first-served
                           (default 10). Resets when the process restarts.
"""
import asyncio
import logging
import os
import re
import time

from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

from otp_core import OtpFetchError, fetch_latest_otp

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)
# httpx logs every request URL at INFO, and Telegram API URLs contain the bot token.
logging.getLogger("httpx").setLevel(logging.WARNING)

EMAIL_RE = re.compile(r"[^\s]+@[^\s]+\.[^\s]+")

RATE_LIMIT_SECONDS = float(os.environ.get("RATE_LIMIT_SECONDS", "10"))
_last_request_at: dict[int, float] = {}

MAX_USERS = int(os.environ.get("MAX_USERS", "10"))
_seen_user_ids: set[int] = set()


def _allowed_ids() -> set[int] | None:
    raw = os.environ.get("ALLOWED_TELEGRAM_IDS", "").strip()
    if not raw:
        return None
    return {int(x) for x in raw.split(",") if x.strip()}


ALLOWED_IDS = _allowed_ids()


def parse_credentials(text: str) -> tuple[str, str] | None:
    """Pull an email address and an app password out of free-form text.

    Everything that isn't the email is treated as the password, with
    whitespace stripped (Google displays app passwords as 'abcd efgh ijkl
    mnop', but they're used without spaces).
    """
    match = EMAIL_RE.search(text)
    if not match:
        return None
    gmail_address = match.group(0)
    remainder = (text[: match.start()] + text[match.end() :]).strip()
    app_password = re.sub(r"\s+", "", remainder)
    if not app_password:
        return None
    return gmail_address, app_password


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "Send me a Gmail address and its App Password (any order, e.g.\n"
        "you@gmail.com abcdefghijklmnop\n"
        ") and I'll reply with the most recent Amazon OTP found in that inbox.\n\n"
        "Use /myid to find your Telegram user ID if you need to allowlist yourself."
    )


async def myid(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(f"Your Telegram user ID: {update.effective_user.id}")


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    if ALLOWED_IDS is not None and user.id not in ALLOWED_IDS:
        await update.message.reply_text("You're not authorized to use this bot.")
        log.warning("Rejected message from unauthorized user id=%s", user.id)
        return

    if user.id not in _seen_user_ids:
        if len(_seen_user_ids) >= MAX_USERS:
            await update.message.reply_text(
                "This bot is at capacity right now. Try again later."
            )
            log.warning("Rejected new user id=%s: at capacity (%s)", user.id, MAX_USERS)
            return
        _seen_user_ids.add(user.id)

    now = time.monotonic()
    last = _last_request_at.get(user.id)
    if last is not None and now - last < RATE_LIMIT_SECONDS:
        wait = RATE_LIMIT_SECONDS - (now - last)
        await update.message.reply_text(f"Please wait {wait:.0f}s before trying again.")
        return
    _last_request_at[user.id] = now

    parsed = parse_credentials(update.message.text or "")
    if not parsed:
        await update.message.reply_text(
            "Couldn't find an email + app password in that message. "
            "Send them like: you@gmail.com abcdefghijklmnop"
        )
        return

    gmail_address, app_password = parsed

    # Delete the incoming message so the app password doesn't linger in chat history.
    try:
        await update.message.delete()
    except Exception:
        pass

    status = await context.bot.send_message(
        chat_id=update.effective_chat.id, text=f"Checking {gmail_address}..."
    )

    try:
        results = await asyncio.to_thread(
            fetch_latest_otp, gmail_address, app_password, max_results=1
        )
    except OtpFetchError as exc:
        await status.edit_text(str(exc))
        return
    except Exception:
        log.exception("Unexpected error fetching OTP for %s", gmail_address)
        await status.edit_text("Unexpected error while checking that inbox.")
        return

    lines = [
        f"{r.when.strftime('%Y-%m-%d %I:%M:%S %p %Z')}    {r.code or '(no code found)'}"
        for r in results
    ]
    await status.edit_text("\n".join(lines))


def build_application(token: str) -> Application:
    app = Application.builder().token(token).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("myid", myid))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    return app


def main() -> None:
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        raise SystemExit("Set the TELEGRAM_BOT_TOKEN environment variable.")

    if ALLOWED_IDS is None:
        log.warning(
            "ALLOWED_TELEGRAM_IDS is not set - anyone who finds this bot can use it "
            "to check any Gmail inbox they have credentials for. Consider setting it."
        )

    app = build_application(token)

    external_url = os.environ.get("RENDER_EXTERNAL_URL")
    if external_url:
        port = int(os.environ.get("PORT", 10000))
        log.info("Bot starting in webhook mode on port %s...", port)
        app.run_webhook(
            listen="0.0.0.0",
            port=port,
            url_path=token,
            webhook_url=f"{external_url}/{token}",
            allowed_updates=Update.ALL_TYPES,
        )
    else:
        log.info("Bot starting in polling mode...")
        app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
