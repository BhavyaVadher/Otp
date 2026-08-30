"""
Telegram bot front-end for otp_core.fetch_latest_otp.

Message the bot with an email address and Gmail App Password (whitespace
between them, in either order or on separate lines) and it replies with the
most recent Amazon OTP found in that inbox.

Required environment variables:
  TELEGRAM_BOT_TOKEN     - token from @BotFather
  ALLOWED_TELEGRAM_IDS   - comma-separated Telegram user IDs allowed to use
                           the bot (recommended; leave unset to allow anyone,
                           NOT recommended since credentials are involved)
"""
import asyncio
import logging
import os
import re

from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

from otp_core import OtpFetchError, fetch_latest_otp

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

EMAIL_RE = re.compile(r"[^\s]+@[^\s]+\.[^\s]+")


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
        results = await asyncio.to_thread(fetch_latest_otp, gmail_address, app_password)
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


def main() -> None:
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        raise SystemExit("Set the TELEGRAM_BOT_TOKEN environment variable.")

    if ALLOWED_IDS is None:
        log.warning(
            "ALLOWED_TELEGRAM_IDS is not set - anyone who finds this bot can use it "
            "to check any Gmail inbox they have credentials for. Consider setting it."
        )

    app = Application.builder().token(token).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("myid", myid))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

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
