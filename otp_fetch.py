"""
Fetch the most recent Amazon job-verification OTP from your own Gmail inbox.

Requires a Gmail App Password (Google Account -> Security -> App passwords).
Set GMAIL_ADDRESS / GMAIL_APP_PASSWORD as environment variables (e.g. in a
local .env file, which is gitignored) whenever you want to switch accounts.
"""
import os
import sys

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

from otp_core import OtpFetchError, fetch_latest_otp

GMAIL_ADDRESS = os.environ.get("GMAIL_ADDRESS", "")
GMAIL_APP_PASSWORD = os.environ.get("GMAIL_APP_PASSWORD", "")


def main() -> int:
    if not GMAIL_ADDRESS or not GMAIL_APP_PASSWORD:
        print("Set the GMAIL_ADDRESS and GMAIL_APP_PASSWORD environment variables.")
        return 1

    try:
        results = fetch_latest_otp(GMAIL_ADDRESS, GMAIL_APP_PASSWORD)
    except OtpFetchError as exc:
        print(exc)
        return 1

    for result in results:
        print(
            f"{result.when.strftime('%Y-%m-%d %I:%M:%S %p %Z')}    "
            f"{result.code or '(no code found)'}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
