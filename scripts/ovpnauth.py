#!/usr/bin/env python3

from __future__ import annotations

import html
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen


VPNBOOK_PAGE = (
    "https://www.vpnbook.com/freevpn/openvpn"
)

OUTPUT_DIR = Path("output/auth")

OUTPUT_FILE = (
    OUTPUT_DIR / "openvpn.json"
)

USER_AGENT = (
    "Mozilla/5.0 "
    "(compatible; VPNBookAuthUpdater/1.0)"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")


def download_page() -> str:

    request = Request(
        VPNBOOK_PAGE,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,*/*",
        },
    )

    with urlopen(
        request,
        timeout=30,
    ) as response:

        return response.read().decode(
            "utf-8",
            errors="ignore",
        )


def strip_html(value: str) -> str:

    value = re.sub(
        r"<script\b[^>]*>.*?</script>",
        " ",
        value,
        flags=re.I | re.S,
    )

    value = re.sub(
        r"<style\b[^>]*>.*?</style>",
        " ",
        value,
        flags=re.I | re.S,
    )

    value = re.sub(
        r"<[^>]+>",
        " ",
        value,
    )

    value = html.unescape(value)

    value = re.sub(
        r"\s+",
        " ",
        value,
    )

    return value.strip()


def extract_credentials(
    text: str,
) -> tuple[str, str]:

    # --------------------------------------------------------
    # Preferred format:
    #
    # Username vpnbook Copy
    # Password 3ssumf2 Copy
    # --------------------------------------------------------

    username_match = re.search(
        r"Username\s+"
        r"([A-Za-z0-9._-]+)"
        r"\s+Copy",
        text,
        flags=re.I,
    )

    password_match = re.search(
        r"Password\s+"
        r"([A-Za-z0-9._-]+)"
        r"\s+Copy",
        text,
        flags=re.I,
    )

    if username_match and password_match:

        return (
            username_match.group(1),
            password_match.group(1),
        )

    # --------------------------------------------------------
    # Fallback
    # --------------------------------------------------------

    username_match = re.search(
        r"Username\s+"
        r"`?([A-Za-z0-9._-]+)`?",
        text,
        flags=re.I,
    )

    password_match = re.search(
        r"Password\s+"
        r"`?([A-Za-z0-9._-]+)`?",
        text,
        flags=re.I,
    )

    if not username_match:
        raise RuntimeError(
            "Could not find VPNBook username."
        )

    if not password_match:
        raise RuntimeError(
            "Could not find VPNBook password."
        )

    return (
        username_match.group(1),
        password_match.group(1),
    )


def main() -> int:

    print("=" * 60)
    print("VPNBook OpenVPN credentials updater")
    print("=" * 60)

    try:

        raw_html = download_page()

        text = strip_html(
            raw_html
        )

        username, password = (
            extract_credentials(text)
        )

        OUTPUT_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        data = {
            "provider": "VPNBook",
            "type": "openvpn",
            "username": username,
            "password": password,
            "updated_at": utc_now(),
            "source": VPNBOOK_PAGE,
        }

        OUTPUT_FILE.write_text(
            json.dumps(
                data,
                indent=2,
                ensure_ascii=False,
            ) + "\n",
            encoding="utf-8",
        )

        print(
            f"Username: {username}"
        )

        print(
            f"Credentials written to: "
            f"{OUTPUT_FILE}"
        )

        return 0

    except Exception as exc:

        print(
            f"FATAL ERROR: {exc}"
        )

        return 1


if __name__ == "__main__":
    sys.exit(main())
