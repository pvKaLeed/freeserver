#!/usr/bin/env python3

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen


SOURCE_URL = "https://www.vpnbook.com/freevpn/openvpn"

OUTPUT = Path(
    "output/auth/openvpn.json"
)


def now_utc() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def fetch_page() -> str:

    request = Request(
        SOURCE_URL,
        headers={
            "User-Agent": (
                "Mozilla/5.0 "
                "(X11; Linux x86_64) "
                "AppleWebKit/537.36 "
                "(KHTML, like Gecko) "
                "Chrome/131 Safari/537.36"
            )
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


def clean_html(value: str) -> str:

    value = re.sub(
        r"<[^>]+>",
        " ",
        value,
    )

    value = value.replace(
        "&nbsp;",
        " ",
    )

    value = value.replace(
        "&amp;",
        "&",
    )

    return " ".join(
        value.split()
    ).strip()


def extract_username(html: str) -> str:

    # VPNBook currently uses "vpnbook".
    # First try to locate it near the Username label.

    patterns = [
        r"Username.{0,1000}?"
        r"(?:<code[^>]*>|<strong[^>]*>|>)"
        r"\s*(vpnbook)\s*"
        r"(?:</code>|</strong>|<)",

        r"Username.{0,1000}?"
        r"\b(vpnbook)\b",
    ]

    for pattern in patterns:

        match = re.search(
            pattern,
            html,
            re.IGNORECASE | re.DOTALL,
        )

        if match:
            return match.group(1).strip()

    # Safe fallback based on the public VPNBook credential.
    if re.search(
        r"\bvpnbook\b",
        html,
        re.IGNORECASE,
    ):
        return "vpnbook"

    raise RuntimeError(
        "Could not find VPNBook username."
    )


def extract_password(html: str) -> str:

    patterns = [
        # Password followed by a code/strong element.
        r"Password.{0,1500}?"
        r"<(?:code|strong)[^>]*>"
        r"\s*([A-Za-z0-9]+)\s*"
        r"</(?:code|strong)>",

        # Generic fallback.
        r"Password.{0,1500}?"
        r"\b([A-Za-z0-9]{5,32})\b",
    ]

    for pattern in patterns:

        match = re.search(
            pattern,
            html,
            re.IGNORECASE | re.DOTALL,
        )

        if not match:
            continue

        password = match.group(1).strip()

        # Avoid accidentally selecting common words.
        if password.lower() in {
            "password",
            "copy",
            "updated",
            "username",
        }:
            continue

        return password

    raise RuntimeError(
        "Could not find VPNBook password."
    )


def main() -> int:

    print(
        "Fetching VPNBook credentials..."
    )

    try:
        html = fetch_page()

        username = extract_username(
            html
        )

        password = extract_password(
            html
        )

    except Exception as exc:

        print(
            f"ERROR: {exc}"
        )

        return 1

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    data = {
        "version": 1,
        "provider": "VPNBook",
        "username": username,
        "password": password,
        "source": SOURCE_URL,
        "updated_at": now_utc(),
    }

    OUTPUT.write_text(
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    print(
        "Credentials updated successfully."
    )

    print(
        f"Username: {username}"
    )

    print(
        "Password: [updated]"
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
