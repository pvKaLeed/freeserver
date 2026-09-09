#!/usr/bin/env python3

from __future__ import annotations

import base64
import csv
import io
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


# ============================================================
# CONFIG
# ============================================================

VPNGATE_API = "https://www.vpngate.net/api/iphone/"

OUTPUT_DIR = Path("output/openvpn")
SERVERS_JSON = OUTPUT_DIR / "servers.json"

USER_AGENT = (
    "Mozilla/5.0 "
    "(Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 "
    "(KHTML, like Gecko) "
    "Chrome/140.0 Safari/537.36"
)

MAX_SERVERS = 50


# ============================================================
# TIME
# ============================================================

def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


# ============================================================
# DOWNLOAD
# ============================================================

def download_csv() -> str:
    """Download VPN Gate API response."""

    print(f"Downloading: {VPNGATE_API}")

    request = Request(
        VPNGATE_API,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
            "Cache-Control": "no-cache",
        },
    )

    try:
        with urlopen(request, timeout=90) as response:
            raw = response.read()

            print(f"Downloaded: {len(raw):,} bytes")

            if not raw:
                raise RuntimeError("VPNGate returned empty response.")

            # VPNGate normally uses UTF-8.
            return raw.decode("utf-8", errors="replace")

    except HTTPError as exc:
        raise RuntimeError(
            f"VPNGate HTTP error {exc.code}: {exc.reason}"
        ) from exc

    except URLError as exc:
        raise RuntimeError(
            f"VPNGate connection error: {exc.reason}"
        ) from exc

    except TimeoutError as exc:
        raise RuntimeError(
            "VPNGate request timed out."
        ) from exc


# ============================================================
# BASE64
# ============================================================

def safe_base64_decode(data: str) -> str:
    """Decode VPNGate Base64 safely."""

    if not data:
        return ""

    data = data.strip()

    # Remove spaces/newlines that may exist inside the field.
    data = re.sub(r"\s+", "", data)

    # Some API responses may contain URL-safe Base64.
    data = data.replace("-", "+").replace("_", "/")

    # Fix padding.
    padding = len(data) % 4

    if padding:
        data += "=" * (4 - padding)

    try:
        decoded = base64.b64decode(
            data,
            validate=False,
        )

        return decoded.decode(
            "utf-8",
            errors="replace",
        )

    except Exception as exc:
        print(f"WARNING: Base64 decode failed: {exc}")
        return ""


# ============================================================
# HEADER HELPERS
# ============================================================

def normalize_header(value: str) -> str:
    """Normalize CSV header names."""

    value = value.strip()

    if value.startswith("#"):
        value = value[1:]

    return value.strip().lower()


def find_header(lines: list[str]) -> tuple[int, list[str]]:
    """
    Find VPNGate CSV header.

    VPNGate responses can contain comment lines before the
    actual CSV header.
    """

    for index, line in enumerate(lines):

        stripped = line.strip()

        if not stripped:
            continue

        # Most common:
        # #HostName,IP,Score,...
        if (
            stripped.startswith("#HostName")
            or stripped.startswith("HostName")
        ):
            reader = csv.reader([stripped])
            header = next(reader)

            return index, [
                normalize_header(x)
                for x in header
            ]

    # Fallback: find any line containing HostName + IP.
    for index, line in enumerate(lines):

        stripped = line.strip()

        if not stripped:
            continue

        try:
            reader = csv.reader([stripped])
            row = next(reader)

            normalized = [
                normalize_header(x)
                for x in row
            ]

            if "hostname" in normalized and "ip" in normalized:
                return index, normalized

        except Exception:
            continue

    raise RuntimeError(
        "VPNGate CSV header was not found."
    )


# ============================================================
# COLUMN LOOKUP
# ============================================================

def get_column(
    row: list[str],
    header_map: dict[str, int],
    name: str,
    default: str = "",
) -> str:

    index = header_map.get(name)

    if index is None:
        return default

    if index >= len(row):
        return default

    return row[index].strip()


# ============================================================
# PROTOCOL
# ============================================================

def is_available(value: str) -> bool:
    """
    VPNGate protocol availability.

    Usually values are:
    0 = unavailable
    1 = available

    Some responses can contain other numeric values,
    therefore any non-zero numeric value is considered available.
    """

    value = value.strip()

    if not value:
        return False

    try:
        return int(float(value)) > 0
    except ValueError:
        return value.lower() not in {
            "false",
            "no",
            "none",
            "null",
        }


def build_protocols(
    row: list[str],
    header_map: dict[str, int],
    filename: str,
) -> list[dict]:

    protocol_definitions = [
        ("udp_443", "udp", 443, "udp443"),
        ("udp_1194", "udp", 1194, "udp1194"),
        ("tcp_443", "tcp", 443, "tcp443"),
        ("tcp_80", "tcp", 80, "tcp80"),
        ("tcp_1194", "tcp", 1194, "tcp1194"),
        ("udp_80", "udp", 80, "udp80"),
        ("udp_53", "udp", 53, "udp53"),
    ]

    protocols = []

    for column, transport, port, protocol_id in protocol_definitions:

        value = get_column(
            row,
            header_map,
            column,
        )

        if is_available(value):
            protocols.append(
                {
                    "id": protocol_id,
                    "transport": transport,
                    "port": port,
                    "file": filename,
                    "available": True,
                }
            )

    return protocols


# ============================================================
# OVPN CLEANUP
# ============================================================

def clean_old_configs() -> None:
    """Delete old generated OVPN files."""

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    removed = 0

    for file in OUTPUT_DIR.glob("*.ovpn"):

        try:
            file.unlink()
            removed += 1

        except OSError as exc:
            print(
                f"WARNING: Cannot remove {file.name}: {exc}"
            )

    print(
        f"Old configs removed: {removed}"
    )


# ============================================================
# FILENAME
# ============================================================

def safe_filename(hostname: str) -> str:

    name = hostname.strip()

    name = re.sub(
        r"[^A-Za-z0-9._-]+",
        "_",
        name,
    )

    name = name.replace(".", "_")
    name = name.replace("-", "_")

    if not name:
        name = "server"

    return f"{name}.ovpn"


# ============================================================
# OVPN CONFIG
# ============================================================

def normalize_ovpn_config(
    config: str,
    hostname: str,
) -> str:

    lines = config.splitlines()

    output = []

    for line in lines:

        stripped = line.strip()

        # VPNGate occasionally uses an unknown remote value.
        if stripped.startswith("remote "):

            parts = stripped.split()

            if len(parts) >= 2:

                # Preserve port if present.
                if len(parts) >= 3:
                    port = parts[2]
                    output.append(
                        f"remote {hostname} {port}"
                    )
                else:
                    output.append(
                        f"remote {hostname} 1194"
                    )

                continue

        output.append(line)

    return "\n".join(output).strip() + "\n"


# ============================================================
# CONFIG VALIDATION
# ============================================================

def is_valid_ovpn(config: str) -> bool:

    if not config:
        return False

    lower = config.lower()

    has_client = (
        "\nclient" in lower
        or lower.startswith("client")
    )

    has_remote = "\nremote " in lower

    has_cert = (
        "<ca>" in lower
        or "<cert>" in lower
        or "<key>" in lower
    )

    return (
        has_client
        and has_remote
        and has_cert
    )


# ============================================================
# SCORE
# ============================================================

def parse_score(value: str) -> int:

    try:
        return int(float(value))
    except (ValueError, TypeError):
        return 0


# ============================================================
# CSV PARSER
# ============================================================

def parse_vpngate_csv(
    csv_content: str,
) -> list[dict]:

    if not csv_content.strip():
        raise RuntimeError(
            "VPNGate response is empty."
        )

    # Keep blank lines because the header location matters.
    lines = csv_content.splitlines()

    header_index, headers = find_header(lines)

    print()
    print(
        f"CSV header found at line: {header_index + 1}"
    )

    print(
        "Columns:",
        ", ".join(headers),
    )

    header_map = {
        name: index
        for index, name in enumerate(headers)
    }

    required = [
        "hostname",
        "ip",
        "country",
        "countrycode",
        "openvpn_configdata_base64",
    ]

    missing = [
        name
        for name in required
        if name not in header_map
    ]

    if missing:
        raise RuntimeError(
            "VPNGate CSV is missing required columns: "
            + ", ".join(missing)
        )

    servers = []

    reader = csv.reader(
        lines[header_index + 1:]
    )

    for row_number, row in enumerate(
        reader,
        start=header_index + 2,
    ):

        if not row:
            continue

        # Ignore comment rows.
        first = row[0].strip()

        if first.startswith("#"):
            continue

        # Make sure row is long enough.
        if len(row) < len(headers):
            print(
                f"WARNING: Row {row_number} has "
                f"{len(row)} columns; expected "
                f"{len(headers)}. Skipping."
            )
            continue

        hostname = get_column(
            row,
            header_map,
            "hostname",
        )

        ip = get_column(
            row,
            header_map,
            "ip",
        )

        country = get_column(
            row,
            header_map,
            "country",
            "Unknown",
        )

        country_code = get_column(
            row,
            header_map,
            "countrycode",
            "UN",
        )

        score = parse_score(
            get_column(
                row,
                header_map,
                "score",
            )
        )

        config_base64 = get_column(
            row,
            header_map,
            "openvpn_configdata_base64",
        )

        if not hostname:
            continue

        if not config_base64:
            print(
                f"WARNING: {hostname}: no OVPN config"
            )
            continue

        config = safe_base64_decode(
            config_base64
        )

        if not is_valid_ovpn(config):
            print(
                f"WARNING: {hostname}: invalid OVPN config"
            )
            continue

        filename = safe_filename(hostname)

        config = normalize_ovpn_config(
            config,
            hostname,
        )

        ovpn_path = OUTPUT_DIR / filename

        try:
            ovpn_path.write_text(
                config,
                encoding="utf-8",
            )

        except OSError as exc:
            print(
                f"WARNING: Failed writing "
                f"{filename}: {exc}"
            )
            continue

        protocols = build_protocols(
            row,
            header_map,
            filename,
        )

        # If API does not provide protocol columns,
        # don't invent unavailable protocols.
        if not protocols:

            print(
                f"WARNING: {hostname}: "
                f"no available protocol"
            )

            # Remove config because the server has no
            # usable protocol according to API.
            try:
                ovpn_path.unlink()
            except OSError:
                pass

            continue

        server = {
            "id": len(servers) + 1,
            "name": f"{country} Server {len(servers) + 1}",
            "host": hostname,
            "ip": ip or hostname,
            "country": country or "Unknown",
            "country_code": country_code or "UN",
            "type": "openvpn",
            "status": "unknown",
            "ping": None,
            "download_speed": None,
            "upload_speed": None,
            "protocols": protocols,
            "score": score,
        }

        servers.append(server)

        print(
            f"OK: {hostname} | "
            f"{country} | "
            f"score={score} | "
            f"protocols={len(protocols)}"
        )

    return servers


# ============================================================
# JSON
# ============================================================

def write_servers_json(
    servers: list[dict],
) -> None:

    if not servers:
        raise RuntimeError(
            "No usable VPNGate servers found."
        )

    # Re-number after sorting.
    for index, server in enumerate(
        servers,
        start=1,
    ):
        server["id"] = index

        country = server.get(
            "country",
            "Unknown",
        )

        server["name"] = (
            f"{country} Server {index}"
        )

    output = {
        "version": 2,
        "provider": "VPNGate",
        "type": "openvpn",
        "source": "https://www.vpngate.net/",
        "updated_at": utc_now(),

        "measurement": {
            "ping": "client",
            "speed": "client",
            "status": "client",
        },

        "protocols": [
            {
                "id": "udp1194",
                "transport": "udp",
                "port": 1194,
                "priority": 1,
            },
            {
                "id": "udp443",
                "transport": "udp",
                "port": 443,
                "priority": 2,
            },
            {
                "id": "udp80",
                "transport": "udp",
                "port": 80,
                "priority": 3,
            },
            {
                "id": "udp53",
                "transport": "udp",
                "port": 53,
                "priority": 4,
            },
            {
                "id": "tcp443",
                "transport": "tcp",
                "port": 443,
                "priority": 5,
            },
            {
                "id": "tcp80",
                "transport": "tcp",
                "port": 80,
                "priority": 6,
            },
            {
                "id": "tcp1194",
                "transport": "tcp",
                "port": 1194,
                "priority": 7,
            },
        ],

        "servers": servers,
    }

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    SERVERS_JSON.write_text(
        json.dumps(
            output,
            indent=2,
            ensure_ascii=False,
        ) + "\n",
        encoding="utf-8",
    )

    print()
    print(
        f"Written: {SERVERS_JSON}"
    )

    print(
        f"Active servers: {len(servers)}"
    )


# ============================================================
# MAIN
# ============================================================

def main() -> int:

    print("=" * 70)
    print("VPN Gate OpenVPN Updater")
    print("=" * 70)

    try:

        # ----------------------------------------------------
        # Download
        # ----------------------------------------------------

        csv_content = download_csv()

        # Quick sanity check.
        if (
            "HostName" not in csv_content
            and "#HostName" not in csv_content
        ):
            print()
            print(
                "WARNING: Downloaded response does not "
                "look like normal VPNGate CSV."
            )

            print(
                "First 500 characters:"
            )

            print(
                csv_content[:500]
            )

            raise RuntimeError(
                "VPNGate API did not return expected CSV."
            )

        # ----------------------------------------------------
        # Prepare output
        # ----------------------------------------------------

        OUTPUT_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        clean_old_configs()

        # ----------------------------------------------------
        # Parse
        # ----------------------------------------------------

        print()
        print("Parsing VPNGate servers...")

        servers = parse_vpngate_csv(
            csv_content
        )

        if not servers:
            raise RuntimeError(
                "No usable VPNGate servers found."
            )

        # ----------------------------------------------------
        # Sort
        # ----------------------------------------------------

        servers.sort(
            key=lambda server: (
                server.get("score", 0)
            ),
            reverse=True,
        )

        print()
        print(
            f"Usable servers found: {len(servers)}"
        )

        # ----------------------------------------------------
        # Limit
        # ----------------------------------------------------

        if len(servers) > MAX_SERVERS:

            print(
                f"Limiting to top "
                f"{MAX_SERVERS} servers."
            )

            servers = servers[:MAX_SERVERS]

        # ----------------------------------------------------
        # Write JSON
        # ----------------------------------------------------

        write_servers_json(
            servers
        )

        # ----------------------------------------------------
        # Summary
        # ----------------------------------------------------

        print()
        print("=" * 70)
        print("UPDATE COMPLETE")
        print("=" * 70)

        for server in servers[:10]:

            print(
                f"{server['id']:>2}. "
                f"{server['host']} | "
                f"{server['country']} | "
                f"score={server['score']} | "
                f"protocols={len(server['protocols'])}"
            )

        print()
        print(
            f"Generated: {SERVERS_JSON}"
        )

        return 0

    except KeyboardInterrupt:

        print()
        print("Interrupted.")

        return 130

    except Exception as exc:

        print()
        print("=" * 70)
        print("FATAL ERROR")
        print("=" * 70)

        print(
            f"{type(exc).__name__}: {exc}"
        )

        import traceback

        traceback.print_exc()

        return 1


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    sys.exit(main())
