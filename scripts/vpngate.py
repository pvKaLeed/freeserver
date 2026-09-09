#!/usr/bin/env python3

from __future__ import annotations

import base64
import csv
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
# DOWNLOAD VPNGATE CSV
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
                raise RuntimeError(
                    "VPNGate returned an empty response."
                )

            return raw.decode(
                "utf-8",
                errors="replace",
            )

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
    """Safely decode Base64 OpenVPN configuration."""

    if not data:
        return ""

    data = data.strip()

    # Remove whitespace/newlines.
    data = re.sub(r"\s+", "", data)

    # Support URL-safe Base64.
    data = data.replace("-", "+").replace("_", "/")

    # Fix missing padding.
    missing_padding = len(data) % 4

    if missing_padding:
        data += "=" * (4 - missing_padding)

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
        print(
            f"WARNING: Base64 decode failed: {exc}"
        )
        return ""


# ============================================================
# CSV HEADER
# ============================================================

def normalize_header(value: str) -> str:
    """Normalize VPNGate CSV header names."""

    value = value.strip()

    if value.startswith("#"):
        value = value[1:]

    return value.strip().lower()


def find_header(
    lines: list[str],
) -> tuple[int, list[str]]:
    """
    Find VPNGate CSV header.

    Current VPNGate API normally returns:

    #HostName,IP,Score,Ping,Speed,CountryLong,
    CountryShort,NumVpnSessions,Uptime,TotalUsers,
    TotalTraffic,LogType,Operator,Message,
    OpenVPN_ConfigData_Base64
    """

    # --------------------------------------------------------
    # Direct header search
    # --------------------------------------------------------

    for index, line in enumerate(lines):

        stripped = line.strip()

        if not stripped:
            continue

        if (
            stripped.startswith("#HostName")
            or stripped.startswith("HostName")
        ):
            reader = csv.reader([stripped])

            try:
                header = next(reader)
            except Exception as exc:
                raise RuntimeError(
                    f"Could not parse VPNGate header: {exc}"
                ) from exc

            normalized = [
                normalize_header(column)
                for column in header
            ]

            return index, normalized

    # --------------------------------------------------------
    # Fallback header search
    # --------------------------------------------------------

    for index, line in enumerate(lines):

        stripped = line.strip()

        if not stripped:
            continue

        try:
            reader = csv.reader([stripped])
            row = next(reader)

            normalized = [
                normalize_header(column)
                for column in row
            ]

            if (
                "hostname" in normalized
                and "ip" in normalized
                and (
                    "openvpn_configdata_base64"
                    in normalized
                )
            ):
                return index, normalized

        except Exception:
            continue

    raise RuntimeError(
        "VPNGate CSV header was not found."
    )


# ============================================================
# CSV COLUMN
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
# NUMERIC
# ============================================================

def parse_int(value: str) -> int:
    try:
        return int(float(value))
    except (ValueError, TypeError):
        return 0


# ============================================================
# PROTOCOL AVAILABILITY
# ============================================================

def is_available(value: str) -> bool:
    """
    VPNGate protocol availability.

    Usually:
        0 = unavailable
        1 = available

    Any positive numeric value is treated as available.
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
            "unavailable",
        }


def build_protocols(
    row: list[str],
    header_map: dict[str, int],
    filename: str,
) -> list[dict]:

    protocol_definitions = [
        (
            "udp_443",
            "udp",
            443,
            "udp443",
        ),
        (
            "udp_1194",
            "udp",
            1194,
            "udp1194",
        ),
        (
            "tcp_443",
            "tcp",
            443,
            "tcp443",
        ),
        (
            "tcp_80",
            "tcp",
            80,
            "tcp80",
        ),
        (
            "tcp_1194",
            "tcp",
            1194,
            "tcp1194",
        ),
        (
            "udp_80",
            "udp",
            80,
            "udp80",
        ),
        (
            "udp_53",
            "udp",
            53,
            "udp53",
        ),
    ]

    protocols = []

    for (
        column,
        transport,
        port,
        protocol_id,
    ) in protocol_definitions:

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
# OLD CONFIG CLEANUP
# ============================================================

def clean_old_configs() -> None:
    """Remove previously generated OVPN files."""

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
                f"WARNING: Could not remove "
                f"{file.name}: {exc}"
            )

    print(
        f"Old configs removed: {removed}"
    )


# ============================================================
# SAFE FILENAME
# ============================================================

def safe_filename(hostname: str) -> str:

    name = hostname.strip()

    # Keep only safe filename characters.
    name = re.sub(
        r"[^A-Za-z0-9._-]+",
        "_",
        name,
    )

    # Match the previous filename convention.
    name = name.replace(".", "_")
    name = name.replace("-", "_")

    if not name:
        name = "server"

    return f"{name}.ovpn"


# ============================================================
# OPENVPN CONFIG VALIDATION
# ============================================================

def is_valid_ovpn(config: str) -> bool:

    if not config:
        return False

    lower = config.lower()

    has_client = (
        lower.startswith("client")
        or "\nclient" in lower
    )

    has_remote = (
        "\nremote " in lower
        or lower.startswith("remote ")
    )

    has_certificate = (
        "<ca>" in lower
        or "<cert>" in lower
        or "<key>" in lower
    )

    return (
        has_client
        and has_remote
        and has_certificate
    )


# ============================================================
# NORMALIZE OPENVPN CONFIG
# ============================================================

def normalize_ovpn_config(
    config: str,
    hostname: str,
) -> str:
    """
    Replace an invalid 'remote unknown ...' entry
    with the actual VPNGate hostname.
    """

    lines = config.splitlines()

    updated = []

    for line in lines:

        stripped = line.strip()

        if stripped.startswith("remote "):

            parts = stripped.split()

            if len(parts) >= 2:

                # remote <host> <port>
                if len(parts) >= 3:

                    port = parts[2]

                    # Only replace obvious unknown values.
                    if parts[1].lower() in {
                        "unknown",
                        "localhost",
                        "127.0.0.1",
                    }:
                        updated.append(
                            f"remote {hostname} {port}"
                        )
                        continue

                # remote unknown without port.
                if parts[1].lower() in {
                    "unknown",
                    "localhost",
                    "127.0.0.1",
                }:
                    updated.append(
                        f"remote {hostname} 1194"
                    )
                    continue

        updated.append(line)

    return "\n".join(updated).strip() + "\n"


# ============================================================
# PARSE VPNGATE CSV
# ============================================================

def parse_vpngate_csv(
    csv_content: str,
) -> list[dict]:

    if not csv_content.strip():
        raise RuntimeError(
            "VPNGate response is empty."
        )

    lines = csv_content.splitlines()

    header_index, headers = find_header(lines)

    print()
    print(
        f"CSV header found at line: "
        f"{header_index + 1}"
    )

    print(
        "Columns: "
        + ", ".join(headers)
    )

    header_map = {
        name: index
        for index, name in enumerate(headers)
    }

    # --------------------------------------------------------
    # CURRENT VPNGATE COLUMN NAMES
    # --------------------------------------------------------

    required = [
        "hostname",
        "ip",
        "score",
        "ping",
        "speed",
        "countrylong",
        "countryshort",
        "openvpn_configdata_base64",
    ]

    missing = [
        column
        for column in required
        if column not in header_map
    ]

    if missing:
        raise RuntimeError(
            "VPNGate CSV is missing required "
            "columns: "
            + ", ".join(missing)
        )

    servers = []

    # --------------------------------------------------------
    # CSV READER
    # --------------------------------------------------------

    reader = csv.reader(
        lines[header_index + 1:]
    )

    for row_number, row in enumerate(
        reader,
        start=header_index + 2,
    ):

        if not row:
            continue

        # Ignore comment lines.
        if row[0].strip().startswith("#"):
            continue

        # Make sure the row is not truncated.
        if len(row) < len(headers):

            print(
                f"WARNING: Row {row_number} has "
                f"{len(row)} columns; expected "
                f"{len(headers)}. Skipping."
            )

            continue

        # ----------------------------------------------------
        # SERVER DATA
        # ----------------------------------------------------

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

        score = parse_int(
            get_column(
                row,
                header_map,
                "score",
            )
        )

        ping = parse_int(
            get_column(
                row,
                header_map,
                "ping",
            )
        )

        speed = parse_int(
            get_column(
                row,
                header_map,
                "speed",
            )
        )

        country = get_column(
            row,
            header_map,
            "countrylong",
            "Unknown",
        )

        country_code = get_column(
            row,
            header_map,
            "countryshort",
            "UN",
        )

        config_base64 = get_column(
            row,
            header_map,
            "openvpn_configdata_base64",
        )

        # ----------------------------------------------------
        # BASIC VALIDATION
        # ----------------------------------------------------

        if not hostname:
            continue

        if not config_base64:
            print(
                f"WARNING: {hostname}: "
                f"no OpenVPN config"
            )
            continue

        # ----------------------------------------------------
        # DECODE CONFIG
        # ----------------------------------------------------

        config = safe_base64_decode(
            config_base64
        )

        if not is_valid_ovpn(config):

            print(
                f"WARNING: {hostname}: "
                f"invalid OpenVPN config"
            )

            continue

        # ----------------------------------------------------
        # FILENAME
        # ----------------------------------------------------

        filename = safe_filename(
            hostname
        )

        # ----------------------------------------------------
        # NORMALIZE CONFIG
        # ----------------------------------------------------

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
                f"WARNING: Failed to write "
                f"{filename}: {exc}"
            )

            continue

        # ----------------------------------------------------
        # PROTOCOLS
        # ----------------------------------------------------

        protocols = build_protocols(
            row,
            header_map,
            filename,
        )

        # Do not invent protocols if VPNGate says
        # none are available.
        if not protocols:

            print(
                f"WARNING: {hostname}: "
                f"no available protocol"
            )

            try:
                ovpn_path.unlink()
            except OSError:
                pass

            continue

        # ----------------------------------------------------
        # SERVER ENTRY
        # ----------------------------------------------------

        server = {
            "id": len(servers) + 1,
            "name": (
                f"{country} "
                f"Server {len(servers) + 1}"
            ),
            "host": hostname,
            "ip": ip or hostname,
            "country": country or "Unknown",
            "country_code": country_code or "UN",
            "type": "openvpn",
            "status": "unknown",
            "ping": ping if ping > 0 else None,
            "download_speed": (
                speed if speed > 0 else None
            ),
            "upload_speed": None,
            "protocols": protocols,
            "score": score,
        }

        servers.append(server)

        print(
            f"OK: {hostname} | "
            f"{country} | "
            f"score={score} | "
            f"ping={ping} | "
            f"speed={speed} | "
            f"protocols={len(protocols)}"
        )

    return servers


# ============================================================
# WRITE SERVERS.JSON
# ============================================================

def write_servers_json(
    servers: list[dict],
) -> None:

    if not servers:
        raise RuntimeError(
            "No usable VPNGate servers found."
        )

    # Re-number after sorting/limiting.
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
        # DOWNLOAD
        # ----------------------------------------------------

        csv_content = download_csv()

        # ----------------------------------------------------
        # SANITY CHECK
        # ----------------------------------------------------

        if (
            "HostName" not in csv_content
            and "#HostName" not in csv_content
        ):

            print()
            print(
                "WARNING: Downloaded response does "
                "not look like normal VPNGate CSV."
            )

            print()
            print("First 500 characters:")

            print(
                csv_content[:500]
            )

            raise RuntimeError(
                "VPNGate API did not return "
                "the expected CSV format."
            )

        # ----------------------------------------------------
        # OUTPUT DIRECTORY
        # ----------------------------------------------------

        OUTPUT_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        # ----------------------------------------------------
        # CLEAN OLD CONFIGS
        # ----------------------------------------------------

        clean_old_configs()

        # ----------------------------------------------------
        # PARSE
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
        # SORT BY SCORE
        # ----------------------------------------------------

        servers.sort(
            key=lambda server: (
                server.get("score", 0)
            ),
            reverse=True,
        )

        print()
        print(
            f"Usable servers found: "
            f"{len(servers)}"
        )

        # ----------------------------------------------------
        # LIMIT
        # ----------------------------------------------------

        if len(servers) > MAX_SERVERS:

            print(
                f"Limiting to top "
                f"{MAX_SERVERS} servers."
            )

            servers = servers[:MAX_SERVERS]

        # ----------------------------------------------------
        # WRITE JSON
        # ----------------------------------------------------

        write_servers_json(
            servers
        )

        # ----------------------------------------------------
        # SUMMARY
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
                f"protocols="
                f"{len(server['protocols'])}"
            )

        print()
        print(
            f"Generated: "
            f"{SERVERS_JSON}"
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
