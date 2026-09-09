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

MAX_SERVERS = 50

USER_AGENT = (
    "Mozilla/5.0 "
    "(Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 "
    "(KHTML, like Gecko) "
    "Chrome/140.0 Safari/537.36"
)


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
                "VPNGate returned empty response."
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

    if not data:
        return ""

    data = data.strip()

    # Remove whitespace
    data = re.sub(r"\s+", "", data)

    # URL-safe Base64 support
    data = data.replace("-", "+")
    data = data.replace("_", "/")

    # Fix padding
    remainder = len(data) % 4

    if remainder:
        data += "=" * (4 - remainder)

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
# HEADER
# ============================================================

def normalize_header(value: str) -> str:

    value = value.strip()

    if value.startswith("#"):
        value = value[1:]

    return value.strip().lower()


def find_header(
    lines: list[str],
) -> tuple[int, list[str]]:

    for index, line in enumerate(lines):

        stripped = line.strip()

        if not stripped:
            continue

        if (
            stripped.startswith("#HostName")
            or stripped.startswith("HostName")
        ):

            reader = csv.reader([stripped])
            header = next(reader)

            return (
                index,
                [
                    normalize_header(x)
                    for x in header
                ],
            )

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
# NUMBER
# ============================================================

def parse_int(value: str) -> int:

    try:
        return int(float(value))
    except (ValueError, TypeError):
        return 0


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
# OVPN VALIDATION
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
        lower.startswith("remote ")
        or "\nremote " in lower
    )

    has_proto = (
        lower.startswith("proto ")
        or "\nproto " in lower
    )

    has_ca = "<ca>" in lower

    return (
        has_client
        and has_remote
        and has_proto
        and has_ca
    )


# ============================================================
# OVPN PROTOCOL PARSER
# ============================================================

def parse_ovpn_protocols(
    config: str,
    filename: str,
) -> list[dict]:
    """
    Read actual protocol/port information from
    the decoded OpenVPN configuration.

    Example:

        proto udp
        remote 219.100.37.81 1194

    becomes:

        udp1194
    """

    lines = config.splitlines()

    current_proto = None

    protocols = []

    seen = set()

    # --------------------------------------------------------
    # Find proto
    # --------------------------------------------------------

    for line in lines:

        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        parts = line.split()

        if not parts:
            continue

        directive = parts[0].lower()

        if directive == "proto" and len(parts) >= 2:

            proto = parts[1].lower()

            if proto in {
                "udp",
                "tcp",
                "tcp-client",
                "udp4",
                "udp6",
                "tcp4-client",
                "tcp6-client",
            }:

                if proto.startswith("tcp"):
                    current_proto = "tcp"
                else:
                    current_proto = "udp"

        elif directive == "remote" and len(parts) >= 2:

            host = parts[1]

            # OpenVPN syntax:
            #
            # remote HOST PORT
            #
            # PORT can be absent.

            port = 1194

            if len(parts) >= 3:

                raw_port = parts[2].strip()

                try:
                    port = int(raw_port)

                except ValueError:
                    # Could be a hostname/service name.
                    # Keep default OpenVPN port.
                    port = 1194

            transport = current_proto or "udp"

            protocol_id = (
                f"{transport}{port}"
            )

            key = (
                transport,
                port,
            )

            if key in seen:
                continue

            seen.add(key)

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
# OVPN NORMALIZATION
# ============================================================

def normalize_ovpn_config(
    config: str,
    hostname: str,
) -> str:

    lines = config.splitlines()

    output = []

    for line in lines:

        stripped = line.strip()

        if stripped.startswith("remote "):

            parts = stripped.split()

            if len(parts) >= 2:

                remote_host = parts[1]

                if remote_host.lower() in {
                    "unknown",
                    "localhost",
                    "127.0.0.1",
                }:

                    if len(parts) >= 3:
                        port = parts[2]
                    else:
                        port = "1194"

                    output.append(
                        f"remote {hostname} {port}"
                    )

                    continue

        output.append(line)

    return "\n".join(output).strip() + "\n"


# ============================================================
# CLEAN OLD CONFIGS
# ============================================================

def clean_old_configs() -> None:

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
    # IMPORTANT:
    #
    # Current VPNGate API:
    #
    # HostName
    # IP
    # Score
    # Ping
    # Speed
    # CountryLong
    # CountryShort
    # NumVpnSessions
    # Uptime
    # TotalUsers
    # TotalTraffic
    # LogType
    # Operator
    # Message
    # OpenVPN_ConfigData_Base64
    #
    # There are NO protocol columns here.
    # Protocol is extracted from the decoded OVPN.
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

    reader = csv.reader(
        lines[header_index + 1:]
    )

    for row_number, row in enumerate(
        reader,
        start=header_index + 2,
    ):

        # ----------------------------------------------------
        # Empty row
        # ----------------------------------------------------

        if not row:
            continue

        # ----------------------------------------------------
        # VPNGate sometimes has a trailing/malformed row.
        # Do not fail the whole update.
        # ----------------------------------------------------

        if len(row) < len(headers):

            print(
                f"WARNING: Row {row_number} has "
                f"{len(row)} columns; expected "
                f"{len(headers)}. Skipping."
            )

            continue

        # ----------------------------------------------------
        # Comment
        # ----------------------------------------------------

        if row[0].strip().startswith("#"):
            continue

        # ----------------------------------------------------
        # DATA
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
        # Basic validation
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
        # Decode
        # ----------------------------------------------------

        config = safe_base64_decode(
            config_base64
        )

        if not config:
            print(
                f"WARNING: {hostname}: "
                f"Base64 decode failed"
            )
            continue

        # ----------------------------------------------------
        # Validate
        # ----------------------------------------------------

        if not is_valid_ovpn(config):

            print(
                f"WARNING: {hostname}: "
                f"invalid OpenVPN config"
            )

            continue

        # ----------------------------------------------------
        # Filename
        # ----------------------------------------------------

        filename = safe_filename(
            hostname
        )

        # ----------------------------------------------------
        # Normalize remote
        # ----------------------------------------------------

        config = normalize_ovpn_config(
            config,
            hostname,
        )

        # ----------------------------------------------------
        # Parse protocols FROM OVPN
        # ----------------------------------------------------

        protocols = parse_ovpn_protocols(
            config,
            filename,
        )

        if not protocols:

            print(
                f"WARNING: {hostname}: "
                f"could not detect protocol/port"
            )

            continue

        # ----------------------------------------------------
        # Save OVPN
        # ----------------------------------------------------

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
        # Server
        # ----------------------------------------------------

        server = {
            "id": len(servers) + 1,

            "name": (
                f"{country} "
                f"Server {len(servers) + 1}"
            ),

            "host": hostname,

            "ip": (
                ip
                if ip
                else hostname
            ),

            "country": (
                country
                if country
                else "Unknown"
            ),

            "country_code": (
                country_code
                if country_code
                else "UN"
            ),

            "type": "openvpn",

            "status": "unknown",

            "ping": (
                ping
                if ping > 0
                else None
            ),

            "download_speed": (
                speed
                if speed > 0
                else None
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
# WRITE JSON
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

        server["name"] = (
            f"{server.get('country', 'Unknown')} "
            f"Server {index}"
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

        # ----------------------------------------------------
        # Check response
        # ----------------------------------------------------

        if (
            "HostName" not in csv_content
            and "#HostName" not in csv_content
        ):

            print()
            print(
                "WARNING: Response does not look "
                "like VPNGate CSV."
            )

            print()
            print(
                csv_content[:500]
            )

            raise RuntimeError(
                "VPNGate API returned unexpected data."
            )

        # ----------------------------------------------------
        # Prepare directory
        # ----------------------------------------------------

        OUTPUT_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        # ----------------------------------------------------
        # Clean old OVPN files
        # ----------------------------------------------------

        clean_old_configs()

        # ----------------------------------------------------
        # Parse
        # ----------------------------------------------------

        print()
        print(
            "Parsing VPNGate servers..."
        )

        servers = parse_vpngate_csv(
            csv_content
        )

        if not servers:
            raise RuntimeError(
                "No usable VPNGate servers found."
            )

        # ----------------------------------------------------
        # Sort by score
        # ----------------------------------------------------

        servers.sort(
            key=lambda server: (
                server.get(
                    "score",
                    0,
                )
            ),
            reverse=True,
        )

        print()
        print(
            f"Usable servers found: "
            f"{len(servers)}"
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
        # Write
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
                f"ping={server['ping']} | "
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
