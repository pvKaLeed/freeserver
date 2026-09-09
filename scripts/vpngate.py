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
MAX_PER_COUNTRY = 3  # Country တစ်ခုကို အများဆုံး ၃ ခုပဲ ထားမယ်

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
            raise RuntimeError("VPNGate returned empty response.")

        return raw.decode("utf-8", errors="replace")

    except HTTPError as exc:
        raise RuntimeError(f"VPNGate HTTP error {exc.code}: {exc.reason}") from exc
    except URLError as exc:
        raise RuntimeError(f"VPNGate connection error: {exc.reason}") from exc
    except TimeoutError as exc:
        raise RuntimeError("VPNGate request timed out.") from exc


# ============================================================
# BASE64
# ============================================================

def safe_base64_decode(data: str) -> str:
    if not data:
        return ""

    data = data.strip()
    data = re.sub(r"\s+", "", data)
    data = data.replace("-", "+")
    data = data.replace("_", "/")

    remainder = len(data) % 4
    if remainder:
        data += "=" * (4 - remainder)

    try:
        decoded = base64.b64decode(data, validate=False)
        return decoded.decode("utf-8", errors="replace")
    except Exception as exc:
        print(f"WARNING: Base64 decode failed: {exc}")
        return ""


# ============================================================
# HEADER
# ============================================================

def normalize_header(value: str) -> str:
    value = value.strip()
    if value.startswith("#"):
        value = value[1:]
    return value.strip().lower()


def find_header(lines: list[str]) -> tuple[int, list[str]]:
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#HostName") or stripped.startswith("HostName"):
            reader = csv.reader([stripped])
            header = next(reader)
            return index, [normalize_header(x) for x in header]

    raise RuntimeError("VPNGate CSV header was not found.")


# ============================================================
# CSV COLUMN
# ============================================================

def get_column(row: list[str], header_map: dict[str, int], name: str, default: str = "") -> str:
    index = header_map.get(name)
    if index is None or index >= len(row):
        return default
    return row[index].strip()


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
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    name = name.replace(".", "_").replace("-", "_")
    if not name:
        name = "server"
    return f"{name}.ovpn"


# ============================================================
# OVPN VALIDATION & PARSING
# ============================================================

def is_valid_ovpn(config: str) -> bool:
    if not config:
        return False
    lower = config.lower()
    return (
        (lower.startswith("client") or "\nclient" in lower)
        and (lower.startswith("remote ") or "\nremote " in lower)
        and (lower.startswith("proto ") or "\nproto " in lower)
        and "<ca>" in lower
    )


def parse_ovpn_protocols(config: str, filename: str) -> list[dict]:
    lines = config.splitlines()
    current_proto = None
    protocols = []
    seen = set()

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split()
        if not parts:
            continue

        directive = parts[0].lower()

        if directive == "proto" and len(parts) >= 2:
            proto = parts[1].lower()
            if proto in {"udp", "tcp", "tcp-client", "udp4", "udp6", "tcp4-client", "tcp6-client"}:
                current_proto = "tcp" if proto.startswith("tcp") else "udp"

        elif directive == "remote" and len(parts) >= 2:
            port = 1194
            if len(parts) >= 3:
                try:
                    port = int(parts[2].strip())
                except ValueError:
                    port = 1194

            transport = current_proto or "udp"
            key = (transport, port)
            if key in seen:
                continue
            seen.add(key)

            protocols.append({
                "id": f"{transport}{port}",
                "transport": transport,
                "port": port,
                "file": filename,
                "available": True,
            })

    return protocols


def enhance_ovpn_config(config: str, hostname: str) -> str:
    """Add missing directives to OVPN config."""
    lines = config.splitlines()
    output = []
    has_auth = False
    has_verb = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("remote "):
            parts = stripped.split()
            if len(parts) >= 2 and parts[1].lower() in {"unknown", "localhost", "127.0.0.1"}:
                port = parts[2] if len(parts) >= 3 else "1194"
                output.append(f"remote {hostname} {port}")
                continue
        elif "auth-user-pass" in stripped.lower():
            has_auth = True
        elif "verb" in stripped.lower():
            has_verb = True

        output.append(line)

    if not has_auth:
        output.append("auth-user-pass")
    if not has_verb:
        output.append("verb 3")

    return "\n".join(output).strip() + "\n"


# ============================================================
# CLEAN OLD CONFIGS
# ============================================================

def clean_old_configs() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    removed = 0
    for file in OUTPUT_DIR.glob("*.ovpn"):
        try:
            file.unlink()
            removed += 1
        except OSError as exc:
            print(f"WARNING: Could not remove {file.name}: {exc}")
    print(f"Old configs removed: {removed}")


# ============================================================
# GROUP SERVERS BY COUNTRY
# ============================================================

def group_servers_by_country(servers: list[dict]) -> list[dict]:
    """Keep only the best servers per country."""
    country_map = {}

    for server in servers:
        country = server.get("country", "Unknown")
        if country not in country_map:
            country_map[country] = []
        country_map[country].append(server)

    # Sort each country's servers by score (highest first)
    for country in country_map:
        country_map[country].sort(key=lambda s: s.get("score", 0), reverse=True)
        # Keep only top MAX_PER_COUNTRY
        country_map[country] = country_map[country][:MAX_PER_COUNTRY]

    result = []
    for servers_list in country_map.values():
        result.extend(servers_list)

    return result


# ============================================================
# PARSE VPNGATE CSV
# ============================================================

def parse_vpngate_csv(csv_content: str) -> list[dict]:
    if not csv_content.strip():
        raise RuntimeError("VPNGate response is empty.")

    lines = csv_content.splitlines()
    header_index, headers = find_header(lines)

    print(f"CSV header found at line: {header_index + 1}")
    print("Columns:", ", ".join(headers))

    header_map = {name: index for index, name in enumerate(headers)}

    # Required columns
    required = [
        "hostname", "ip", "score", "ping", "speed",
        "countrylong", "countryshort", "openvpn_configdata_base64"
    ]

    missing = [col for col in required if col not in header_map]
    if missing:
        raise RuntimeError(f"VPNGate CSV missing columns: {', '.join(missing)}")

    servers = []
    reader = csv.reader(lines[header_index + 1:])

    for row_number, row in enumerate(reader, start=header_index + 2):
        if not row or len(row) < len(headers):
            continue
        if row[0].strip().startswith("#"):
            continue

        hostname = get_column(row, header_map, "hostname")
        if not hostname:
            continue

        config_base64 = get_column(row, header_map, "openvpn_configdata_base64")
        if not config_base64:
            print(f"WARNING: {hostname}: no OpenVPN config")
            continue

        config = safe_base64_decode(config_base64)
        if not config or not is_valid_ovpn(config):
            print(f"WARNING: {hostname}: invalid OpenVPN config")
            continue

        filename = safe_filename(hostname)
        config = enhance_ovpn_config(config, hostname)
        protocols = parse_ovpn_protocols(config, filename)

        if not protocols:
            print(f"WARNING: {hostname}: no protocol found")
            continue

        ovpn_path = OUTPUT_DIR / filename
        try:
            ovpn_path.write_text(config, encoding="utf-8")
        except OSError as exc:
            print(f"WARNING: Failed to write {filename}: {exc}")
            continue

        # Extract data
        ip = get_column(row, header_map, "ip")
        score = parse_int(get_column(row, header_map, "score"))
        ping = parse_int(get_column(row, header_map, "ping"))
        speed = parse_int(get_column(row, header_map, "speed"))
        country = get_column(row, header_map, "countrylong", "Unknown")
        country_code = get_column(row, header_map, "countryshort", "UN")

        # Determine status based on ping
        if ping > 0 and ping < 200:
            status = "online"
        elif ping > 0:
            status = "slow"
        else:
            status = "unknown"

        server = {
            "id": len(servers) + 1,
            "name": f"{country} Server {len(servers) + 1}",
            "host": hostname,
            "ip": ip if ip else hostname,
            "country": country,
            "country_code": country_code,
            "type": "openvpn",
            "status": status,
            "ping": ping if ping > 0 else None,
            "download_speed": speed if speed > 0 else None,
            "upload_speed": None,
            "protocols": protocols,
            "score": score,
        }

        servers.append(server)
        print(f"OK: {hostname} | {country} | score={score} | ping={ping} | protocols={len(protocols)}")

    return servers


# ============================================================
# WRITE JSON
# ============================================================

def write_servers_json(servers: list[dict]) -> None:
    if not servers:
        raise RuntimeError("No usable VPNGate servers found.")

    for index, server in enumerate(servers, start=1):
        server["id"] = index
        server["name"] = f"{server.get('country', 'Unknown')} Server {index}"

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
            {"id": "udp1194", "transport": "udp", "port": 1194, "priority": 1},
            {"id": "udp443", "transport": "udp", "port": 443, "priority": 2},
            {"id": "udp80", "transport": "udp", "port": 80, "priority": 3},
            {"id": "udp53", "transport": "udp", "port": 53, "priority": 4},
            {"id": "tcp443", "transport": "tcp", "port": 443, "priority": 5},
            {"id": "tcp80", "transport": "tcp", "port": 80, "priority": 6},
            {"id": "tcp1194", "transport": "tcp", "port": 1194, "priority": 7},
        ],
        "servers": servers,
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    SERVERS_JSON.write_text(
        json.dumps(output, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print(f"Written: {SERVERS_JSON}")
    print(f"Active servers: {len(servers)}")


# ============================================================
# MAIN
# ============================================================

def main() -> int:
    print("=" * 70)
    print("VPN Gate OpenVPN Updater (Enhanced)")
    print("=" * 70)

    try:
        csv_content = download_csv()

        if "HostName" not in csv_content and "#HostName" not in csv_content:
            print("WARNING: Response does not look like VPNGate CSV.")
            print(csv_content[:500])
            raise RuntimeError("VPNGate API returned unexpected data.")

        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        clean_old_configs()

        print("Parsing VPNGate servers...")
        servers = parse_vpngate_csv(csv_content)

        if not servers:
            raise RuntimeError("No usable VPNGate servers found.")

        # Sort by score
        servers.sort(key=lambda s: s.get("score", 0), reverse=True)

        # Group by country (limit per country)
        servers = group_servers_by_country(servers)

        # Limit total
        if len(servers) > MAX_SERVERS:
            print(f"Limiting to top {MAX_SERVERS} servers.")
            servers = servers[:MAX_SERVERS]

        write_servers_json(servers)

        print("\n" + "=" * 70)
        print("UPDATE COMPLETE")
        print("=" * 70)

        for server in servers[:10]:
            print(f"{server['id']:>2}. {server['host']} | {server['country']} | "
                  f"score={server['score']} | ping={server['ping']} | "
                  f"protocols={len(server['protocols'])}")

        return 0

    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except Exception as exc:
        print("\n" + "=" * 70)
        print("FATAL ERROR")
        print("=" * 70)
        print(f"{type(exc).__name__}: {exc}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
