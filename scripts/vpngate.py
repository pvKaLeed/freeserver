#!/usr/bin/env python3

from __future__ import annotations

import base64
import csv
import json
import re
import sys
import socket
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

PING_TIMEOUT = 3
MAX_SERVERS = 50
MAX_PER_COUNTRY = 3

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
    print(f"📥 Downloading: {VPNGATE_API}")

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

        print(f"📊 Downloaded: {len(raw):,} bytes")

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
        print(f"  ⚠️ Base64 decode failed: {exc}")
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
# ✅ ACTIVE SERVER CHECK
# ============================================================

def check_server_active(host: str, ip: str = None) -> bool:
    """Check if server is reachable via TCP connection."""
    try:
        target = ip if ip else host
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(PING_TIMEOUT)
            # Try port 443 first (most common)
            result = sock.connect_ex((target, 443))
            if result == 0:
                return True
            # Try port 80 as fallback
            result = sock.connect_ex((target, 80))
            return result == 0
    except Exception:
        return False


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
# ✅ OVPN ENHANCEMENT (FIX CONFIG)
# ============================================================

def enhance_ovpn_config(config: str, hostname: str) -> str:
    """
    Fix OpenVPN config file for SoftEther VPN:
    1. Uncomment auth-user-pass
    2. Fix remote hostname and port
    3. Add missing proto
    4. Add verb
    """
    lines = config.splitlines()
    output = []
    has_auth = False
    has_verb = False
    has_remote = False
    has_proto = False

    for line in lines:
        stripped = line.strip()

        # ✅ Uncomment auth-user-pass (SoftEther VPN comments it)
        if stripped.startswith("#auth-user-pass"):
            output.append("auth-user-pass")
            has_auth = True
            continue

        # ✅ Fix remote
        if stripped.startswith("remote "):
            parts = stripped.split()
            if len(parts) >= 2:
                # Replace with correct hostname and port 443
                output.append(f"remote {hostname} 443")
                has_remote = True
                continue

        # ✅ Fix proto
        if stripped.startswith("proto "):
            parts = stripped.split()
            if len(parts) >= 2:
                # Keep as is - will be handled by Android app
                output.append(line)
                has_proto = True
                continue

        # Check for existing auth
        if "auth-user-pass" in stripped.lower() and not stripped.startswith("#"):
            has_auth = True

        # Check for verb
        if "verb" in stripped.lower():
            has_verb = True

        output.append(line)

    # ✅ Add missing directives
    if not has_remote:
        output.append(f"remote {hostname} 443")
    if not has_auth:
        output.append("auth-user-pass")
    if not has_verb:
        output.append("verb 3")
    if not has_proto:
        output.append("proto udp")

    return "\n".join(output).strip() + "\n"


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
    """Parse protocol and port from OVPN config."""
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
    if removed > 0:
        print(f"🗑️ Removed {removed} old configs")


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

    for country in country_map:
        country_map[country].sort(key=lambda s: s.get("score", 0), reverse=True)
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

    print(f"\n📋 CSV header at line: {header_index + 1}")
    print(f"📋 Columns: {', '.join(headers[:8])}...")

    header_map = {name: index for index, name in enumerate(headers)}

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

        # Extract data by column index
        hostname = row[0].strip()
        if not hostname:
            continue

        ip = row[1].strip() if len(row) > 1 else ""
        score = parse_int(row[2].strip()) if len(row) > 2 else 0
        ping = parse_int(row[3].strip()) if len(row) > 3 else 0
        speed = parse_int(row[4].strip()) if len(row) > 4 else 0
        country = row[5].strip() if len(row) > 5 else "Unknown"
        country_code = row[6].strip() if len(row) > 6 else "UN"
        num_sessions = parse_int(row[7].strip()) if len(row) > 7 else 0
        uptime = row[8].strip() if len(row) > 8 else "0%"
        config_base64 = row[14].strip() if len(row) > 14 else ""

        if not config_base64:
            continue

        # ✅ Check if server has active sessions OR is reachable
        is_active = False
        if num_sessions > 0:
            print(f"  ✅ {hostname}: {num_sessions} active sessions")
            is_active = True
        else:
            # Try TCP connection check
            print(f"  🔍 Checking {hostname}...", end=" ")
            is_active = check_server_active(hostname, ip)
            if is_active:
                print("✅ Active")
            else:
                print("❌ Inactive")
                continue

        # Decode config
        config = safe_base64_decode(config_base64)
        if not config or not is_valid_ovpn(config):
            print(f"  ⚠️ {hostname}: invalid OpenVPN config")
            continue

        # ✅ Enhance OVPN config (fix auth-user-pass, remote, etc.)
        config = enhance_ovpn_config(config, hostname)

        # Save OVPN file
        filename = safe_filename(hostname)
        protocols = parse_ovpn_protocols(config, filename)

        if not protocols:
            print(f"  ⚠️ {hostname}: no protocol found")
            continue

        ovpn_path = OUTPUT_DIR / filename
        try:
            ovpn_path.write_text(config, encoding="utf-8")
        except OSError as exc:
            print(f"  ⚠️ Failed to write {filename}: {exc}")
            continue

        # Build server entry
        server = {
            "id": len(servers) + 1,
            "name": f"{country} Server {len(servers) + 1}",
            "host": hostname,
            "ip": ip if ip else hostname,
            "country": country,
            "country_code": country_code,
            "type": "openvpn",
            "status": "online" if is_active else "unknown",
            "ping": ping if ping > 0 else None,
            "download_speed": speed if speed > 0 else None,
            "upload_speed": None,
            "protocols": protocols,
            "score": score,
            "ovpn_file": filename,  # ✅ Link to OVPN file
            "num_sessions": num_sessions,
            "uptime": uptime
        }

        servers.append(server)
        print(f"  ✅ Added {hostname} | {country} | score={score} | sessions={num_sessions}")

    return servers


# ============================================================
# WRITE JSON
# ============================================================

def write_servers_json(servers: list[dict]) -> None:
    if not servers:
        raise RuntimeError("No usable VPNGate servers found.")

    # Re-number after sorting
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

    print(f"\n✅ Written: {SERVERS_JSON}")
    print(f"✅ Active servers: {len(servers)}")


# ============================================================
# MAIN
# ============================================================

def main() -> int:
    print("=" * 70)
    print("🌐 VPN Gate OpenVPN Updater")
    print("=" * 70)

    try:
        csv_content = download_csv()

        if "HostName" not in csv_content and "#HostName" not in csv_content:
            print("\n⚠️ Response does not look like VPNGate CSV.")
            print(csv_content[:500])
            raise RuntimeError("VPNGate API returned unexpected data.")

        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        clean_old_configs()

        print("\n📊 Parsing VPNGate servers...")
        servers = parse_vpngate_csv(csv_content)

        if not servers:
            raise RuntimeError("No usable VPNGate servers found.")

        # Sort by score
        servers.sort(key=lambda s: s.get("score", 0), reverse=True)

        # Group by country (limit per country)
        servers = group_servers_by_country(servers)

        # Limit total
        if len(servers) > MAX_SERVERS:
            print(f"\n📊 Limiting to top {MAX_SERVERS} servers.")
            servers = servers[:MAX_SERVERS]

        write_servers_json(servers)

        print("\n" + "=" * 70)
        print("✅ UPDATE COMPLETE")
        print("=" * 70)

        for server in servers[:10]:
            print(f"{server['id']:>2}. {server['host']} | {server['country']} | "
                  f"sessions={server.get('num_sessions', 0)} | protocols={len(server['protocols'])}")
            print(f"   📄 OVPN: {server.get('ovpn_file', 'MISSING')}")

        return 0

    except KeyboardInterrupt:
        print("\n⏹️ Interrupted.")
        return 130
    except Exception as exc:
        print(f"\n❌ FATAL ERROR: {exc}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
