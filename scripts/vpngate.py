#!/usr/bin/env python3

from __future__ import annotations

import base64
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen
import socket

VPNGATE_API = "https://www.vpngate.net/api/iphone/"

OUTPUT_DIR = Path("output/openvpn")
SERVERS_JSON = OUTPUT_DIR / "servers.json"

USER_AGENT = (
    "Mozilla/5.0 "
    "(compatible; VPNGateUpdater/1.0)"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")


def download_csv() -> str:
    """Download VPN Gate server list as CSV."""
    
    request = Request(
        VPNGATE_API,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/csv,*/*",
        },
    )
    
    with urlopen(request, timeout=60) as response:
        return response.read().decode("utf-8", errors="ignore")


def parse_vpngate_csv(csv_content: str) -> list[dict]:
    """Parse VPN Gate CSV and extract OpenVPN configs."""
    
    lines = csv_content.strip().splitlines()
    
    # VPN Gate CSV headers
    headers = [
        "Country", "CountryCode", "Score", "IP", "Hostname",
        "UDP_443", "UDP_1194", "TCP_443", "TCP_80", "TCP_1194",
        "UDP_80", "UDP_53", "OpenVPN_ConfigData_Base64"
    ]
    
    servers = []
    
    reader = csv.reader(lines)
    
    for row in reader:
        if len(row) < len(headers):
            continue
            
        # Map row to dict
        data = dict(zip(headers, row))
        
        # Skip if no OpenVPN config
        if not data.get("OpenVPN_ConfigData_Base64"):
            continue
        
        # Decode OpenVPN config
        try:
            config_data = base64.b64decode(
                data["OpenVPN_ConfigData_Base64"]
            ).decode("utf-8", errors="ignore")
        except Exception:
            continue
        
        # Skip if config is empty
        if not config_data.strip():
            continue
        
        hostname = data["Hostname"].strip()
        
        # Skip if no hostname
        if not hostname:
            continue
        
        # Generate filename
        filename = f"{hostname}.ovpn"
        
        # Save OVPN file
        ovpn_path = OUTPUT_DIR / filename
        ovpn_path.write_text(config_data, encoding="utf-8")
        
        # Determine available protocols
        protocols = []
        
        protocol_mapping = [
            ("udp", 53, "udp53"),
            ("udp", 80, "udp80"),
            ("udp", 443, "udp443"),
            ("udp", 1194, "udp1194"),
            ("tcp", 80, "tcp80"),
            ("tcp", 443, "tcp443"),
            ("tcp", 1194, "tcp1194"),
        ]
        
        for transport, port, proto_id in protocol_mapping:
            # Check if this protocol has data (non-empty)
            port_key = f"{transport.upper()}_{port}"
            if data.get(port_key, "").strip():
                protocols.append({
                    "id": proto_id,
                    "transport": transport,
                    "port": port,
                    "file": filename,
                    "available": True,
                })
        
        # If no specific protocols found, add generic ones
        if not protocols:
            protocols = [
                {"id": "udp1194", "transport": "udp", "port": 1194, "file": filename, "available": True},
                {"id": "udp53", "transport": "udp", "port": 53, "file": filename, "available": True},
                {"id": "tcp443", "transport": "tcp", "port": 443, "file": filename, "available": True},
                {"id": "tcp80", "transport": "tcp", "port": 80, "file": filename, "available": True},
            ]
        
        # Get IP
        ip = data.get("IP", "").strip()
        
        # Get country
        country = data.get("Country", "Unknown").strip()
        country_code = data.get("CountryCode", "UN").strip()
        
        servers.append({
            "id": len(servers) + 1,
            "name": f"{country} Server {len(servers) + 1}",
            "host": hostname,
            "ip": ip,
            "country": country,
            "country_code": country_code,
            "type": "openvpn",
            "status": "unknown",
            "ping": None,
            "download_speed": None,
            "upload_speed": None,
            "protocols": protocols,
            "score": int(data.get("Score", 0))
        })
        
        print(f"✅ Added {hostname} ({len(protocols)} protocols)")
    
    return servers


def clean_old_configs() -> None:
    """Remove old .ovpn files."""
    
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    for file in OUTPUT_DIR.glob("*.ovpn"):
        try:
            file.unlink()
            print(f"Removed old config: {file.name}")
        except Exception as exc:
            print(f"WARNING: Could not remove {file}: {exc}")


def write_servers_json(servers: list[dict]) -> None:
    """Write servers.json file."""
    
    if not servers:
        raise RuntimeError("No VPN Gate servers found.")
    
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
    
    SERVERS_JSON.write_text(
        json.dumps(output, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    
    print()
    print(f"✅ Wrote {SERVERS_JSON}")
    print(f"Active servers: {len(servers)}")


def main() -> int:
    print("=" * 60)
    print("VPN Gate OpenVPN Updater")
    print("=" * 60)
    
    try:
        print("Downloading VPN Gate server list...")
        csv_content = download_csv()
        
        print("Parsing servers...")
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        clean_old_configs()
        
        servers = parse_vpngate_csv(csv_content)
        
        if not servers:
            raise RuntimeError("No VPN Gate servers found.")
        
        # Sort by score (higher is better)
        servers.sort(key=lambda x: x.get("score", 0), reverse=True)
        
        write_servers_json(servers)
        
        print()
        print("=" * 60)
        print("UPDATE COMPLETE")
        print("=" * 60)
        
        for server in servers[:10]:
            print(f"- {server['host']}: {len(server['protocols'])} protocols")
        
        return 0
        
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except Exception as exc:
        print()
        print(f"FATAL ERROR: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
