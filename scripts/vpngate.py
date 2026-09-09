#!/usr/bin/env python3

from __future__ import annotations

import base64
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

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


def safe_base64_decode(data: str) -> str:
    """Safely decode base64 string with padding fix."""
    
    if not data:
        return ""
    
    # Remove whitespace and newlines
    data = data.strip()
    
    # Add padding if needed
    missing_padding = len(data) % 4
    if missing_padding:
        data += "=" * (4 - missing_padding)
    
    try:
        decoded = base64.b64decode(data).decode("utf-8", errors="ignore")
        return decoded
    except Exception as e:
        print(f"  ⚠️ Base64 decode error: {e}")
        return ""


def parse_vpngate_csv(csv_content: str) -> list[dict]:
    """
    Parse VPN Gate CSV and extract OpenVPN configs.
    
    VPN Gate CSV Columns (from actual API):
    0: HostName
    1: IP
    2: Score
    3: Country
    4: CountryCode
    5: UDP_443
    6: UDP_1194
    7: TCP_443
    8: TCP_80
    9: TCP_1194
    10: UDP_80
    11: UDP_53
    12: OpenVPN_ConfigData_Base64
    """
    
    lines = csv_content.strip().splitlines()
    
    if not lines:
        return []
    
    servers = []
    
    # ✅ Header ကို ရှာပါ
    header_line = None
    data_start_index = 0
    
    for i, line in enumerate(lines):
        if line.startswith("#HostName") or line.startswith("HostName"):
            header_line = line
            data_start_index = i + 1
            break
    
    if not header_line:
        # Header မတွေ့ရင် ပထမစာကြောင်းကို header အဖြစ်ယူဆ
        header_line = lines[0]
        data_start_index = 1
    
    print(f"Header: {header_line[:100]}...")
    
    # ✅ CSV reader နဲ့ parse လုပ်ပါ
    for line in lines[data_start_index:]:
        if not line.strip():
            continue
        
        # CSV row ကို parse လုပ်ပါ
        reader = csv.reader([line])
        try:
            row = next(reader)
        except Exception as e:
            print(f"  ⚠️ CSV parse error: {e}")
            continue
        
        # အနည်းဆုံး 13 columns ရှိရပါမယ်
        if len(row) < 13:
            print(f"  ⚠️ Skipping row: only {len(row)} columns")
            continue
        
        # ✅ Column index အတိုင်း ယူပါ
        hostname = row[0].strip()
        ip = row[1].strip()
        score_str = row[2].strip()
        country = row[3].strip()
        country_code = row[4].strip()
        udp_443 = row[5].strip()
        udp_1194 = row[6].strip()
        tcp_443 = row[7].strip()
        tcp_80 = row[8].strip()
        tcp_1194 = row[9].strip()
        udp_80 = row[10].strip()
        udp_53 = row[11].strip()
        config_base64 = row[12].strip() if len(row) > 12 else ""
        
        # Skip if no hostname
        if not hostname:
            continue
        
        # ✅ Base64 ကို safe ဖြစ်အောင် decode လုပ်ပါ
        config_data = safe_base64_decode(config_base64)
        
        if not config_data:
            print(f"  ⚠️ No config data for {hostname}")
            continue
        
        # ✅ OpenVPN config ဖြစ်မဖြစ် စစ်ဆေးပါ
        if not any(keyword in config_data for keyword in ["client", "remote", "<ca>"]):
            print(f"  ⚠️ Invalid OpenVPN config for {hostname}")
            continue
        
        # ✅ Hostname ကို safe filename အဖြစ် ပြောင်းပါ
        safe_hostname = hostname.replace(".", "_").replace("-", "_")
        filename = f"{safe_hostname}.ovpn"
        
        # ✅ Config ထဲက remote hostname ကို update လုပ်ပါ
        config_lines = config_data.splitlines()
        updated_config = []
        
        for line in config_lines:
            if line.startswith("remote ") and "unknown" in line:
                # Replace with actual hostname
                parts = line.split()
                if len(parts) >= 2:
                    updated_config.append(f"remote {hostname} {parts[2] if len(parts) > 2 else '1194'}")
                else:
                    updated_config.append(f"remote {hostname} 1194")
            elif line.startswith("remote "):
                # Already has correct hostname, keep it
                updated_config.append(line)
            else:
                updated_config.append(line)
        
        config_data = "\n".join(updated_config)
        
        # Save OVPN file
        ovpn_path = OUTPUT_DIR / filename
        try:
            ovpn_path.write_text(config_data, encoding="utf-8")
        except Exception as e:
            print(f"  ⚠️ Failed to write file {filename}: {e}")
            continue
        
        # Determine available protocols
        protocols = []
        
        # Protocol mapping: (column_data, transport, port, protocol_id)
        protocol_list = [
            (udp_443, "udp", 443, "udp443"),
            (udp_1194, "udp", 1194, "udp1194"),
            (udp_80, "udp", 80, "udp80"),
            (udp_53, "udp", 53, "udp53"),
            (tcp_443, "tcp", 443, "tcp443"),
            (tcp_80, "tcp", 80, "tcp80"),
            (tcp_1194, "tcp", 1194, "tcp1194"),
        ]
        
        for data_val, transport, port, proto_id in protocol_list:
            # Check if protocol is available (not empty and not "0")
            if data_val and data_val != "0":
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
        
        # Score
        try:
            score = int(score_str) if score_str else 0
        except ValueError:
            score = 0
        
        # ✅ မှန်ကန်တဲ့ data တွေကို သိမ်းပါ
        server_entry = {
            "id": len(servers) + 1,
            "name": f"{country} Server {len(servers) + 1}",
            "host": hostname,
            "ip": ip if ip else hostname,
            "country": country if country else "Unknown",
            "country_code": country_code if country_code else "UN",
            "type": "openvpn",
            "status": "unknown",
            "ping": None,
            "download_speed": None,
            "upload_speed": None,
            "protocols": protocols,
            "score": score
        }
        
        servers.append(server_entry)
        print(f"✅ {hostname} ({country}) - {len(protocols)} protocols")
    
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
        
        # Limit to top 50 servers
        if len(servers) > 50:
            print(f"Limiting to top 50 servers (out of {len(servers)})")
            servers = servers[:50]
        
        write_servers_json(servers)
        
        print()
        print("=" * 60)
        print("UPDATE COMPLETE")
        print("=" * 60)
        
        for server in servers[:10]:
            print(f"- {server['host']} ({server['country']}): {len(server['protocols'])} protocols")
        
        return 0
        
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except Exception as exc:
        print()
        print(f"FATAL ERROR: {exc}")
        import traceback
        traceback.print_tb(exc.__traceback__)
        return 1


if __name__ == "__main__":
    sys.exit(main())
