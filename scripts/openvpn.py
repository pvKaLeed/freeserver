
#!/usr/bin/env python3

from __future__ import annotations

import json
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen


VPNBOOK_API = "https://www.vpnbook.com/api/openvpn"
VPNBOOK_PAGE = "https://www.vpnbook.com/freevpn/openvpn"

OUTPUT_DIR = Path("output/openvpn")
SERVERS_JSON = OUTPUT_DIR / "servers.json"


SERVERS = [
    {
        "id": 1,
        "name": "US Server 1",
        "host": "us16.vpnbook.com",
        "country": "United States",
        "country_code": "US",
    },
    {
        "id": 2,
        "name": "US Server 2",
        "host": "us178.vpnbook.com",
        "country": "United States",
        "country_code": "US",
    },
    {
        "id": 3,
        "name": "Canada Server 1",
        "host": "ca149.vpnbook.com",
        "country": "Canada",
        "country_code": "CA",
    },
    {
        "id": 4,
        "name": "Canada Server 2",
        "host": "ca196.vpnbook.com",
        "country": "Canada",
        "country_code": "CA",
    },
    {
        "id": 5,
        "name": "UK Server 1",
        "host": "uk205.vpnbook.com",
        "country": "United Kingdom",
        "country_code": "GB",
    },
    {
        "id": 6,
        "name": "UK Server 2",
        "host": "uk68.vpnbook.com",
        "country": "United Kingdom",
        "country_code": "GB",
    },
    {
        "id": 7,
        "name": "Germany Server 1",
        "host": "de20.vpnbook.com",
        "country": "Germany",
        "country_code": "DE",
    },
    {
        "id": 8,
        "name": "Germany Server 2",
        "host": "de220.vpnbook.com",
        "country": "Germany",
        "country_code": "DE",
    },
    {
        "id": 9,
        "name": "France Server 1",
        "host": "fr200.vpnbook.com",
        "country": "France",
        "country_code": "FR",
    },
    {
        "id": 10,
        "name": "France Server 2",
        "host": "fr2311.vpnbook.com",
        "country": "France",
        "country_code": "FR",
    },
]


PROTOCOLS = [
    {
        "name": "udp25000",
        "protocol": "udp",
        "port": 25000,
        "label": "UDP 25000",
    },
    {
        "name": "udp53",
        "protocol": "udp",
        "port": 53,
        "label": "UDP 53",
    },
    {
        "name": "tcp443",
        "protocol": "tcp",
        "port": 443,
        "label": "TCP 443",
    },
    {
        "name": "tcp80",
        "protocol": "tcp",
        "port": 80,
        "label": "TCP 80",
    },
]


def now_utc() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def resolve_ip(host: str) -> str:
    """
    Resolve VPNBook hostname to IPv4.
    The VPNBook API requires the server IP.
    """

    try:
        return socket.gethostbyname(host)
    except socket.gaierror as exc:
        raise RuntimeError(
            f"DNS resolution failed for {host}: {exc}"
        ) from exc


def download_ovpn(
    host: str,
    protocol_name: str,
    ip: str,
    destination: Path,
) -> None:

    query = urlencode(
        {
            "hostname": host,
            "protocol": protocol_name,
            "ip": ip,
        }
    )

    url = f"{VPNBOOK_API}?{query}"

    print(f"Downloading {host} {protocol_name}")

    request = Request(
        url,
        headers={
            "User-Agent": "freeserver-vpnbook-updater/1.0",
            "Accept": "*/*",
        },
    )

    with urlopen(request, timeout=60) as response:
        data = response.read()

    if not data:
        raise RuntimeError(
            f"Empty response from VPNBook API: {url}"
        )

    # Basic validation.
    text_start = data[:4096].decode(
        "utf-8",
        errors="ignore",
    ).lower()

    if (
        "client" not in text_start
        and "dev tun" not in text_start
        and "remote " not in text_start
    ):
        raise RuntimeError(
            f"VPNBook API returned unexpected data for "
            f"{host}/{protocol_name}"
        )

    destination.write_bytes(data)


def clean_old_configs() -> None:
    """
    Remove old generated .ovpn files.

    This prevents obsolete server/protocol files from
    remaining after VPNBook changes.
    """

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    for file in OUTPUT_DIR.glob("*.ovpn"):
        file.unlink()


def build_server_data() -> list[dict]:
    result = []

    for server in SERVERS:

        ip = resolve_ip(server["host"])

        print(
            f"{server['host']} -> {ip}"
        )

        protocols = []

        for protocol in PROTOCOLS:

            filename = (
                f"{server['host']}-"
                f"{protocol['name']}.ovpn"
            )

            destination = OUTPUT_DIR / filename

            try:
                download_ovpn(
                    host=server["host"],
                    protocol_name=protocol["name"],
                    ip=ip,
                    destination=destination,
                )

                protocols.append(
                    {
                        "name": protocol["name"],
                        "protocol": protocol["protocol"],
                        "port": protocol["port"],
                        "label": protocol["label"],
                        "file": filename,
                        "available": True,
                    }
                )

            except Exception as exc:

                print(
                    f"WARNING: "
                    f"{server['host']} "
                    f"{protocol['name']} "
                    f"failed: {exc}"
                )

                protocols.append(
                    {
                        "name": protocol["name"],
                        "protocol": protocol["protocol"],
                        "port": protocol["port"],
                        "label": protocol["label"],
                        "file": filename,
                        "available": False,
                    }
                )

        result.append(
            {
                "id": server["id"],
                "name": server["name"],
                "host": server["host"],
                "ip": ip,
                "country": server["country"],
                "country_code": server["country_code"],
                "type": "openvpn",

                # App will replace these with live values.
                "status": "unknown",
                "ping": None,
                "download_speed": None,
                "upload_speed": None,

                "protocols": protocols,
            }
        )

    return result


def write_servers_json(servers: list[dict]) -> None:

    data = {
        "version": 2,
        "provider": "VPNBook",
        "type": "openvpn",
        "source": VPNBOOK_PAGE,
        "updated_at": now_utc(),

        # These are intentionally null because
        # GitHub cannot measure the user's ISP latency.
        "measurement": {
            "ping": "client",
            "speed": "client",
            "status": "client",
        },

        "protocols": [
            {
                "name": p["name"],
                "protocol": p["protocol"],
                "port": p["port"],
                "label": p["label"],
            }
            for p in PROTOCOLS
        ],

        "servers": servers,
    }

    SERVERS_JSON.write_text(
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )


def main() -> int:

    print("=" * 60)
    print("VPNBook OpenVPN updater")
    print("=" * 60)

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    clean_old_configs()

    try:
        servers = build_server_data()
        write_servers_json(servers)

    except Exception as exc:
        print()
        print(f"FATAL ERROR: {exc}")
        return 1

    print()
    print("=" * 60)
    print("Update completed")
    print("=" * 60)

    available = len(
        list(OUTPUT_DIR.glob("*.ovpn"))
    )

    print(
        f"OpenVPN profiles generated: {available}"
    )

    print(
        f"servers.json: {SERVERS_JSON}"
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
