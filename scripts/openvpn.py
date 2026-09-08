#!/usr/bin/env python3

from __future__ import annotations

import json
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


# ============================================================
# VPNBook OpenVPN updater
# ============================================================

VPNBOOK_API = "https://www.vpnbook.com/api/openvpn"

OUTPUT_DIR = Path("output/openvpn")
SERVERS_JSON = OUTPUT_DIR / "servers.json"


# ------------------------------------------------------------
# VPNBook servers
#
# France Server 2 is currently inconsistent between VPNBook
# pages:
#
# Homepage      -> fr231
# OpenVPN page  -> fr2311
#
# Therefore both are used as aliases and the first resolvable
# hostname is selected.
# ------------------------------------------------------------

SERVERS = [
    {
        "id": 1,
        "name": "US Server 1",
        "hosts": ["us16.vpnbook.com"],
        "country": "United States",
        "country_code": "US",
    },
    {
        "id": 2,
        "name": "US Server 2",
        "hosts": ["us178.vpnbook.com"],
        "country": "United States",
        "country_code": "US",
    },
    {
        "id": 3,
        "name": "Canada Server 1",
        "hosts": ["ca149.vpnbook.com"],
        "country": "Canada",
        "country_code": "CA",
    },
    {
        "id": 4,
        "name": "Canada Server 2",
        "hosts": ["ca196.vpnbook.com"],
        "country": "Canada",
        "country_code": "CA",
    },
    {
        "id": 5,
        "name": "UK Server 1",
        "hosts": ["uk205.vpnbook.com"],
        "country": "United Kingdom",
        "country_code": "GB",
    },
    {
        "id": 6,
        "name": "UK Server 2",
        "hosts": ["uk68.vpnbook.com"],
        "country": "United Kingdom",
        "country_code": "GB",
    },
    {
        "id": 7,
        "name": "Germany Server 1",
        "hosts": ["de20.vpnbook.com"],
        "country": "Germany",
        "country_code": "DE",
    },
    {
        "id": 8,
        "name": "Germany Server 2",
        "hosts": ["de220.vpnbook.com"],
        "country": "Germany",
        "country_code": "DE",
    },
    {
        "id": 9,
        "name": "France Server 1",
        "hosts": ["fr200.vpnbook.com"],
        "country": "France",
        "country_code": "FR",
    },
    {
        "id": 10,
        "name": "France Server 2",
        "hosts": [
            "fr231.vpnbook.com",
            "fr2311.vpnbook.com",
        ],
        "country": "France",
        "country_code": "FR",
    },
]


# ------------------------------------------------------------
# VPNBook OpenVPN protocols
#
# Order:
#   UDP 25000 = usually best speed
#   UDP 53    = useful on restricted networks
#   TCP 443   = firewall friendly
#   TCP 80    = fallback
# ------------------------------------------------------------

PROTOCOLS = [
    {
        "id": "udp25000",
        "transport": "udp",
        "port": 25000,
    },
    {
        "id": "udp53",
        "transport": "udp",
        "port": 53,
    },
    {
        "id": "tcp443",
        "transport": "tcp",
        "port": 443,
    },
    {
        "id": "tcp80",
        "transport": "tcp",
        "port": 80,
    },
]


USER_AGENT = (
    "Mozilla/5.0 "
    "(compatible; VPNBookUpdater/1.0; +https://www.vpnbook.com/)"
)


# ============================================================
# Helpers
# ============================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")


def resolve_ip(host: str) -> str | None:
    """
    Resolve hostname to IPv4.

    Returns None instead of raising because one dead server
    must not stop the whole updater.
    """

    try:
        ip = socket.gethostbyname(host)
        return ip

    except socket.gaierror as exc:
        print(
            f"WARNING: DNS resolution failed for {host}: {exc}"
        )
        return None

    except Exception as exc:
        print(
            f"WARNING: Could not resolve {host}: {exc}"
        )
        return None


def download_bytes(url: str, timeout: int = 30) -> bytes:
    """
    Download data using urllib.
    """

    request = Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
        },
    )

    with urlopen(request, timeout=timeout) as response:
        return response.read()


def download_config(
    host: str,
    ip: str,
    protocol: dict,
    destination: Path,
) -> bool:
    """
    Download one OpenVPN configuration from VPNBook API.
    """

    protocol_id = protocol["id"]

    query = urlencode(
        {
            "hostname": host,
            "protocol": protocol_id,
            "ip": ip,
        }
    )

    url = f"{VPNBOOK_API}?{query}"

    print(
        f"Downloading {host} {protocol_id}"
    )

    try:
        data = download_bytes(url)

    except HTTPError as exc:
        print(
            f"  HTTP ERROR {exc.code}: {host} {protocol_id}"
        )
        return False

    except URLError as exc:
        print(
            f"  URL ERROR: {host} {protocol_id}: {exc.reason}"
        )
        return False

    except TimeoutError:
        print(
            f"  TIMEOUT: {host} {protocol_id}"
        )
        return False

    except Exception as exc:
        print(
            f"  ERROR: {host} {protocol_id}: {exc}"
        )
        return False

    if not data:
        print(
            f"  EMPTY RESPONSE: {host} {protocol_id}"
        )
        return False

    # Decode for validation.
    try:
        text = data.decode(
            "utf-8",
            errors="ignore",
        )
    except Exception:
        text = ""

    # VPNBook should return an OpenVPN profile.
    #
    # Do not require every possible OpenVPN directive because
    # VPNBook may change its config formatting.
    if (
        "client" not in text
        and "remote " not in text
        and "<ca>" not in text
    ):
        print(
            f"  INVALID OpenVPN CONFIG: "
            f"{host} {protocol_id}"
        )
        return False

    try:
        destination.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        destination.write_bytes(data)

    except Exception as exc:
        print(
            f"  FILE WRITE ERROR: {destination}: {exc}"
        )
        return False

    print(
        f"  OK -> {destination}"
    )

    return True


def clean_old_configs() -> None:
    """
    Remove old .ovpn files.

    This prevents stale configurations from remaining when
    VPNBook removes or changes a server.
    """

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    for file in OUTPUT_DIR.glob("*.ovpn"):
        try:
            file.unlink()
            print(f"Removed old config: {file.name}")
        except Exception as exc:
            print(
                f"WARNING: Could not remove "
                f"{file}: {exc}"
            )


def select_resolvable_host(
    hosts: list[str],
) -> tuple[str, str] | None:
    """
    Try hostname aliases in order.

    Example:
        fr231.vpnbook.com
        fr2311.vpnbook.com

    The first hostname that resolves is selected.
    """

    for host in hosts:
        print(f"Resolving {host}...")

        ip = resolve_ip(host)

        if ip:
            print(
                f"  {host} -> {ip}"
            )
            return host, ip

    return None


# ============================================================
# Main update
# ============================================================

def update_servers() -> list[dict]:

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    clean_old_configs()

    result = []

    for server in SERVERS:

        print()
        print(
            "=" * 60
        )
        print(
            server["name"]
        )
        print(
            "=" * 60
        )

        selected = select_resolvable_host(
            server["hosts"]
        )

        if not selected:
            print(
                f"SKIP: {server['name']} "
                f"(no DNS-resolvable hostname)"
            )
            continue

        host, ip = selected

        successful_protocols = []

        for protocol in PROTOCOLS:

            protocol_id = protocol["id"]

            filename = (
                f"{host}-{protocol_id}.ovpn"
            )

            destination = (
                OUTPUT_DIR / filename
            )

            success = download_config(
                host=host,
                ip=ip,
                protocol=protocol,
                destination=destination,
            )

            if success:

                successful_protocols.append(
                    {
                        "id": protocol_id,
                        "transport": protocol[
                            "transport"
                        ],
                        "port": protocol["port"],
                        "file": filename,
                        "available": True,
                    }
                )

            else:

                # Make sure a partial/stale file does
                # not remain.
                try:
                    if destination.exists():
                        destination.unlink()
                except Exception:
                    pass

        # ----------------------------------------------------
        # If no protocol works, skip the server.
        # ----------------------------------------------------

        if not successful_protocols:

            print(
                f"SKIP: {host} "
                f"(no working OpenVPN profile)"
            )

            continue

        # ----------------------------------------------------
        # Server entry
        # ----------------------------------------------------

        server_entry = {
            "id": server["id"],
            "name": server["name"],
            "host": host,
            "ip": ip,
            "country": server["country"],
            "country_code": server["country_code"],
            "type": "openvpn",

            # Client measures these values.
            "status": "unknown",
            "ping": None,
            "download_speed": None,
            "upload_speed": None,

            "protocols": successful_protocols,
        }

        result.append(server_entry)

        print(
            f"ACTIVE: {host} "
            f"({len(successful_protocols)} protocols)"
        )

    return result


def write_servers_json(
    servers: list[dict],
) -> None:

    if not servers:
        raise RuntimeError(
            "No working VPNBook OpenVPN servers found."
        )

    output = {
        "version": 2,
        "provider": "VPNBook",
        "type": "openvpn",
        "source": "https://www.vpnbook.com/freevpn/openvpn",

        "updated_at": utc_now(),

        "measurement": {
            "ping": "client",
            "speed": "client",
            "status": "client",
        },

        "protocols": [
            {
                "id": "udp25000",
                "transport": "udp",
                "port": 25000,
                "priority": 1,
            },
            {
                "id": "udp53",
                "transport": "udp",
                "port": 53,
                "priority": 2,
            },
            {
                "id": "tcp443",
                "transport": "tcp",
                "port": 443,
                "priority": 3,
            },
            {
                "id": "tcp80",
                "transport": "tcp",
                "port": 80,
                "priority": 4,
            },
        ],

        "servers": servers,
    }

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
        f"Wrote {SERVERS_JSON}"
    )

    print(
        f"Active servers: {len(servers)}"
    )


# ============================================================
# Entry point
# ============================================================

def main() -> int:

    print("=" * 60)
    print("VPNBook OpenVPN updater")
    print("=" * 60)

    try:

        servers = update_servers()

        # At least one server must work.
        if not servers:
            raise RuntimeError(
                "All VPNBook servers failed."
            )

        write_servers_json(servers)

        print()
        print("=" * 60)
        print("UPDATE COMPLETE")
        print("=" * 60)

        for server in servers:
            print(
                f"- {server['host']}: "
                f"{len(server['protocols'])} protocols"
            )

        return 0

    except KeyboardInterrupt:

        print(
            "\nInterrupted."
        )

        return 130

    except Exception as exc:

        print()
        print(
            "FATAL ERROR:"
        )
        print(
            str(exc)
        )

        return 1


if __name__ == "__main__":
    sys.exit(main())
