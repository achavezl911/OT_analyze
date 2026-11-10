"""Funciones puras: direcciones IP/MAC, nombres y formatos."""
from __future__ import annotations

import ipaddress
import re

from .catalog import OT_PORTS, OT_VENDORS
from .i18n import t

_SERV_ES = ("DHCP cliente", "DHCP servidor", "EtherNet/IP explicito (CIP)")   # nombres con palabras en espanol


def clean_hostname(name: str) -> str:
    """'BLACKJACK<00>|BLACKJACK<00> (Workstation/Redirector)' -> 'BLACKJACK'.
    Los nombres NetBIOS traen sufijo de tipo y a veces vienen repetidos."""
    if not name:
        return ""
    first = name.split("|")[0]
    first = re.sub(r"<[0-9a-fA-F]{2}>?.*$", "", first)
    first = re.sub(r"\s*\(.*\)\s*$", "", first)
    first = first.strip().strip(".")
    # Algunos equipos anuncian marcadores como '--' o 'N/A': no son nombres.
    if not re.search(r"[A-Za-z0-9]", first) or first.lower() in ("n/a", "none", "null"):
        return ""
    return first


def _int_or_none(v: str):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def g(row: list[str], idx: dict[str, int], name: str) -> str:
    i = idx.get(name)
    if i is None or i >= len(row):
        return ""
    return row[i].strip()


def vendor_of(resolved: str, mac: str) -> str:
    """Wireshark resuelve 'RockwellAuto_85:71:4d'; nos quedamos con el fabricante."""
    if not resolved or resolved == mac:
        return ""
    name = resolved.split("_")[0]
    if re.fullmatch(r"[0-9A-Fa-f:.-]+", name):
        return ""
    low = name.lower()
    for key, full in OT_VENDORS.items():
        if low.startswith(key):
            return full
    return name


def is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return a.is_private or a.is_loopback or a.is_multicast or a.is_link_local or a.is_reserved


def is_apipa(ip: str) -> bool:
    return ip.startswith("169.254.")


def is_unicast_mac(mac: str) -> bool:
    """Descarta multicast y broadcast: el bit I/G es el menos significativo
    del primer octeto. Esas direcciones son grupos de destino, no equipos."""
    if not mac or len(mac) < 2:
        return False
    try:
        return not (int(mac[:2], 16) & 1)
    except ValueError:
        return False


def is_host_ip(ip: str) -> bool:
    """IP que puede pertenecer a un equipo real (no grupo ni comodin)."""
    if not ip or ip in ("0.0.0.0", "255.255.255.255", "::"):
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_multicast or a.is_unspecified)


def port_info(port: str, proto: str) -> tuple[str, str]:
    try:
        p = int(port)
    except (TypeError, ValueError):
        return ("", "")
    nombre, cat = OT_PORTS.get((p, proto), ("", ""))
    return (t(nombre) if nombre in _SERV_ES else nombre), cat


def human_duration(raw: str) -> str:
    """'2402.100152900 seconds' -> '40 min 2 s'."""
    m = re.search(r"([\d.]+)", raw or "")
    if not m:
        return raw or "?"
    s = float(m.group(1))
    if s < 60:
        return f"{s:.0f} s"
    if s < 3600:
        return f"{int(s // 60)} min {int(s % 60)} s"
    return f"{int(s // 3600)} h {int((s % 3600) // 60)} min"


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
