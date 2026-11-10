"""Inferencia de rol y nivel Purdue a partir del comportamiento observado."""
from __future__ import annotations

from .catalog import SWITCH_HINTS
from .i18n import t, unir
from .model import Capture

# Roles y niveles que fija este modulo (identificadores en espanol): solo estos se traducen al mostrar;
# los de una plataforma importada son datos del cliente y salen tal cual.
_FIJOS = ("Indeterminado", "Equipo de red (switch / router)",
          "Controlador / dispositivo de campo (PLC, RTU, IED)", "HMI / estacion SCADA",
          "Cliente de control (HMI, SCADA o historiador)", "Dispositivo CIP (controlador o modulo de I/O)",
          "Nodo EtherNet/IP", "Host Windows (estacion de trabajo o servidor)",
          "Infraestructura", "Nivel 1", "Nivel 2", "Nivel 1-2", "Nivel 2-3")
_PREF_OT = "Dispositivo OT ("


def mostrar(valor: str) -> str:
    """Rol o nivel Purdue inferido, traducido al idioma del reporte (los datos importados no se tocan)."""
    if valor in _FIJOS:
        return t(valor)
    if valor.startswith(_PREF_OT) and valor.endswith(")"):
        return t("Dispositivo OT ({fabricante})", fabricante=valor[len(_PREF_OT):-1])
    return valor


def inferir_rol(h: dict) -> tuple:
    """(rol, nivel Purdue, motivo) de un host con las claves proto_seen, ports_served, ports_used,
    vendor, fingerprints y hostnames. Es la regla de infer_roles, reutilizable para una IP suelta."""
    protos = {p.lower() for p in h["proto_seen"]}
    served = {p for (p, l4) in h["ports_served"]}
    used = {p for (p, l4) in h["ports_used"]}
    vendor_l = (h["vendor"] or "").lower()
    fps = " ".join(h["fingerprints"]).lower()
    names = " ".join(h["hostnames"]).lower()

    role, why, purdue = "Indeterminado", [], ""

    is_switch = (
        any(s in vendor_l or s in fps or s in names for s in SWITCH_HINTS)
        or "stp" in protos or "cdp" in protos or "gvrp" in protos
    )
    ot_served = served & {502, 20000, 2404, 102, 44818, 4840, 47808, 2222, 18245}
    ot_used = used & {502, 20000, 2404, 102, 44818, 4840, 47808, 18245}
    windows = bool(protos & {"nbns", "browser", "llmnr", "smb", "smb2", "dcerpc", "ssdp"})
    is_ot_vendor = bool(h["vendor"]) and any(
        k in vendor_l for k in ("rockwell", "siemens", "schneider", "abb",
                                "general electric", "sel", "phoenix", "beckhoff",
                                "omron", "mitsubishi", "yokogawa", "wago",
                                "power measurement", "woodward", "prosoft")
    )

    if is_switch:
        role, purdue = "Equipo de red (switch / router)", "Infraestructura"
        why.append(t("habla STP/CDP/LLDP o el OUI es de un fabricante de switches"))
    elif ot_served and not ot_used:
        role, purdue = "Controlador / dispositivo de campo (PLC, RTU, IED)", "Nivel 1"
        why.append(t("atiende puertos OT {p}", p=sorted(ot_served)))
    elif ot_used and windows:
        role, purdue = "HMI / estacion SCADA", "Nivel 2"
        why.append(t("consulta puertos OT {p} y usa protocolos Windows", p=sorted(ot_used)))
    elif ot_used:
        role, purdue = "Cliente de control (HMI, SCADA o historiador)", "Nivel 2"
        why.append(t("consulta puertos OT {p}", p=sorted(ot_used)))
    elif "cip" in protos or "enip" in protos or "cipio" in protos:
        if is_ot_vendor:
            role, purdue = "Dispositivo CIP (controlador o modulo de I/O)", "Nivel 1"
            why.append(t("trafico EtherNet/IP y OUI de fabricante OT"))
        else:
            role, purdue = "Nodo EtherNet/IP", "Nivel 1-2"
            why.append(t("trafico EtherNet/IP"))
    elif windows:
        role, purdue = "Host Windows (estacion de trabajo o servidor)", "Nivel 2-3"
        why.append(t("protocolos de Windows (SMB/NBNS/LLMNR/SSDP)"))
    elif is_ot_vendor:
        role, purdue = f"Dispositivo OT ({h['vendor']})", "Nivel 1-2"
        why.append(t("OUI de fabricante OT"))

    if "ptp" in protos:
        why.append(t("participa en sincronizacion de tiempo PTP"))
    return role, purdue, unir("; ", why)


def infer_roles(cap: Capture) -> None:
    for h in cap.hosts.values():
        h["role"], h["purdue"], h["role_why"] = inferir_rol(h)
