"""Consolidacion entre capturas: inventario unico y matriz de comunicaciones."""
from __future__ import annotations

import collections
import ipaddress
import re

from .catalog import CRIT_ORDER
from .model import Capture
from .util import clean_hostname, is_host_ip, port_info

FW_PATTERNS = [
    r"FW:\s*Version\s*([\w.\-]+)",
    r"\bFW[:\s]+([\w.\-]{3,})",
    r"SW:\s*([\w.\-]+)",
    r"\bVersion\s+(\d[\w.()\-]*)",
    r"\bv(\d+\.\d+\.\d+[\w.\-]*)",
]


def extract_fw(text: str) -> str:
    for pat in FW_PATTERNS:
        m = re.search(pat, text or "")
        if m:
            return m.group(1).rstrip(",;")
    return ""


def merge_assets(caps: list[Capture]) -> tuple[dict, dict]:
    """Une los activos de todas las capturas por MAC y devuelve
    (inventario, indice IP -> activo). Un mismo equipo visto desde varios
    puntos de captura es un solo renglon del inventario."""
    assets: dict[str, dict] = {}
    for c in caps:
        for mac, h in c.hosts.items():
            a = assets.get(mac)
            if a is None:
                a = {
                    "mac": mac, "vendor": h["vendor"], "ips": set(), "vlans": set(),
                    "hostnames": set(), "protos": collections.Counter(),
                    "ports_served": collections.Counter(), "pkts": 0, "bytes": 0,
                    "capturas": set(), "identidad": [], "role": "", "purdue": "",
                    "role_why": "", "_role_weight": -1,
                }
                assets[mac] = a
            a["ips"] |= h["ips"]
            a["vlans"] |= h["vlans"]
            a["hostnames"] |= {
                c2 for c2 in (clean_hostname(n) for n in h["hostnames"])
                if c2 and "not set" not in c2.lower()
            }
            a["protos"].update(h["proto_seen"])
            a["ports_served"].update(h["ports_served"])
            a["pkts"] += h["tx_pkts"] + h["rx_pkts"]
            a["bytes"] += h["tx_bytes"] + h["rx_bytes"]
            a["capturas"].add(c.name)
            if not a["vendor"] and h["vendor"]:
                a["vendor"] = h["vendor"]
            # El rol se toma de la captura donde mas se vio al equipo.
            w = h["tx_pkts"] + h["rx_pkts"]
            if h.get("role") and h["role"] != "Indeterminado" and w > a["_role_weight"]:
                a["role"] = h["role"]
                a["purdue"] = h.get("purdue", "")
                a["role_why"] = h.get("role_why", "")
                a["_role_weight"] = w

    for c in caps:
        for i in c.identity:
            a = assets.get(i["mac"])
            if a is not None:
                a["identidad"].append(i)
                if i.get("ot"):      # V1b (D90): identidad del protocolo OT, por IP del equipo descrito
                    d = a.setdefault("ot_por_ip", {}).setdefault(i["ip"], {"captura": c.name})
                    for campo, valor in i["ot"].items():
                        if valor and not d.get(campo):
                            d[campo] = valor
                            d["tipo_" + campo] = i["tipo"]

    from .inventario_normalizado import (
        _enrutamiento,  # import tardio: ese modulo no depende de este
    )
    # Modelo y firmware a partir de los anuncios de descubrimiento y de la identidad OT.
    for a in assets.values():
        modelo, firmware = "", ""
        ots = list(a.get("ot_por_ip", {}).values())
        # Una MAC de enrutamiento (D74) no es un equipo: su identidad OT se queda en la fila de su IP.
        if _enrutamiento(sorted(a["ips"])):
            ots = []

        def primero(campo, ots=ots):
            return next(((d[campo], d["tipo_" + campo], d["captura"]) for d in ots if d.get(campo)), ("", "", ""))
        a["fuente_ot"] = {}
        for i in a["identidad"]:
            if i["tipo"] == "CDP" and not modelo:
                # El valor viene como "<deviceid> / <plataforma>"; nos quedamos
                # con la plataforma, que es el modelo real del equipo.
                partes = i["valor"].split(" / ", 1)
                modelo = (partes[1] if len(partes) > 1 else partes[0])
                # El campo puede traer varias ocurrencias unidas por '|'.
                modelo = modelo.split("|")[0].strip()
            if i["tipo"] == "CDP" and not firmware:
                firmware = extract_fw(f"{i['valor']} {i['detalle']}")
        # CDP primero, luego la identidad OT, luego LLDP y banners como siempre.
        fw_ot = primero("firmware")
        if not firmware and fw_ot[0]:
            firmware = fw_ot[0]
            a["fuente_ot"]["firmware"] = fw_ot[1:]
        mod_ot = primero("modelo")
        if not modelo and mod_ot[0]:
            modelo = mod_ot[0]
            a["fuente_ot"]["modelo"] = mod_ot[1:]
        for i in a["identidad"]:
            if i.get("ot"):
                continue
            blob = f"{i['valor']} {i['detalle']}"
            if i["tipo"] == "LLDP" and not modelo and i["detalle"]:
                modelo = i["detalle"][:70]
            if i["tipo"] in ("Banner HTTP", "SMB Native OS") and not modelo:
                modelo = i["valor"][:70]
            if not firmware:
                firmware = extract_fw(blob)
        fab_ot = primero("fabricante")
        if fab_ot[0]:         # el fabricante que reporta el protocolo OT gana sobre el OUI de la MAC
            a["vendor"] = fab_ot[0]
            a["fuente_ot"]["fabricante"] = fab_ot[1:]
        nom_ot = primero("nombre")[0]
        if nom_ot and not a["hostnames"]:
            a["hostnames"].add(clean_hostname(nom_ot))
        a["modelo"] = modelo
        a["firmware"] = firmware
        a["nombre"] = (sorted(a["hostnames"])[0] if a["hostnames"]
                       else (sorted(a["ips"])[0] if a["ips"] else a["mac"]))
        a.pop("_role_weight", None)

    ip_index: dict[str, dict] = {}
    for a in assets.values():
        for ip in a["ips"]:
            # Si dos equipos reclaman la misma IP se queda el de mas trafico;
            # el conflicto ya se reporta como hallazgo aparte.
            if ip not in ip_index or a["pkts"] > ip_index[ip]["pkts"]:
                ip_index[ip] = a
    return assets, ip_index


def criticidad_conducto(categoria: str, cruza_zona: bool, escrituras: int) -> str:
    """Criticidad de un conducto: combina tipo de servicio, cruce de zonas y escrituras."""
    if escrituras:
        return "Critica"
    if categoria == "ot":
        return "Alta" if cruza_zona else "Media"
    if categoria == "claro" or cruza_zona:
        return "Media"
    return "Baja"


def build_conduits(caps: list[Capture], ip_index: dict) -> list[dict]:
    """Matriz de comunicaciones: un renglon por relacion origen -> destino -> servicio."""
    pairs: set[tuple[str, str]] = set()
    for c in caps:
        for f in c.flows.values():
            if f["src"] and f["dst"]:
                pairs.add((f["src"], f["dst"]))

    # Escrituras y comandos por par, para marcar los conductos de control.
    writes: collections.Counter = collections.Counter()
    for c in caps:
        for o in c.control_ops:
            writes[(o["src"], o["dst"])] += 1

    conduits: dict[tuple, dict] = {}
    for c in caps:
        for f in c.flows.values():
            src, dst = f["src"], f["dst"]
            if not src or not dst or not is_host_ip(src):
                continue
            svc, cat = port_info(f["dport"], f["l4"])
            key = (src, dst, f["l4"], f["dport"])
            k = conduits.get(key)
            if k is None:
                a_src = ip_index.get(src, {})
                a_dst = ip_index.get(dst, {})
                try:
                    dst_mc = ipaddress.ip_address(dst).is_multicast
                except ValueError:
                    dst_mc = False
                k = {
                    "src": src, "dst": dst, "l4": f["l4"], "port": f["dport"],
                    "servicio": svc or f["proto"] or "-",
                    "categoria": cat or ("multicast" if dst_mc else "otro"),
                    "src_nombre": a_src.get("nombre", src),
                    "dst_nombre": (a_dst.get("nombre") or
                                   ("grupo multicast" if dst_mc else dst)),
                    "src_rol": a_src.get("role", ""), "dst_rol": a_dst.get("role", ""),
                    "src_zona": a_src.get("purdue", ""), "dst_zona": a_dst.get("purdue", ""),
                    "pkts": 0, "bytes": 0, "capturas": set(),
                    "multicast": dst_mc,
                }
                conduits[key] = k
            k["pkts"] += f["pkts"]
            k["bytes"] += f["bytes"]
            k["capturas"].add(c.name)

    out = []
    for k in conduits.values():
        k["bidireccional"] = (k["dst"], k["src"]) in pairs
        k["escrituras"] = writes.get((k["src"], k["dst"]), 0)
        zs, zd = k["src_zona"], k["dst_zona"]
        k["cruza_zona"] = bool(zs and zd and zs != zd and not k["multicast"])
        k["criticidad"] = criticidad_conducto(k["categoria"], k["cruza_zona"], k["escrituras"])
        out.append(k)
    out.sort(key=lambda x: (CRIT_ORDER.get(x["criticidad"], 9), -x["pkts"]))
    return out
