"""Reglas sobre el inventario y los conductos importados de una plataforma (sin captura).

Cubren el caso "no tengo la plataforma, solo su exportacion". Producen hallazgos con el
mismo formato y los mismos titulos mapeados (heredan las referencias) que las reglas de
capturas; el titulo lleva un sufijo que indica el origen de los datos.
"""
from __future__ import annotations

import collections
import ipaddress
import re
from pathlib import Path

from ..catalog import OBSOLETE_PATTERNS
from ..i18n import t, unir
from ..model import Capture
from ..registry import Registry
from ..util import port_info
from .base import finding

# Cada regla es una funcion (assets, conductos, destino) -> None decorada con @REGLAS_INVENTARIO.
REGLAS_INVENTARIO = Registry()

AVISO = " (datos de la exportacion; formato no validado con exportaciones reales, P1)"


def _ips_extremos(extremos, assets: dict) -> list:
    """IP de los extremos de conducto: la IP misma o, si es la clave/MAC de un activo, las del activo."""
    out = []
    for x in extremos:
        x = str(x or "").strip()
        a = assets.get(x)
        out += [str(ip) for ip in a["ips"]] if a is not None and a.get("ips") else [x]
    return out


def _es_global(x) -> bool:
    try:
        ip = ipaddress.ip_address(str(x).strip())
        return ip.is_global and not ip.is_multicast      # multicast no es Internet
    except ValueError:
        return False


@REGLAS_INVENTARIO
def gestion_sin_cifrar_exportacion(assets: dict, conductos: list, destino: Capture) -> None:
    por_servicio = collections.Counter()
    extremos: set = set()
    for c in conductos:
        nombre, cat = port_info(c.get("port", ""), c.get("l4") or "tcp")
        if c.get("categoria") == "claro" or cat == "claro":
            extremos.update((c.get("src"), c.get("dst")))
            serv = c.get("servicio")
            por_servicio[serv if serv and serv != "-" else (nombre or "desconocido")] += 1
    if por_servicio:
        finding(
            destino, "Media",
            "Protocolos de gestion sin cifrar en uso (segun la exportacion)",
            t("{lista}{aviso}", aviso=t(AVISO), lista=unir(
                ", ", (t("{k}: {v} conductos", k=k, v=v) for k, v in por_servicio.most_common()))),
            "Telnet, FTP, TFTP, HTTP y SNMPv1/v2c transportan credenciales y "
            "configuracion sin proteccion. TFTP ademas se usa para cargar firmware.",
            "Deshabilitar los servicios que no se usen y sustituir los necesarios por "
            "su equivalente cifrado.",
            categoria="Exposicion", activos=_ips_extremos(extremos, assets),
        )


@REGLAS_INVENTARIO
def software_obsoleto_exportacion(assets: dict, conductos: list, destino: Capture) -> None:
    vistos, lineas, ips = set(), [], []
    for a in assets.values():
        ident = a.get("nombre") or (min(a["ips"]) if a.get("ips") else a.get("mac", "?"))
        campo = " ".join(str(a.get(k) or "") for k in ("modelo", "firmware", "tipo_texto", "nombre"))
        for pat, etiqueta, nota in OBSOLETE_PATTERNS:
            if re.search(pat, campo, re.IGNORECASE) and (ident, etiqueta) not in vistos:
                vistos.add((ident, etiqueta))
                ips += [str(ip) for ip in a.get("ips") or ()]
                lineas.append(t("- {ident}: {etiqueta} - {nota} | campo: {campo}", ident=ident,
                                etiqueta=etiqueta, nota=t(nota), campo=campo.strip()[:160]))
    if lineas:
        finding(
            destino, "Alta",
            "Software o sistema operativo fuera de soporte (segun el inventario)",
            t("{lista}{aviso}", aviso=t(AVISO), lista=unir("\n", lineas)),
            "Un sistema sin soporte no recibe parches. Es exactamente el tipo de "
            "hallazgo que un motor de CVE pasivo emite en cuanto logra leer la version.",
            "Levantar plan de reemplazo o compensar con aislamiento de red y control "
            "de acceso estricto mientras se reemplaza.",
            categoria="Obsolescencia", activos=ips,
        )


def _etiqueta(x, indice: dict) -> str:
    """Extremo de un conducto: IP y, si hay, nombre entre parentesis; la MAC solo si el activo no tiene IP."""
    a = indice.get(str(x))
    if a is None or not a.get("ips"):
        return str(x)
    ip = sorted(a["ips"])[0]
    nombre = a.get("nombre") or ""
    return f"{ip} ({nombre})" if nombre and nombre != ip else ip


@REGLAS_INVENTARIO
def ip_publicas_exportacion(assets: dict, conductos: list, destino: Capture) -> None:
    pares = sorted({(str(c.get("src", "")), str(c.get("dst", ""))) for c in conductos
                    if _es_global(c.get("src")) or _es_global(c.get("dst"))})
    if pares:
        indice: dict = {}
        for a in assets.values():
            for k in {a.get("mac"), *a.get("ips", ()), *a.get("alias", ())}:
                if k:
                    indice.setdefault(str(k), a)
        finding(
            destino, "Alta",
            "Trafico con direcciones IP publicas desde la red OT (segun la exportacion)",
            t("{lista}{aviso}", aviso=t(AVISO), lista=", ".join(
                f"{_etiqueta(s, indice)} -> {_etiqueta(d, indice)}" for s, d in pares[:15])),
            "Comunicacion hacia Internet desde un segmento de control rompe la "
            "segmentacion esperada y es via de exfiltracion y de mando y control.",
            "Verificar si son equipos de planta o trafico de transito mal segmentado; "
            "bloquear la salida directa a Internet desde niveles 0-2.",
            categoria="Segmentacion",
            activos=[ip for s, d in pares for ip in _ips_extremos((s, d), assets)],
        )


def evaluar_inventario(assets: dict, conductos: list, plataforma: str) -> list:
    """Corre las reglas de inventario y devuelve los hallazgos (dicts de finding)."""
    destino = Capture(Path(f"exportacion {plataforma}"))
    for regla in REGLAS_INVENTARIO:
        regla(assets or {}, conductos or [], destino)
    return destino.findings
