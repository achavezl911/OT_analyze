"""Regla T8 (D68): herramientas de acceso remoto de terceros (AnyDesk, TeamViewer, ScreenConnect, RustDesk...).

Evidencia tecnica de nombres y puertos del catalogo (data/acceso_remoto.json), no un veredicto: no prueba
que haya una sesion ni que sea no autorizada. La deteccion vive en acceso_remoto.py; el camino `diagrama`
(exportaciones de plataformas) reutiliza hallazgo().
"""
from __future__ import annotations

import collections

from ..acceso_remoto import D_DESCARTADO, SIN_VERIFICAR, de_captura, orden_ip
from ..i18n import t, unir
from ..model import Capture
from .base import RULES, finding

MAX_ACTIVOS = 10


def _linea(ip: str, xs: list) -> str:
    herr = sorted({x["herramienta"] for x in xs})
    metodos = sorted({f"{t(x['metodo'])} {x['indicador']}" for x in xs})
    destinos = sorted({t(x["destino"]) for x in xs})
    ips = sorted({i for x in xs for i in x["destino_ip"].split(";") if i})
    primera = min((x["primera"] for x in xs if x["primera"]), default="-")
    ultima = max((x["ultima"] for x in xs if x["ultima"]), default="-")
    texto = t("{ip} ({activo}): {herr}; indicadores: {metodos}; destino: {destinos} ({ips}); {c} conductos, "
              "{b} bytes; primera {p}, ultima {u}", ip=ip, activo=xs[0]["activo"], herr=", ".join(herr),
              metodos="; ".join(metodos), destinos=", ".join(destinos), ips=", ".join(ips[:3]) or "-",
              c=sum(x["conductos"] for x in xs), b=sum(x["bytes"] for x in xs), p=primera, u=ultima)
    if any(x["estado"] == SIN_VERIFICAR for x in xs):
        texto = unir(" ", [texto, t("[indicador sin verificar: confirmar con el dueno del equipo]")])
    return texto


def hallazgo(cap: Capture, inds: list) -> None:
    """Un solo hallazgo agregado para todos los indicadores (de una captura o de una exportacion)."""
    inds = [x for x in inds if x["estado"] != D_DESCARTADO]
    if not inds:
        return
    por_ip = collections.defaultdict(list)
    for x in inds:
        por_ip[x["ip"]].append(x)
    ips = sorted(por_ip, key=orden_ip)
    lineas = [_linea(ip, por_ip[ip]) for ip in ips[:MAX_ACTIVOS]]
    if len(ips) > MAX_ACTIVOS:
        lineas.append(t(" y {n} mas", n=len(ips) - MAX_ACTIVOS))
    ot = any(x["ot"] for x in inds)
    finding(
        cap, "Media", "Herramienta de acceso remoto de terceros en la red",
        unir("\n", [t("{n} activos con herramientas de acceso remoto de terceros ({h})", n=len(ips),
                      h=", ".join(sorted({x["herramienta"] for x in inds})))] + lineas),
        "Estas herramientas abren acceso entrante desde Internet que salta la segmentacion y la DMZ, a menudo "
        "sin MFA ni registro de sesiones. Un nombre o un puerto del catalogo es evidencia de que alguien la usa "
        "o lo intenta, no prueba una sesion activa ni que sea no autorizada.",
        "Inventariar y autorizar cada uso; centralizar el acceso remoto de proveedores en una solucion con MFA, "
        "registro de sesiones y aprobacion por sesion en la DMZ; bloquear el resto por dominio y puerto.",
        categoria="Segmentacion", activos=[x["ip"] for x in inds],
    )
    if ot:      # la severidad base es un literal para que las pruebas lean el titulo con una expresion
        cap.findings[-1]["severidad"] = "Alta"


@RULES
def acceso_remoto_terceros(cap: Capture) -> None:
    inds = de_captura(cap)
    if inds:
        hallazgo(cap, inds)
