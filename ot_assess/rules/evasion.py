"""Regla T9 (D71): canales que evaden la inspeccion (DoH, DoQ, Tor, VPN, tuneles y proxies hacia Internet).

Evidencia tecnica de nombres, IP, puertos y protocolos del catalogo (data/evasion.json), no un veredicto: no
prueba una sesion ni que sea no autorizada. La deteccion vive en evasion.py; el camino `diagrama` (exportaciones
de plataformas) reutiliza hallazgo(). DoT (TCP/853) lo cubre dns_dot y no se duplica aqui.
"""
from __future__ import annotations

import collections

from ..evasion import ETIQUETA, T_CANARIO, TIPOS_CANAL, TIPOS_DNS, de_captura
from ..i18n import t, unir
from ..indicadores import D_DESCARTADO, SIN_VERIFICAR, orden_ip
from ..model import Capture
from .base import RULES, finding

MAX_ACTIVOS = 10
MAX_INDICADORES = 5


def _indicador(x: dict) -> str:
    ips = ", ".join(i for i in x["destino_ip"].split(";") if i) or "-"
    return t("{tipo} por {metodo} {indicador}: destino {destino} ({ips}); {b} bytes; primera {p}, ultima {u}; "
             "indicador {estado}", tipo=t(ETIQUETA[x["tipo"]]), metodo=t(x["metodo"]), indicador=x["indicador"],
             destino=t(x["destino"]), ips=ips, b=x["bytes"], p=x["primera"] or "-", u=x["ultima"] or "-",
             estado=t(x["estado"]))


def _linea(ip: str, xs: list) -> str:
    xs = sorted(xs, key=lambda x: (x["tipo"], x["metodo"], x["indicador"]))
    partes = [_indicador(x) for x in xs[:MAX_INDICADORES]]
    if len(xs) > MAX_INDICADORES:
        partes.append(t(" y {n} mas", n=len(xs) - MAX_INDICADORES))
    return t("{ip} ({activo}): {inds}", ip=ip, activo=xs[0]["activo"], inds="; ".join(partes))


def _lineas(inds: list) -> tuple:
    por_ip = collections.defaultdict(list)
    for x in inds:
        por_ip[x["ip"]].append(x)
    ips = sorted(por_ip, key=orden_ip)
    lineas = [_linea(ip, por_ip[ip]) for ip in ips[:MAX_ACTIVOS]]
    if len(ips) > MAX_ACTIVOS:
        lineas.append(t(" y {n} mas", n=len(ips) - MAX_ACTIVOS))
    return ips, lineas


def hallazgo(cap: Capture, inds: list) -> None:
    """Hasta dos hallazgos agregados para los indicadores (de una captura o de una exportacion)."""
    inds = [x for x in inds if x["estado"] != D_DESCARTADO]
    dns = [x for x in inds if x["tipo"] in TIPOS_DNS]
    canario = [x for x in inds if x["tipo"] == T_CANARIO]
    canal = [x for x in inds if x["tipo"] in TIPOS_CANAL]
    if dns:
        ips, lineas = _lineas(dns)
        if canario:
            cl = sorted({x["ip"] for x in canario}, key=orden_ip)
            lineas.append(t("{n} equipos consultaron el dominio canario de Firefox (use-application-dns.net): es "
                            "indicio de que Firefox puede activar DoH solo, no prueba que lo use ({ips})",
                            n=len(cl), ips=", ".join(cl[:MAX_ACTIVOS])))
        sin = any(x["estado"] == SIN_VERIFICAR for x in dns)
        finding(
            cap, "Baja", "DNS cifrado hacia resolvedores externos (DoH o DoQ)",
            unir("\n", [t("{n} equipos con DNS cifrado hacia resolvedores externos ({h})", n=len(ips),
                          h=", ".join(sorted({x["herramienta"] for x in dns})))] + lineas
                 + ([t("[indicador sin verificar: confirmar con el dueno del equipo]")] if sin else [])),
            "DNS sobre HTTPS o sobre QUIC va hacia un resolvedor externo por un puerto que el firewall suele "
            "dejar pasar: salta el DNS interno, su registro y los filtros por nombre. Un nombre, una IP o un puerto "
            "del catalogo es evidencia de que alguien lo usa o lo intenta, no prueba una sesion ni que sea no "
            "autorizada.",
            "Permitir DNS solo hacia el resolvedor interno; bloquear el puerto 853 (DoT y DoQ) y los resolvedores "
            "DoH conocidos en el firewall; configurar los navegadores y clientes para usar el DNS de la red. "
            "Limites: Encrypted Client Hello oculta el SNI y un DoH propio sobre HTTPS no se distingue de otro "
            "HTTPS, por lo que la ausencia de indicadores no demuestra que no exista.",
            categoria="Visibilidad", activos=[x["ip"] for x in dns],
        )
        if any(x["ot"] for x in dns):    # la severidad base es un literal para que las pruebas lean el titulo
            cap.findings[-1]["severidad"] = "Media"
    if canal:
        ips, lineas = _lineas(canal)
        sin = any(x["estado"] == SIN_VERIFICAR for x in canal)
        tipos = sorted({t(ETIQUETA[x["tipo"]]) for x in canal})
        finding(
            cap, "Media", "Canal anonimizador o tunel hacia Internet (Tor, VPN o proxy)",
            unir("\n", [t("{n} equipos con canales anonimizadores o tuneles hacia Internet ({h})", n=len(ips),
                          h=", ".join(tipos))] + lineas
                 + ([t("[indicador sin verificar: confirmar con el dueno del equipo]")] if sin else [])),
            "Tor, una VPN, un tunel o un proxy hacia Internet saltan el DNS interno, la segmentacion y la "
            "inspeccion del firewall, y abren un camino de entrada y de salida de datos que nadie vigila. Un "
            "nombre, un puerto, un protocolo o una IP de la lista es evidencia de que alguien lo usa o lo "
            "intenta, no prueba una sesion ni que sea no autorizada.",
            "Bloquear Tor y las VPN por aplicacion o por lista en el firewall, cerrar los puertos de VPN, tunel y "
            "proxy hacia Internet que no tengan dueno, y llevar el acceso remoto a la solucion autorizada con MFA y "
            "registro de sesiones. Limites: los puentes Tor ofuscados y una VPN sobre HTTPS no se distinguen de "
            "otro HTTPS, y sin --tor-relays solo se ven los puertos por defecto de Tor.",
            categoria="Segmentacion", activos=[x["ip"] for x in canal],
        )
        if any(x["ot"] for x in canal):
            cap.findings[-1]["severidad"] = "Alta"


@RULES
def evasion_canales(cap: Capture) -> None:
    inds = de_captura(cap, getattr(cap, "tor_relays", None))
    if inds:
        hallazgo(cap, inds)
