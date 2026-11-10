"""Reglas de DNS: hallazgos a partir de cap.dns_eventos (detail/dns.py) y cap.flows (DNS-b).

La unidad de "sin respuesta" es el paquete de consulta sin respuesta (incluye reintentos).
LLMNR/NBT-NS/mDNS los cubre exposure.descubrimiento_windows; el colector ya los excluye.
"""
from __future__ import annotations

import collections

from ..i18n import t, unir
from ..model import Capture
from ..registros_dns import _sin_respuesta, ambito_ip, ambito_nombre
from .base import RULES, finding

MAX_EVIDENCIA = 10
FALLAS_MIN = 20              # respuestas REFUSED+SERVFAIL
FALLAS_PCT_RESP = 0.20
SIN_RESP_MIN = 20            # consultas (paquetes) sin respuesta
SIN_RESP_PCT = 0.10
NXDOMAIN_MIN = 50
NXDOMAIN_RESP_MIN = 20
NXDOMAIN_PCT = 0.30
TUNEL_ETIQUETA = 50        # caracteres, se dispara con mas de
TUNEL_SUBDOMINIOS = 100      # distintos bajo un dominio, se dispara con mas de
TUNEL_TXT_NULL = 50          # consultas TXT o NULL, se dispara con al menos
TIPOS_TUNEL = ("TXT", "NULL", "10")
PUERTO_DOT = "853"


def _lista(items, max_n=MAX_EVIDENCIA) -> str:
    """'a, b, c' con hasta max_n elementos y 'y N mas' si hay mas."""
    items = list(items)
    resto = t(" y {n} mas", n=len(items) - max_n) if len(items) > max_n else ""
    return t("{lista}{resto}", lista=", ".join(items[:max_n]), resto=resto)


def _consultas(cap: Capture) -> list:
    return [e for e in cap.dns_eventos if not e["resp"]]


def _respuestas(cap: Capture) -> list:
    return [e for e in cap.dns_eventos if e["resp"]]


def _conteos(c: collections.Counter) -> list:
    return [f"{k} ({n})" for k, n in sorted(c.items(), key=lambda x: (-x[1], x[0]))]


@RULES
def dns_wpad(cap: Capture) -> None:
    wpad = [e for e in _consultas(cap) if e["nombre"] == "wpad" or e["nombre"].startswith("wpad.")]
    if not wpad:
        return
    nombres = collections.Counter(e["nombre"] for e in wpad)
    clientes = sorted({e["src"] for e in wpad})
    finding(
        cap, "Media", "Busqueda de proxy WPAD por DNS",
        t("{n} consultas; nombres: {nombres}; clientes ({nc}): {clientes}", n=len(wpad),
          nombres=_lista(_conteos(nombres)), nc=len(clientes), clientes=_lista(clientes)),
        "Quien registre o responda ese nombre puede hacerse pasar por el proxy e interceptar "
        "trafico web.",
        "Deshabilitar la autodeteccion de proxy (WPAD) por GPO y crear un registro wpad "
        "controlado o bloquearlo en el DNS interno.",
        categoria="Exposicion",
    )


@RULES
def dns_publico(cap: Capture) -> None:
    pub = [e for e in _consultas(cap) if e["dst"] and ambito_ip(e["dst"]) == "publico"]
    if not pub:
        return
    por_srv = collections.Counter(e["dst"] for e in pub)
    clientes = sorted({e["src"] for e in pub})
    finding(
        cap, "Media", "Consultas DNS a servidores publicos",
        t("{n} consultas a {ns} servidores: {srv}; clientes ({nc}): {clientes}", n=len(pub),
          ns=len(por_srv), srv=_lista(_conteos(por_srv)), nc=len(clientes), clientes=_lista(clientes)),
        "Equipos de la red resuelven nombres directamente con servidores de Internet, fuera del "
        "DNS interno: se salta el control del perimetro, se filtran nombres internos y el "
        "canal sirve para comando y control o exfiltracion.",
        "Forzar la resolucion por los DNS internos y bloquear en el firewall el puerto 53 "
        "(y 853) hacia Internet desde las zonas OT.",
        categoria="Segmentacion",
    )


@RULES
def dns_dominios_internet(cap: Capture) -> None:
    ext = [e for e in _consultas(cap) if ambito_nombre(e["nombre"], cap.dominios_internos) == "externo"]
    if not ext:
        return
    nombres = collections.defaultdict(lambda: [0, set()])
    for e in ext:
        nombres[e["nombre"]][0] += 1
        nombres[e["nombre"]][1].add(e["src"])
    top = sorted(nombres.items(), key=lambda x: (-x[1][0], x[0]))
    ev = [t("{nombre} ({n} consultas; clientes: {clientes})", nombre=n, n=v[0],
            clientes=_lista(sorted(v[1]), 3)) for n, v in top[:MAX_EVIDENCIA]]
    resto = t(" y {n} mas", n=len(top) - MAX_EVIDENCIA) if len(top) > MAX_EVIDENCIA else ""
    finding(
        cap, "Baja", "Resolucion de dominios de Internet desde la red",
        t("{n} nombres externos, {c} consultas; mas consultados: {ev}{resto}", n=len(top),
          c=len(ext), ev="; ".join(ev), resto=resto),
        "Una red de control no deberia necesitar nombres de Internet; indican acceso a Internet, "
        "actualizaciones automaticas o software de terceros que se comunica hacia afuera.",
        "Validar cada dominio con su dueno, permitir solo los necesarios mediante lista blanca "
        "en el DNS o proxy y bloquear el resto.",
        categoria="Segmentacion",
    )


@RULES
def dns_fallas(cap: Capture) -> None:
    resp, cons = _respuestas(cap), _consultas(cap)
    fallas = [e for e in resp if e["rcode"] in ("REFUSED", "SERVFAIL")]
    sin = _sin_respuesta(cap)
    por_resp = len(fallas) >= FALLAS_MIN and len(fallas) >= FALLAS_PCT_RESP * len(resp)
    por_sin = len(sin) >= SIN_RESP_MIN and len(sin) >= SIN_RESP_PCT * len(cons)
    if not (por_resp or por_sin):
        return
    partes = []
    if por_resp:
        c = collections.Counter(e["src"] for e in fallas)
        r = collections.Counter(e["rcode"] for e in fallas)
        partes.append(t("{n} de {total} respuestas con falla ({tipos}); servidores: {srv}",
                        n=len(fallas), total=len(resp), tipos=_lista(_conteos(r)),
                        srv=_lista(_conteos(c))))
    if por_sin:
        c = collections.Counter(e["dst"] for e in sin)
        partes.append(t("{n} de {total} paquetes de consulta sin respuesta; servidores: {srv}",
                        n=len(sin), total=len(cons), srv=_lista(_conteos(c))))
    finding(
        cap, "Baja", "Fallas de resolucion DNS", unir("; ", partes),
        "Las fallas continuas indican un servidor DNS mal configurado, inalcanzable o que "
        "rechaza a los clientes; los equipos pueden perder resolucion y reintentar sin parar.",
        "Revisar la configuracion DNS de los clientes, la disponibilidad de los servidores y las "
        "reglas del firewall hacia ellos.",
        categoria="Configuracion",
    )


@RULES
def dns_nxdomain(cap: Capture) -> None:
    resp = collections.Counter(e["dst"] for e in _respuestas(cap))
    nx = collections.Counter(e["dst"] for e in _respuestas(cap) if e["rcode"] == "NXDOMAIN")
    malos = {c: n for c, n in nx.items() if c and (
        n >= NXDOMAIN_MIN or (resp[c] >= NXDOMAIN_RESP_MIN and n >= NXDOMAIN_PCT * resp[c]))}
    if not malos:
        return
    ev = [t("{c} ({n} de {total} respuestas)", c=c, n=n, total=resp[c]) for c, n in
          sorted(malos.items(), key=lambda x: (-x[1], x[0]))]
    finding(
        cap, "Baja", "Cliente con muchas respuestas NXDOMAIN",
        t("{n} {palabra}: {lista}", n=len(malos),
          palabra=t("cliente") if len(malos) == 1 else t("clientes"), lista=_lista(ev)),
        "Muchos nombres inexistentes sugieren configuracion errada, software roto o malware "
        "que genera dominios (DGA) o hace descubrimiento por DNS.",
        "Revisar en cada cliente que genera las consultas fallidas y corregir la configuracion "
        "o aislar el equipo si no hay explicacion.",
        categoria="Anomalia",
    )


@RULES
def dns_tunel(cap: Capture) -> None:
    cons = _consultas(cap)
    largas = sorted({e["nombre"] for e in cons
                     if any(len(et) > TUNEL_ETIQUETA for et in e["nombre"].split("."))})
    subs = collections.defaultdict(set)
    for e in cons:
        et = e["nombre"].split(".")
        if len(et) > 2:
            subs[".".join(et[-2:])].add(e["nombre"])
    muchos = {d: len(s) for d, s in subs.items() if len(s) > TUNEL_SUBDOMINIOS}
    txt = [e for e in cons if e["tipo"] in TIPOS_TUNEL]
    por_txt = len(txt) >= TUNEL_TXT_NULL
    if not (largas or muchos or por_txt):
        return
    partes = []
    if largas:
        partes.append(t("{n} nombres con una etiqueta de mas de {max} caracteres: {lista}",
                        n=len(largas), max=TUNEL_ETIQUETA,
                        lista=_lista(n[:60] + "..." if len(n) > 60 else n for n in largas)))
    if muchos:
        partes.append(t("subdominios distintos por dominio: {lista}",
                        lista=_lista(_conteos(collections.Counter(muchos)))))
    if por_txt:
        c = collections.Counter(e["src"] for e in txt)
        partes.append(t("{n} consultas TXT o NULL; clientes: {lista}", n=len(txt),
                        lista=_lista(_conteos(c))))
    finding(
        cap, "Media", "Posible tunel DNS", unir("; ", partes),
        "Etiquetas largas, muchos subdominios unicos o consultas TXT/NULL en volumen son el "
        "patron de un tunel DNS para comando y control o exfiltracion, y atraviesa firewalls "
        "que permiten el puerto 53.",
        "Identificar los clientes y dominios implicados, inspeccionar su trafico y restringir "
        "la resolucion externa a los DNS internos; si no tiene explicacion, contener el equipo.",
        categoria="Anomalia",
    )


@RULES
def dns_transferencia_zona(cap: Capture) -> None:
    xfr = [e for e in _consultas(cap) if e["tipo"] in ("AXFR", "IXFR")]
    if not xfr:
        return
    c = collections.Counter(f"{e['src']} -> {e['dst']} {e['tipo']} {e['nombre']}" for e in xfr)
    finding(
        cap, "Media", "Intento de transferencia de zona DNS",
        t("{n} consultas: {lista}", n=len(xfr), lista=_lista(_conteos(c))),
        "AXFR/IXFR entrega todos los nombres de una zona: es un reconocimiento de la red y "
        "solo debe ocurrir entre servidores DNS autorizados.",
        "Limitar las transferencias de zona a los servidores secundarios autorizados y "
        "revisar el origen de estas consultas.",
        categoria="Exposicion",
    )


@RULES
def dns_dot(cap: Capture) -> None:
    dot = [f for f in cap.flows.values() if f["l4"] == "tcp" and f["dport"] == PUERTO_DOT]
    if not dot:
        return
    srv = collections.Counter()
    for f in dot:
        srv[f["dst"]] += f["pkts"]
    clientes = sorted({f["src"] for f in dot})
    finding(
        cap, "Baja", "DNS cifrado sin visibilidad (DoT)",
        t("{n} flujos TCP al puerto 853; servidores: {srv}; clientes ({nc}): {clientes}",
          n=len(dot), srv=_lista(_conteos(srv)), nc=len(clientes), clientes=_lista(clientes)),
        "DNS sobre TLS oculta las consultas al monitoreo y a los controles del DNS interno; "
        "puede usarse para evadir inspeccion.",
        "Bloquear el puerto 853 hacia Internet o dirigirlo a un resolvedor interno que registre "
        "las consultas.",
        categoria="Visibilidad",
    )
