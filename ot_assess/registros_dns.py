"""Registros DNS de las capturas: tres tablas agregadas sobre res.caps (DNS-a).

Fuente: cap.dns_eventos y cap.nombres_servidor (detail/dns.py). Sin hallazgos aqui.
"""
from __future__ import annotations

import collections
import ipaddress
from datetime import datetime, timezone

from .i18n import t

COL_REGISTROS = ["nombre", "tipo", "consultas", "respuestas", "sin_respuesta", "rcodes", "ttl_min",
                 "registros", "clientes", "servidores", "primera", "ultima", "ambito", "capturas"]
COL_RESOLUCIONES = ["ip", "nombre", "fuente", "veces", "capturas"]
COL_SERVIDORES = ["servidor", "ambito", "consultas", "respuestas", "rcodes", "clientes", "capturas"]

SUFIJOS_INTERNOS = ("local", "lan", "internal", "intranet", "corp", "home.arpa")


def _ip_de_arpa(nombre: str):
    """IP que representa un nombre in-addr.arpa / ip6.arpa completo, o None."""
    try:
        if nombre.endswith(".in-addr.arpa"):
            p = nombre[:-len(".in-addr.arpa")].split(".")
            return ipaddress.IPv4Address(".".join(reversed(p))) if len(p) == 4 else None
        if nombre.endswith(".ip6.arpa"):
            p = nombre[:-len(".ip6.arpa")].split(".")
            if len(p) != 32 or any(len(x) != 1 for x in p):
                return None
            h = "".join(reversed(p))
            return ipaddress.IPv6Address(":".join(h[i:i + 4] for i in range(0, 32, 4)))
    except ValueError:
        return None
    return None


def ambito_nombre(nombre: str, dominios=()) -> str:
    n = nombre.lower().rstrip(".")
    if n.endswith(".in-addr.arpa") or n.endswith(".ip6.arpa"):
        ip = _ip_de_arpa(n)
        return "interno" if ip is not None and ip.is_private else "externo"
    if "." not in n:
        return "interno"
    for d in (*SUFIJOS_INTERNOS, *dominios):
        if n == d or n.endswith("." + d):
            return "interno"
    return "externo"


def ambito_ip(ip: str) -> str:
    try:
        return "interno" if ipaddress.ip_address(ip).is_private else "publico"
    except ValueError:
        return "publico"


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _conteo(c: collections.Counter) -> str:
    return "; ".join(f"{k} {n}" for k, n in sorted(c.items(), key=lambda x: (-x[1], x[0])))


def _dominios(res) -> tuple:
    return tuple((getattr(res, "perfil", None) or {}).get("dominios_internos", ()))


def _sin_respuesta(cap) -> list:
    """Consultas de la captura sin respuesta, emparejadas por (cliente, servidor, id, nombre)."""
    # Una respuesta cubre todas las consultas con la misma clave (reintentos con el mismo id).
    resp = {(e["dst"], e["src"], e["id"], e["nombre"]) for e in cap.dns_eventos if e["resp"]}
    return [e for e in cap.dns_eventos
            if not e["resp"] and (e["src"], e["dst"], e["id"], e["nombre"]) not in resp]


def registros(res) -> list:
    doms = _dominios(res)
    filas = {}
    for cap in res.caps:
        sin = {id(e) for e in _sin_respuesta(cap)}
        for e in cap.dns_eventos:
            f = filas.setdefault((e["nombre"], e["tipo"]), {
                "consultas": 0, "respuestas": 0, "sin": 0, "rcodes": collections.Counter(),
                "ttl": None, "registros": [], "clientes": set(), "servidores": set(),
                "primera": e["t"], "ultima": e["t"], "capturas": set()})
            f["capturas"].add(cap.name)
            f["primera"], f["ultima"] = min(f["primera"], e["t"]), max(f["ultima"], e["t"])
            if not e["resp"]:
                f["consultas"] += 1
                f["sin"] += id(e) in sin
                cli, srv = e["src"], e["dst"]
            else:
                f["respuestas"] += 1
                cli, srv = e["dst"], e["src"]
                if e["rcode"]:
                    f["rcodes"][e["rcode"]] += 1
                for _dueno, tipo, valor, ttl in e["respuestas"]:
                    if ttl is not None and (f["ttl"] is None or ttl < f["ttl"]):
                        f["ttl"] = ttl
                    reg = f"{tipo} {valor}".strip()
                    if reg not in f["registros"]:
                        f["registros"].append(reg)
            if cli:
                f["clientes"].add(cli)
            if srv:
                f["servidores"].add(srv)
    out = [[n, t, f["consultas"], f["respuestas"], f["sin"], _conteo(f["rcodes"]),
            "" if f["ttl"] is None else f["ttl"], "; ".join(f["registros"]),
            ";".join(sorted(f["clientes"])), ";".join(sorted(f["servidores"])),
            _iso(f["primera"]), _iso(f["ultima"]), ambito_nombre(n, doms),
            ";".join(sorted(f["capturas"]))] for (n, t), f in filas.items()]
    return sorted(out, key=lambda r: (-r[2], r[0], r[1]))


def resoluciones(res) -> list:
    cuenta = collections.Counter()
    caps = collections.defaultdict(set)

    def sumar(ip, nombre, fuente, cap):
        if ip and nombre:
            cuenta[(ip, nombre, fuente)] += 1
            caps[(ip, nombre, fuente)].add(cap.name)

    for cap in res.caps:
        for e in cap.dns_eventos:
            if not e["resp"] or e["rcode"] not in ("", "NOERROR"):
                continue
            for dueno, tipo, valor, _ttl in e["respuestas"]:
                if tipo in ("A", "AAAA"):
                    for nombre in {e["nombre"], dueno}:
                        sumar(valor, nombre, "DNS " + tipo, cap)
                elif tipo == "PTR":
                    ip = _ip_de_arpa(dueno)
                    if ip is not None:
                        sumar(str(ip), valor.lower().rstrip("."), "DNS PTR", cap)
        for n in cap.nombres_servidor:
            sumar(n["ip"], n["nombre"], n["fuente"], cap)
    return [[ip, nombre, fuente, n, ";".join(sorted(caps[(ip, nombre, fuente)]))]
            for (ip, nombre, fuente), n in sorted(cuenta.items())]


def servidores(res) -> list:
    filas = {}
    for cap in res.caps:
        for e in cap.dns_eventos:
            srv, cli = (e["src"], e["dst"]) if e["resp"] else (e["dst"], e["src"])
            if not srv:
                continue
            f = filas.setdefault(srv, {"c": 0, "r": 0, "rcodes": collections.Counter(),
                                       "clientes": set(), "capturas": set()})
            f["capturas"].add(cap.name)
            if cli:
                f["clientes"].add(cli)
            if e["resp"]:
                f["r"] += 1
                if e["rcode"]:
                    f["rcodes"][e["rcode"]] += 1
            else:
                f["c"] += 1
    out = [[s, ambito_ip(s), f["c"], f["r"], _conteo(f["rcodes"]), len(f["clientes"]),
            ";".join(sorted(f["capturas"]))] for s, f in filas.items()]
    return sorted(out, key=lambda r: (-r[2], r[0]))


_ORDEN_FUENTE = {"DNS A": 0, "DNS AAAA": 0, "DNS PTR": 1, "TLS SNI": 2, "HTTP Host": 3}
TOP_NOMBRES = 20
MAX_REGISTROS = 80
SIN_DNS = "No se observo trafico DNS."
NOTA_MAS = "Hay mas nombres; la lista completa esta en dns_registros.csv."


def nombre_de_ip(res) -> dict:
    """{ip: "nombre1; nombre2"}: hasta 2 nombres por IP. Orden de fuente: DNS A/AAAA, PTR,
    TLS SNI, HTTP Host; dentro de la fuente, el mas visto primero."""
    por_ip = collections.defaultdict(dict)
    for ip, nombre, fuente, veces, _caps in resoluciones(res):
        clave = (_ORDEN_FUENTE.get(fuente, 9), nombre)
        por_ip[ip][clave] = por_ip[ip].get(clave, 0) + veces
    out = {}
    for ip, d in por_ip.items():
        nombres = []
        for (_rango, nombre), _n in sorted(d.items(), key=lambda x: (x[0][0], -x[1], x[0][1])):
            if nombre not in nombres:
                nombres.append(nombre)
        out[ip] = "; ".join(nombres[:2])
    return out


def _recortar(s: str) -> str:
    return s if len(s) <= MAX_REGISTROS else s[:MAX_REGISTROS - 3] + "..."


def seccion(res):
    """Datos de la seccion 'Resolucion de nombres (DNS)' de los reportes; None sin trafico DNS."""
    reg = registros(res)
    if not reg:
        return None
    srv = servidores(res)
    ambitos = {r[0]: r[12] for r in reg}
    resumen = t("{c} consultas, {r} respuestas, {s} consultas sin respuesta, {n} nombres "
                "distintos, {v} servidores, {i} nombres internos y {e} externos.",
                c=f"{sum(x[2] for x in reg):,}", r=f"{sum(x[3] for x in reg):,}",
                s=f"{sum(x[4] for x in reg):,}", n=len(ambitos), v=len(srv),
                i=sum(a == "interno" for a in ambitos.values()),
                e=sum(a == "externo" for a in ambitos.values()))
    return {
        "resumen": resumen,
        "cab_nombres": [t(c) for c in ("Nombre", "Tipo", "Consultas", "Rcodes", "Ambito", "Registros")],
        "nombres": [[r[0], r[1], r[2], r[5], t(r[12]), _recortar(r[7])] for r in reg[:TOP_NOMBRES]],
        "mas": len(reg) > TOP_NOMBRES,
        "cab_servidores": [t(c) for c in ("Servidor", "Ambito", "Consultas", "Respuestas", "Rcodes", "Clientes")],
        "servidores": [[r[0], t(r[1]), *r[2:6]] for r in srv],
    }
