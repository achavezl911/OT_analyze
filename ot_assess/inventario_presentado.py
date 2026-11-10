"""Inventario presentado (I3, D105): las filas de inventario.csv, la hoja Inventario y las tablas de los reportes.

En una captura tomada detras de un enrutador todas las IP remotas llegan con la MAC del enrutador y
`merge_assets` las junta en un solo activo. Aqui esa MAC se presenta como una fila por IP (como ya hace
inventario_normalizado, D78), sin tocar `res.assets`. Una sola funcion produce las filas; el CSV, el HTML, el
Markdown, el Word y la consola cuentan las mismas. Las exportaciones de plataforma (sin capturas) no cambian.

Cada fila es un dict con las claves de un activo de `merge_assets`; los activos que no se parten se devuelven
tal cual (el mismo objeto). Las filas partidas agregan `mac_salto` y `nombre_dns`."""
from __future__ import annotations

import collections

from . import inventario_normalizado as _in
from .i18n import t
from .roles import inferir_rol


def _caps(res) -> list:
    return [c for c in res.caps if not c.error]


def _ips_partidas(a: dict, caps) -> list:
    """IP unicast que presenta una MAC de enrutamiento; [] si el activo no se parte (misma condicion que
    inventario_normalizado.registros_activos y mismas IP omitidas que _dividir_enrutada). Con una sola IP
    unicast no se parte."""
    ips = sorted(a["ips"])
    if not (caps and _in._enrutamiento(ips) and _in._mac(a["mac"])):
        return []
    out = []
    for ip in ips:
        d = _in._ipv4_unicast(ip)
        if d is not None and not d.is_link_local and not d.is_loopback:
            out.append(ip)
    # Una sola IP ya es una fila: partirla solo quitaria la MAC y el fabricante (redes OT con direccionamiento
    # publico, donde cada PLC tiene una IP publica y su propia MAC).
    return out if len(out) > 1 else []


def contar(res) -> int:
    """Numero de filas del inventario presentado (sin calcular nada mas)."""
    caps = _caps(res)
    return sum(len(_ips_partidas(a, caps)) or 1 for a in res.assets.values())


def hay_partidas(filas: list) -> bool:
    return any("mac_salto" in f for f in filas)


def _puerto(texto: str) -> tuple:
    p, _, l4 = texto.partition("/")
    return (int(p) if p.isdigit() else p, l4)


def _fila(a: dict, ip: str, caps_ip: dict, router: str, ot: dict, nombres: dict, rutas: dict, zonas: dict) -> dict:
    from .zonas import _zona_activo
    serv, usa, protos = collections.Counter(), collections.Counter(), collections.Counter()
    for d in caps_ip.values():
        serv.update(d["serv"])
        usa.update(d["usa"])
        protos.update(d["protos"])
    es_router = ip == router
    fab = ot.get("fabricante") or (a["vendor"] if es_router else "")
    host = {"proto_seen": protos, "ports_served": {_puerto(p) for p in serv}, "ports_used": {_puerto(p) for p in usa},
            "vendor": ot.get("fabricante") or "", "fingerprints": (), "hostnames": ()}
    rol, purdue, por_que = inferir_rol(host)
    nombre_dns = nombres.get(ip, "")
    z, o = _zona_activo({"ips": {ip}}, *((zonas or {}).get("tablas") or ([], [])))
    fila = {
        "nombre": ot.get("nombre") or nombre_dns or ip,
        "ips": {ip}, "mac": a["mac"] if es_router else "", "mac_salto": "" if es_router else a["mac"],
        "vendor": fab,
        "modelo": (a.get("modelo") or ot.get("modelo") or "") if es_router else ot.get("modelo", ""),
        "firmware": (a.get("firmware") or ot.get("firmware") or "") if es_router else ot.get("firmware", ""),
        "role": rol, "purdue": purdue, "role_why": por_que,
        "vlans": a["vlans"] if es_router else set(),
        "ports_served": [_puerto(p) for p in sorted(serv)],
        "protos": collections.Counter(protos),
        "pkts": sum(d["pkts"] for d in caps_ip.values()), "bytes": sum(d["bytes"] for d in caps_ip.values()),
        "capturas": set(caps_ip),
        "nombre_dns": nombre_dns,
        "interfaz_firewall": (rutas.get("asignacion") or {}).get(ip, ""),
        "zona_asignada": z, "origen_zona": o,
    }
    if es_router:
        for k in ("switch_puerto", "vlan", "nat_nota"):
            if a.get(k):
                fila[k] = a[k]
    return fila


def filas(res, nombres=None) -> list:
    """Filas presentadas, ordenadas por (-paquetes, mac); desempata por IP. `nombres`: {ip: nombre DNS}
    (registros_dns.nombre_de_ip); si no se da y hace falta, se calcula."""
    caps = _caps(res)
    partidas = {k: _ips_partidas(a, caps) for k, a in res.assets.items()}
    por_ip = _in._flujos_por_ip(caps) if any(partidas.values()) else {}
    if any(partidas.values()) and nombres is None:
        from . import registros_dns as _rd
        nombres = _rd.nombre_de_ip(res)
    out = []
    for k, a in res.assets.items():
        if not partidas[k]:
            out.append((a["pkts"], a["mac"], "", a))
            continue
        router = _in._ip_del_router(a["mac"], a["ips"], caps)
        for ip in partidas[k]:
            ot = (a.get("ot_por_ip") or {}).get(ip) or {}
            f = _fila(a, ip, por_ip.get(ip, {}), router, ot, nombres or {}, res.rutas or {}, res.zonas)
            out.append((f["pkts"], a["mac"], ip, f))
    out.sort(key=lambda x: (-x[0], x[1], x[2]))
    return [x[3] for x in out]


def nombre_dns(a: dict, nombres: dict) -> str:
    """Nombre DNS de la fila: el de su IP si la fila ya se partio, si no el de la primera IP del activo que tenga."""
    if "nombre_dns" in a:
        return a["nombre_dns"]
    return next((nombres[i] for i in sorted(a["ips"]) if i in nombres), "")


def mac_mostrada(a: dict) -> str:
    """MAC de la fila; en una fila partida sin MAC propia, la del salto entre parentesis."""
    if a["mac"] or not a.get("mac_salto"):
        return a["mac"]
    return "(" + a["mac_salto"] + ")"


def nota() -> str:
    return t("Las MAC de enrutamiento (una MAC con muchas IP o con IP publicas) no identifican un equipo: "
             "se muestra una fila por IP y la MAC del enrutador va en mac_salto.")
