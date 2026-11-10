"""F5c (D49): que hacer con cada ruta de un firewall y que destinos observados no tienen una ruta util.

Parte de `higiene.estado_rutas` (ARP, conductos por ruta y marcas) y de las IP de destino de los conductos
que cruzan el firewall. No inventa el salto correcto: eso queda para el analista y el dueno de la red."""
from __future__ import annotations

import collections
import ipaddress

from ..i18n import Traducido, t
from . import higiene as _hg
from . import topologia as _tp

A_MANTENER = "mantener"
A_ELIMINAR = "eliminar"
A_REVISAR = "revisar"
A_RESUMIR = "resumir"
ACCIONES = [A_MANTENER, A_ELIMINAR, A_REVISAR, A_RESUMIR]
PREFIJO_DESTINOS = 24
MAX_EJEMPLOS = 5

R_CONECTADA = "conectada"
R_OTRA = "ruta aprendida o no estatica: no se toca"
R_DEFECTO = "ruta por defecto"
R_DEFECTO_SIN_ARP = "ruta por defecto con salto sin ARP"
R_SIN_ARP_SIN = "salto sin ARP y sin conductos observados"
R_SIN_ARP_CON = "salto sin ARP con conductos observados: definir el salto correcto"
R_CUBIERTA = "cubierta por {red} (redundante: la cubre otra ruta con el mismo salto e interfaz)"
R_DOS_SALTOS = "mismo prefijo en dos saltos"
R_SIN_TRAFICO = "sin trafico observado (puede ser trafico poco frecuente)"
R_USADA = "salto en ARP y con conductos observados"
R_USADA_SIN_DATO = "con conductos observados; sin show arp no se valida el salto"
R_RESUMIBLE = "{n} rutas contiguas con el mismo salto e interfaz"
D_SOLO_DEFECTO = "solo la ruta por defecto"
D_SALTO_MUERTO = "salto que no responde"

TITULO = "Rutas propuestas"
NOTA = ("El ARP envejece: una ruta de uso poco frecuente puede no tener ARP en el momento de la captura. "
        "Confirmar con el dueno de la red antes de eliminar o resumir. La propuesta solo cubre lo observado y "
        "es evidencia tecnica relacionada, no una afirmacion de cumplimiento.")
HOJAS = {"rutas": "Rutas propuestas", "destinos": "Rutas destinos sin ruta"}
COL_RUTAS = ["red", "interfaz", "siguiente_salto", "tipo", "accion", "razon", "conductos", "salto_en_arp"]
COL_DESTINOS = ["red", "ruta_actual", "siguiente_salto", "conductos", "ejemplos", "razon"]
COL_RESUMIDAS = ["red_resumida", "interfaz", "siguiente_salto", "rutas"]


def _cubridora(r, fw):
    """La ruta que atenderia a r si se elimina: la mas especifica, distinta de r, que contiene su red."""
    otras = [o for o in fw.rutas if o is not r and o.red != r.red and r.red.subnet_of(o.red)]
    return max(otras, key=lambda o: o.red.prefixlen, default=None)


def _clasificar(r, f: dict, fw) -> tuple:
    """(accion, razon[clave, kw]) de una ruta."""
    if r.tipo in ("conectada", "local"):
        return A_MANTENER, [R_CONECTADA, {}]
    if r.tipo not in ("estatica", "defecto"):
        return A_MANTENER, [R_OTRA, {}]
    marcas = f["marcas"]
    sin_arp = _hg.M_SIN_ARP in marcas
    if r.tipo == "defecto":
        return (A_REVISAR, [R_DEFECTO_SIN_ARP, {}]) if sin_arp else (A_MANTENER, [R_DEFECTO, {}])
    if sin_arp:
        return (A_REVISAR, [R_SIN_ARP_CON, {}]) if f["conductos"] else (A_ELIMINAR, [R_SIN_ARP_SIN, {}])
    cub = _cubridora(r, fw)
    if (cub is not None and cub.salto == r.salto and cub.interfaz == r.interfaz
            and _hg.M_CUBIERTA in marcas):
        return A_ELIMINAR, [R_CUBIERTA, {"red": str(cub.red)}]
    if _hg.M_DOS_SALTOS in marcas:
        return A_REVISAR, [R_DOS_SALTOS, {}]
    if not f["conductos"]:
        return A_REVISAR, [R_SIN_TRAFICO, {}]
    return A_MANTENER, [R_USADA_SIN_DATO if f["salto_en_arp"] == _hg.SIN_DATO else R_USADA, {}]


def _resumir(filas: list) -> list:
    """Marca 'resumir' en las rutas mantener contiguas; devuelve las redes resumidas (una vez cada una)."""
    grupos = collections.defaultdict(list)
    for x in filas:
        if x["tipo"] == "estatica" and x["accion"] == A_MANTENER and x["siguiente_salto"]:
            grupos[(x["siguiente_salto"], x["interfaz"])].append(x)
    out = []
    for (salto, ifc), xs in sorted(grupos.items()):
        for net in ipaddress.collapse_addresses([ipaddress.ip_network(x["red"]) for x in xs]):
            miembros = [x for x in xs if ipaddress.ip_network(x["red"]).subnet_of(net)]
            if len(miembros) < 2:
                continue
            for x in miembros:
                x["accion"], x["resumen"] = A_RESUMIR, str(net)
                x["razon"] = [R_RESUMIBLE, {"n": len(miembros)}]
            out.append({"red_resumida": str(net), "interfaz": ifc, "siguiente_salto": salto,
                        "rutas": len(miembros), "miembros": [x["red"] for x in miembros]})
    return sorted(out, key=lambda o: (ipaddress.ip_network(o["red_resumida"]), o["siguiente_salto"]))


def _sin_ruta_util(fw, filas_por_id: dict, destinos: list) -> list:
    """Destinos (por /24) cuya ruta mas especifica es la de defecto o tiene el salto sin ARP."""
    acum: dict = {}
    for d in destinos:
        if d is None:
            continue
        ip = ipaddress.IPv4Address(d)
        if ip.is_multicast or ip.is_unspecified or ip == ipaddress.IPv4Address("255.255.255.255") or int(ip) & 0xFF == 0xFF:
            continue            # multicast y difusion no se enrutan
        r = fw.ruta_de(ip)
        if r is None:
            continue
        f = filas_por_id[id(r)]
        if _hg.M_SIN_ARP in f["marcas"]:
            razon = D_SALTO_MUERTO
        elif r.tipo == "defecto":
            if ip.is_global and not ip.is_multicast:
                continue        # Internet sale por la ruta por defecto: es lo esperado, no es un destino sin ruta
            razon = D_SOLO_DEFECTO
        else:
            continue
        red = ipaddress.IPv4Network(((int(ip) >> (32 - PREFIJO_DESTINOS)) << (32 - PREFIJO_DESTINOS),
                                     PREFIJO_DESTINOS))
        a = acum.setdefault((red, id(r)), {"r": r, "razon": razon, "n": 0, "ips": set()})
        a["n"] += 1
        a["ips"].add(int(ip))
    out = []
    for (red, _i), a in sorted(acum.items(), key=lambda kv: (kv[0][0], str(kv[1]["r"].red))):
        r = a["r"]
        out.append({"red": str(red), "ruta_actual": str(r.red), "siguiente_salto": r.salto,
                    "conductos": a["n"], "razon": a["razon"],
                    "ejemplos": [str(ipaddress.IPv4Address(x)) for x in sorted(a["ips"])[:MAX_EJEMPLOS]]})
    return out


def construir(fw, filas: list, destinos: list) -> dict:
    """Propuesta de un firewall. `filas` = higiene.estado_rutas(fw, destinos) (mismo orden que fw.rutas)."""
    por_id = {id(r): f for r, f in zip(fw.rutas, filas)}
    rutas = []
    for r, f in zip(fw.rutas, filas):
        accion, razon = _clasificar(r, f, fw)
        rutas.append({"red": f["red"], "interfaz": f["interfaz"], "siguiente_salto": f["siguiente_salto"],
                      "tipo": f["tipo"], "accion": accion, "resumen": "", "razon": razon,
                      "conductos": f["conductos"], "salto_en_arp": f["salto_en_arp"]})
    resumidas = _resumir(rutas)
    sin_ruta = _sin_ruta_util(fw, por_id, destinos)
    cuenta = {a: sum(1 for x in rutas if x["accion"] == a) for a in ACCIONES}
    return {"rutas": rutas, "resumidas": resumidas, "sin_ruta": sin_ruta,
            "resumen": {"por_accion": cuenta, "resumidas": len(resumidas), "destinos": len(sin_ruta),
                        "conductos_sin_ruta": sum(x["conductos"] for x in sin_ruta)}}


def combinar(ids: list, dicts: list) -> dict:
    """{'firewalls': [propuesta + id y prefijo], 'multiple': bool}."""
    return {"firewalls": [dict(d["rutas_propuestas"], id=i, prefijo=_tp.prefijo_archivo(i))
                          for i, d in zip(ids, dicts)],
            "multiple": len(dicts) > 1}


def hay(fw: dict) -> bool:
    rp = (fw or {}).get("rutas_propuestas")
    return bool(rp and any(p["rutas"] for p in rp["firewalls"]))


def _texto_accion(x: dict) -> str:
    return t("resumir en {red}", red=x["resumen"]) if x["accion"] == A_RESUMIR else t(x["accion"])


def filas_rutas(p: dict) -> list:
    return [[x["red"], x["interfaz"], x["siguiente_salto"], t(x["tipo"]), _texto_accion(x),
             t(x["razon"][0], **x["razon"][1]), x["conductos"], t(x["salto_en_arp"]) if x["salto_en_arp"] else ""]
            for x in p["rutas"]]


def filas_destinos(p: dict) -> list:
    return [[x["red"], x["ruta_actual"], x["siguiente_salto"], x["conductos"], ";".join(x["ejemplos"]),
             t(x["razon"])] for x in p["sin_ruta"]]


def filas_resumidas(p: dict) -> list:
    return [[x["red_resumida"], x["interfaz"], x["siguiente_salto"], ";".join(x["miembros"])]
            for x in p["resumidas"]]


def _hoja(p: dict, nombre: str, multiple: bool):
    return Traducido(p["id"] + " " + t(nombre)) if multiple else nombre


def tablas(rp: dict) -> list:
    """[(archivo, hoja, cabecera, filas)] por firewall."""
    out = []
    mult = rp["multiple"]
    for p in rp["firewalls"]:
        pre = (p["prefijo"] + "_") if mult else ""
        for base, clave, cab, f in (("rutas_propuestas.csv", "rutas", COL_RUTAS, filas_rutas),
                                    ("rutas_destinos_sin_ruta.csv", "destinos", COL_DESTINOS, filas_destinos)):
            out.append((pre + base, _hoja(p, HOJAS[clave], mult), cab, f(p)))
    return out


def resumen_texto(rp: dict) -> str:
    cu = collections.Counter()
    for p in rp["firewalls"]:
        cu.update(p["resumen"]["por_accion"])
    return t("Rutas: mantener {m}, eliminar {e}, revisar {r}, resumir {s} (en {n} redes resumidas). Destinos "
             "observados sin ruta util: {d} redes /24 con {c} conductos. Detalle en rutas_propuestas.csv y "
             "rutas_destinos_sin_ruta.csv.", m=cu[A_MANTENER], e=cu[A_ELIMINAR], r=cu[A_REVISAR], s=cu[A_RESUMIR],
             n=sum(p["resumen"]["resumidas"] for p in rp["firewalls"]),
             d=sum(p["resumen"]["destinos"] for p in rp["firewalls"]),
             c=sum(p["resumen"]["conductos_sin_ruta"] for p in rp["firewalls"]))


def tablas_reporte(rp: dict) -> list:
    """[(titulo, cabecera, filas)] para HTML, Markdown y Word."""
    mult = rp["multiple"]

    def pre(cab, filas, p):
        return ([t("Firewall")] + cab, [[p["id"]] + f for f in filas]) if mult else (cab, filas)
    acc, res, des = ([], []), ([], []), ([], [])
    for p in rp["firewalls"]:
        c, f = pre([t("Accion"), t("Rutas")], [[t(a), p["resumen"]["por_accion"][a]] for a in ACCIONES], p)
        acc = (c, acc[1] + f)
        c, f = pre([t(x) for x in ("Red resumida", "Interfaz", "Siguiente salto", "Rutas que reemplaza")],
                   filas_resumidas(p), p)
        res = (c, res[1] + f)
        c, f = pre([t(x) for x in ("Red", "Ruta actual", "Siguiente salto", "Conductos", "Ejemplos", "Razon")],
                   filas_destinos(p), p)
        des = (c, des[1] + f)
    out = [(t("Rutas propuestas por accion"),) + acc]
    if res[1]:
        out.append((t("Redes resumidas propuestas"),) + res)
    if des[1]:
        out.append((t("Destinos observados sin ruta util"),) + des)
    return out
