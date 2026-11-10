"""A1 (D52): rutas de ataque por alcanzabilidad sobre los conductos observados.

Grafo dirigido de activos (arista u -> v = conducto observado de u, cliente, a v, servidor, no negado por el
firewall). Busca, por BFS desde cada origen (Internet y zonas IT), el camino mas corto hasta cada activo
critico y cuenta los puntos de paso. Es alcanzabilidad por comunicaciones observadas, no una prueba de
explotacion. Funciones puras sobre el modelo ya calculado.
"""
from __future__ import annotations

import collections
import ipaddress
import re

from .catalog import CRIT_ORDER
from .firewalls import cruces as _cr
from .i18n import t
from .remediacion import criticidad_activo

TITULO = "Rutas de ataque"
HOJA = "Rutas de ataque"
HOJA_PUNTOS = "Puntos de paso"
ARCHIVO = "rutas_ataque.csv"
ARCHIVO_PUNTOS = "rutas_ataque_puntos.csv"
COLUMNAS = ["origen", "objetivo", "zona_objetivo", "criticidad", "saltos", "camino", "acceso_remoto",
            "conductos_zcr", "reglas_firewall"]
COLUMNAS_PUNTOS = ["tipo", "nombre", "caminos"]
INTERNET = "Internet"
MAX_SALTOS = 6
MAX_TOP = 10
CRITICOS = ("Critica", "Alta")
T_ACTIVO = "activo"
T_ZCR = "conducto ZCR"
T_REGLA = "regla"
TIT = ("Activos criticos alcanzables desde Internet o IT por comunicaciones observadas "
       "(segun los conductos observados)")
NOTA = ("Es alcanzabilidad por comunicaciones observadas, no una prueba de explotacion: un camino indica que "
        "existe comunicacion permitida en cada salto, no que cada salto sea vulnerable. Los puntos de paso "
        "son los mejores lugares para cortar varios caminos a la vez.")
_REMOTO = _cr._REMOTO | _cr._ADMIN
_NEGADOS = ("denegado_observado", "sin_regla")
_EFIMERO = 32768
_TOKENS = re.compile(r"[^A-Z0-9]+")


def _ip(x):
    try:
        return ipaddress.ip_address(str(x).strip())
    except ValueError:
        return None


def _es_origen_it(nombre: str) -> bool:
    toks = [x for x in _TOKENS.split(str(nombre).upper()) if x]
    return "IT" in toks or "INTERNET" in toks or any(x.startswith("CORP") for x in toks)


def _remoto(svc: str) -> bool:
    p = svc.rsplit("/", 1)[-1]
    return p.isdigit() and int(p) in _REMOTO


def _reglas(r: dict, multiple: bool) -> set:
    out = set()
    camino = r.get("camino")
    if camino:
        for x in camino:
            if x["resultado"] == "permitido" and x.get("regla_id"):
                out.add(f"{x['fw']}: {x['regla_id']} {x.get('regla_nombre', '')}".strip())
    elif not multiple and r.get("resultado") == "permitido" and r.get("regla"):
        out.add((str(r["regla"]) + " " + str(r.get("regla_nombre", ""))).strip())
    return out


def _servicio(c: dict) -> str:
    l4 = str(c.get("l4") or "").strip().lower()
    p = _cr._puerto(c)
    if p is None:
        return l4 or "ip"
    return f"{l4}/{p}" if l4 else str(p)


def _grafo(assets: dict, conductos: list, firewall: dict) -> tuple:
    """(nodos, adj). nodos: {id: {ip, zona, activo, externo, orden}}; adj: {u: {v: {servicio: {reglas}}}}."""
    from .conductos_zcr import _ip_de

    ip_de = _ip_de(assets)
    por_ip: dict = {}
    for k, a in assets.items():
        for ip in a["ips"]:
            por_ip.setdefault(ip, (k, a))
    fw = firewall or {}
    res_fw = fw.get("resultados") or []
    con_fw = "hostname" in fw and len(res_fw) == len(conductos)
    multiple = bool(fw.get("firewalls")) and len(fw["firewalls"]) > 1
    nodos: dict = {}

    def nodo(ip):
        hit = por_ip.get(ip)
        nid = hit[0] if hit else ip
        if nid not in nodos:
            a = hit[1] if hit else None
            x = _ip(ip)
            ext = x is not None and x.is_global and not x.is_multicast and (
                a is None or a.get("origen_zona") == "internet")
            zona = INTERNET if ext else ((a or {}).get("zona_asignada") or "")
            ips = min(a["ips"], key=_cr._orden_ip) if a else ip
            nodos[nid] = {"ip": ips, "zona": zona, "activo": a, "externo": ext, "orden": _cr._orden_ip(ips)}
        return nid

    puertos: dict = {}
    if not con_fw:                # sin firewall no hay "respuesta": se reconoce por puerto efimero con vuelta
        for c in conductos:
            p = _cr._puerto(c)
            if p is not None and p < _EFIMERO:
                puertos[(str(ip_de(c.get("src"))), str(ip_de(c.get("dst"))))] = True
    adj: dict = collections.defaultdict(lambda: collections.defaultdict(dict))
    for i, c in enumerate(conductos):
        r = res_fw[i] if con_fw else {}
        if r.get("resultado") in _NEGADOS or r.get("resultado") == "respuesta":
            continue
        s, d = str(ip_de(c.get("src"))), str(ip_de(c.get("dst")))
        if r.get("sentido") == "invertido":
            s, d = d, s
        p = _cr._puerto(c)
        if not con_fw and p is not None and p >= _EFIMERO and puertos.get((d, s)):
            continue
        u, v = nodo(s), nodo(d)
        if u == v or nodos[v]["externo"]:
            continue
        adj[u][v].setdefault(_servicio(c), set()).update(_reglas(r, multiple) if con_fw else ())
    return nodos, adj


def _bfs(fuentes: list, adj: dict, nodos: dict) -> tuple:
    """(dist, padre) desde un conjunto de nodos; el desempate es el orden por IP."""
    dist = {n: 0 for n in fuentes}
    padre: dict = {}
    cola = collections.deque(fuentes)
    vecinos: dict = {}
    while cola:
        u = cola.popleft()
        if u not in vecinos:
            vecinos[u] = sorted(adj.get(u, ()), key=lambda n: nodos[n]["orden"])
        for v in vecinos[u]:
            if v not in dist:
                dist[v] = dist[u] + 1
                padre[v] = u
                cola.append(v)
    return dist, padre


def _servicio_salto(servicios: dict) -> str:
    return min(servicios, key=lambda s: (not _remoto(s), s))


def construir(assets: dict, conductos: list, zonas: dict, firewall: dict | None, perfil: dict | None = None,
              zcr: dict | None = None, origenes=(), objetivos=()) -> dict:
    """Rutas de ataque; {} si no hay conductos o activos."""
    if not conductos or not assets:
        return {}
    nodos, adj = _grafo(assets, conductos, firewall or {})
    declaradas = (perfil or {}).get("criticidad_activos", {})
    avisos = []
    nombres_zona = {f["zona"] for f in (zonas or {}).get("filas", ())}
    for z in [*origenes, *objetivos]:
        if z not in nombres_zona:
            avisos.append(t("La zona '{z}' de las opciones de rutas de ataque no existe en el analisis.", z=z))
    zcr_id = {frozenset((f["zona_a"], f["zona_b"])): f["id"] for f in (zcr or {}).get("filas", ())}

    ext = sorted((n for n, x in nodos.items() if x["externo"] and adj.get(n)), key=lambda n: nodos[n]["orden"])
    lista = [(INTERNET, ext)]
    if origenes:
        nz = [z for z in dict.fromkeys(origenes) if z in nombres_zona and z != INTERNET]
    else:
        nz = [z for z in sorted(nombres_zona) if z != INTERNET and _es_origen_it(z)]
    for z in nz:
        lista.append((z, sorted((n for n, x in nodos.items() if x["zona"] == z and not x["externo"]),
                                key=lambda n: nodos[n]["orden"])))

    crit: dict = {}
    for n, x in nodos.items():
        a = x["activo"]
        if a is not None and not x["externo"]:
            crit[n] = criticidad_activo(a, declaradas)[0]
    obj = {n for n, c in crit.items() if c in CRITICOS}
    obj |= {n for n, x in nodos.items() if x["zona"] in objetivos and not x["externo"] and n in crit}

    filas: list = []
    resumen = []
    for oi, (nombre, fuentes) in enumerate(lista):
        dist, padre = _bfs(fuentes, adj, nodos) if fuentes else ({}, {})
        ya = set(fuentes)
        alc = [n for n in obj if n in dist and n not in ya]
        fuera = sum(1 for n in alc if dist[n] > MAX_SALTOS)
        por_saltos: collections.Counter = collections.Counter()
        for n in sorted(alc, key=lambda n: nodos[n]["orden"]):
            if dist[n] > MAX_SALTOS:
                continue
            por_saltos[dist[n]] += 1
            ruta = [n]
            while ruta[0] in padre:
                ruta.insert(0, padre[ruta[0]])
            filas.append(_fila(nombre, oi, ruta, nodos, adj, crit, zcr_id))
        resumen.append({"origen": nombre, "origenes": len(fuentes), "alcanzables": sum(por_saltos.values()),
                        "por_saltos": dict(sorted(por_saltos.items())), "fuera": fuera})
    filas.sort(key=lambda f: (f["saltos"], f["_oi"], CRIT_ORDER.get(f["criticidad"], 9), f["_orden"]))
    return {"filas": filas, "origenes": resumen, "objetivos": len(obj), "avisos": avisos,
            "puntos": _puntos(filas), "max_saltos": MAX_SALTOS}


def _fila(nombre: str, oi: int, ruta: list, nodos: dict, adj: dict, crit: dict, zcr_id: dict) -> dict:
    partes = []
    remoto = False
    zcrs, reglas = [], []
    saltos = []
    for u, v in zip(ruta, ruta[1:]):   # pares consecutivos sin la API de 3.10
        svc = _servicio_salto(adj[u][v])
        remoto = remoto or _remoto(svc)
        z = zcr_id.get(frozenset((nodos[u]["zona"], nodos[v]["zona"])))
        if z and z not in zcrs:
            zcrs.append(z)
        reglas += [x for x in sorted(adj[u][v][svc]) if x not in reglas]
        saltos.append((u, v, svc))
    for n in ruta:
        x = nodos[n]
        partes.append(f"{x['ip']} ({x['zona'] or t('sin zona')})")
    txt = partes[0]
    for (_u, _v, svc), p in zip(saltos, partes[1:]):
        txt += f" -[{svc}]-> {p}"
    fin = nodos[ruta[-1]]
    return {"origen": nombre, "objetivo": fin["ip"], "zona_objetivo": fin["zona"], "criticidad": crit[ruta[-1]],
            "saltos": len(ruta) - 1, "camino": txt, "acceso_remoto": "si" if remoto else "no",
            "conductos_zcr": ", ".join(zcrs), "reglas_firewall": "; ".join(reglas),
            "_oi": oi, "_orden": fin["orden"], "_ruta": ruta, "_zcr": zcrs, "_reglas": reglas,
            "_nombres": [nodos[n]["ip"] + " (" + (nodos[n]["zona"] or t("sin zona")) + ")" for n in ruta]}


def _puntos(filas: list) -> list:
    cuenta: collections.Counter = collections.Counter()
    for f in filas:
        for nm in f["_nombres"][1:-1]:
            cuenta[(T_ACTIVO, nm)] += 1
        for z in f["_zcr"]:
            cuenta[(T_ZCR, z)] += 1
        for r in f["_reglas"]:
            cuenta[(T_REGLA, r)] += 1
    orden = {T_ACTIVO: 0, T_ZCR: 1, T_REGLA: 2}
    return [{"tipo": k[0], "nombre": k[1], "caminos": n}
            for k, n in sorted(cuenta.items(), key=lambda kv: (orden[kv[0][0]], -kv[1], kv[0][1]))]


def hay(ra: dict) -> bool:
    return bool(ra) and bool(ra.get("filas"))


def filas_tabla(ra: dict) -> list:
    return [[f[c] for c in COLUMNAS] for f in ra["filas"]]


def filas_puntos(ra: dict) -> list:
    return [[p["tipo"], p["nombre"], p["caminos"]] for p in ra["puntos"]]


def tablas(ra: dict) -> list:
    """[(archivo, hoja, cabecera, filas)] para el CSV y el XLSX."""
    if not hay(ra):
        return []
    return [(ARCHIVO, HOJA, COLUMNAS, filas_tabla(ra)),
            (ARCHIVO_PUNTOS, HOJA_PUNTOS, COLUMNAS_PUNTOS, filas_puntos(ra))]


def resumen_texto(ra: dict) -> str:
    partes = []
    for o in ra["origenes"]:
        if o["origen"] == INTERNET and not o["origenes"]:
            partes.append(t("Internet no tiene camino de entrada observado."))
            continue
        detalle = ", ".join(f"{n} " + t("saltos") + f": {c}" for n, c in o["por_saltos"].items()) or "-"
        txt = t("Desde {o}: {n} de {m} objetivos alcanzables ({d}).", o=o["origen"], n=o["alcanzables"],
                m=ra["objetivos"], d=detalle)
        if o["fuera"]:
            txt += " " + t("{n} mas quedan a mas de {s} saltos.", n=o["fuera"], s=ra["max_saltos"])
        partes.append(txt)
    return " ".join(partes)


def tabla_caminos(ra: dict, n: int = MAX_TOP) -> tuple:
    cab = [t("origen"), t("criticidad"), t("saltos"), t("camino"), t("acceso_remoto")]
    return cab, [[f["origen"], t(f["criticidad"]), f["saltos"], f["camino"], t(f["acceso_remoto"])]
                 for f in ra["filas"][:n]]


def tabla_puntos(ra: dict, n: int = MAX_TOP) -> tuple:
    cab = [t("tipo"), t("nombre"), t("caminos")]
    filas = []
    for tipo in (T_ACTIVO, T_ZCR, T_REGLA):
        filas += [[t(p["tipo"]), p["nombre"], p["caminos"]] for p in ra["puntos"] if p["tipo"] == tipo][:n]
    return cab, filas


def agregar_hallazgos(cap, ra: dict) -> None:
    """Hallazgo de activos criticos alcanzables desde Internet o IT. Alcanzabilidad, no cumplimiento."""
    from .rules.base import finding

    if not hay(ra) or not ra["filas"]:
        return
    alta = any(f["origen"] == INTERNET or (f["saltos"] <= 2 and f["acceso_remoto"] == "si") for f in ra["filas"])
    top = [f["camino"] for f in ra["filas"][:MAX_TOP]]
    finding(cap, "Alta" if alta else "Media", TIT,
            t("Caminos: {n}. {lista}", n=len(ra["filas"]), lista=" | ".join(top)),
            "Un atacante con acceso a Internet o a la red IT podria llegar a estos activos criticos saltando por "
            "equipos que ya se comunican entre si; cada salto es una comunicacion observada, no una "
            "vulnerabilidad probada.",
            "Cortar los caminos en los puntos de paso que mas concentran (activos, conductos entre zonas y "
            "reglas del firewall) y limitar el acceso remoto entre zonas a los equipos que lo requieren.",
            "Segmentacion", activos=[f["objetivo"] for f in ra["filas"]])
