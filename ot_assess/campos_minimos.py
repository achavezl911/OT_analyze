"""CAMPOS1 (D141): campos minimos por salida (activos, flujos, direccionamiento, matriz de segmentacion, fuentes de log).

Con la clave de perfil `campos_minimos` ({} vale) agrega columnas AL FINAL de inventario_normalizado.csv,
comunicaciones.csv, direccionamiento_ip.csv y fuentes_log.csv, y una tabla nueva matriz_segmentacion.csv (zona x zona:
lo observado y la politica esperada que declara el perfil). Es formato, no riesgo: no genera hallazgos. Solo lee el
modelo ya calculado; las horas son UTC. Sin la clave no hace nada (las salidas quedan identicas).
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone

from . import conductos_zcr as _zc
from .i18n import t
from .zonas import mostrar_zona

CLAVE = "campos_minimos"
ARCHIVO_MATRIZ = "matriz_segmentacion.csv"
HOJA_MATRIZ = "Matriz de segmentacion"
DOMINIOS = ("IT", "OT", "DMZ")
SIN_DATO, MIXTO, PENDIENTE, SIN_DECLARAR = "sin dato", "mixto", "PENDIENTE", "sin declarar"
MAX_DUENOS = 500
MAX_POLITICAS = 2500
MAX_TEXTO_DUENO = 100
MAX_TEXTO_POLITICA = 60
MAX_ZONAS_MATRIZ = 100
COMODIN = "*"
FORMATO = "%Y-%m-%dT%H:%M:%SZ"

COL_INVENTARIO = ["sitio", "dominio", "primera_vez_visto", "ultima_vez_visto", "as_of"]
COL_COMUNICACIONES = ["origen_id", "destino_id", "primera_vez_visto", "ultima_vez_visto", "dataset_id",
                      "origen_dominio", "destino_dominio", "cruza_it_ot"]
COL_DIRECCIONAMIENTO = ["sitio", "dominio", "dueno"]
COL_FUENTES = ["destinos", "volumen_bytes", "volumen_paquetes"]
COL_MATRIZ = ["zona_origen", "zona_destino", "observado", "servicios", "conductos", "bytes", "politica_esperada"]

# Puertos de registro de los que sale el volumen de fuentes_log.csv: syslog, trampas SNMP, NetFlow e IPFIX.
PUERTOS_LOG = frozenset({("udp", "514"), ("tcp", "514"), ("tcp", "6514"), ("udp", "162"), ("udp", "2055"),
                         ("udp", "4739"), ("udp", "9995"), ("udp", "9996")})

_RE_SITIO = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
_RE_FECHA = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.\d{1,6})?)?(Z|[+-]\d{2}:\d{2})$")
_RE_NIVEL = re.compile(r"(?<![\d.])(\d(?:\.\d)?)(?!\d)")


# --------------------------------------------------------------------------- #
# Perfil
# --------------------------------------------------------------------------- #

def _a_utc(texto: str):
    """Fecha ISO 8601 con Z u offset -> 'YYYY-MM-DDTHH:MM:SSZ' en UTC; None si no es valida."""
    m = _RE_FECHA.match(texto)
    if not m:
        return None
    y, mo, d, h, mi, s = (int(m.group(i) or 0) for i in range(1, 7))
    try:
        dt = datetime(y, mo, d, h, mi, s, tzinfo=timezone.utc)
        if m.group(7) != "Z":
            oh, om = int(m.group(7)[1:3]), int(m.group(7)[4:6])
            if oh > 23 or om > 59:
                return None
            dt -= (1 if m.group(7)[0] == "+" else -1) * timedelta(hours=oh, minutes=om)
    except (ValueError, OverflowError):
        return None
    return dt.strftime(FORMATO)


def _texto(v, minimo: int, maximo: int):
    return v.strip() if isinstance(v, str) and minimo <= len(v.strip()) <= maximo else None


def validar(v, fallo, objeto, zonas=()) -> dict:
    """Normaliza la clave de perfil `campos_minimos` ({} vale). `zonas`: las zonas ya validadas del perfil."""
    v = objeto(v, CLAVE, ("sitio", "as_of", "duenos", "politica_esperada"))
    out: dict = {}
    if "sitio" in v:
        if not isinstance(v["sitio"], str) or not _RE_SITIO.match(v["sitio"]):
            fallo(f"'{CLAVE}.sitio' debe ser un codigo de 1 a 40 caracteres de A-Z, a-z, 0-9, guion y guion bajo.")
        out["sitio"] = v["sitio"]
    if "as_of" in v:
        f = _a_utc(v["as_of"]) if isinstance(v["as_of"], str) else None
        if f is None:
            fallo(f"'{CLAVE}.as_of' debe ser una fecha ISO 8601 con Z u offset (p. ej. 2026-03-01T12:00:00Z).")
        out["as_of"] = f
    if "duenos" in v:
        lista = v["duenos"]
        if not isinstance(lista, list) or len(lista) > MAX_DUENOS:
            fallo(f"'{CLAVE}.duenos' debe ser una lista de 0 a {MAX_DUENOS} objetos {{red, dueno}}.")
        out["duenos"], vistas = [], set()
        for e in lista:
            e = objeto(e, f"{CLAVE}.duenos", ("red", "dueno"))
            if "red" not in e or "dueno" not in e:
                fallo(f"cada elemento de '{CLAVE}.duenos' necesita 'red' y 'dueno'.")
            try:
                red = ipaddress.ip_network(e["red"], strict=True) if isinstance(e["red"], str) else None
            except ValueError:
                red = None
            if red is None:
                fallo(f"'{CLAVE}.duenos': '{e['red']}' no es un CIDR valido.")
            dueno = _texto(e["dueno"], 1, MAX_TEXTO_DUENO)
            if dueno is None:
                fallo(f"'{CLAVE}.duenos.dueno' debe ser un texto de 1 a {MAX_TEXTO_DUENO} caracteres.")
            if red in vistas:
                fallo(f"'{CLAVE}.duenos': la red {red} esta repetida.")
            vistas.add(red)
            out["duenos"].append({"red": str(red), "dueno": dueno})
    if "politica_esperada" in v:
        lista = v["politica_esperada"]
        if not isinstance(lista, list) or len(lista) > MAX_POLITICAS:
            fallo(f"'{CLAVE}.politica_esperada' debe ser una lista de 0 a {MAX_POLITICAS} objetos "
                  "{origen, destino, politica}.")
        nombres = {z["nombre"] for z in zonas}
        out["politica_esperada"], vistos = [], set()
        for e in lista:
            e = objeto(e, f"{CLAVE}.politica_esperada", ("origen", "destino", "politica"))
            if not all(k in e for k in ("origen", "destino", "politica")):
                fallo(f"cada elemento de '{CLAVE}.politica_esperada' necesita 'origen', 'destino' y 'politica'.")
            for k in ("origen", "destino"):
                if not isinstance(e[k], str) or (e[k] != COMODIN and e[k] not in nombres):
                    fallo(f"'{CLAVE}.politica_esperada.{k}': '{e[k]}' no es una zona del perfil ni '*'.")
            politica = _texto(e["politica"], 1, MAX_TEXTO_POLITICA)
            if politica is None:
                fallo(f"'{CLAVE}.politica_esperada.politica' debe ser un texto de 1 a {MAX_TEXTO_POLITICA} "
                      "caracteres.")
            par = (e["origen"], e["destino"])
            if par in vistos:
                fallo(f"'{CLAVE}.politica_esperada': el par {par[0]} -> {par[1]} esta repetido.")
            vistos.add(par)
            out["politica_esperada"].append({"origen": par[0], "destino": par[1], "politica": politica})
    return out


def activa(res) -> bool:
    return CLAVE in (getattr(res, "perfil", None) or {})


# --------------------------------------------------------------------------- #
# Dominio
# --------------------------------------------------------------------------- #

def _por_purdue(nivel: str) -> str:
    """Dominio por nivel Purdue: 4 y 5 -> IT; 3.5 -> DMZ; 0 a 3 -> OT; un rango solo si ambos lados coinciden."""
    texto = str(nivel or "")
    if "dmz" in texto.lower():
        return "DMZ"
    clases = set()
    for n in _RE_NIVEL.findall(texto):
        clases.add("DMZ" if n == "3.5" else "IT" if n in ("4", "5") else "OT" if n in ("0", "1", "2", "3") else "")
    return next(iter(clases)) if len(clases) == 1 and "" not in clases else SIN_DATO


def _de_zona(zona: dict):
    """Dominio que declara una zona del perfil (o DMZ si es dmz); None si no declara ninguno."""
    return zona.get("dominio") or ("DMZ" if zona.get("dmz") else None)


def dominio_de(activo, perfil) -> str:
    """IT, OT, DMZ o 'sin dato' de un activo (con zona_asignada y purdue): el dominio de su zona si lo declara, DMZ si
    la zona es dmz; si no, por nivel Purdue."""
    activo = activo or {}
    nombre = activo.get("zona_asignada") or ""
    for z in (perfil or {}).get("zonas") or ():
        if z["nombre"] == nombre:
            d = _de_zona(z)
            if d:
                return d
            break
    return _por_purdue(activo.get("purdue", ""))


def _dominio_subred(red, zonas: list, doms_activos: list) -> str:
    """Dominio de una subred: el de la zona que la contiene si lo declara; si no, el de sus activos."""
    mejor = None
    for z in zonas:
        for r in z["redes"]:
            n = ipaddress.ip_network(r)
            if n.version == red.version and red.subnet_of(n) and (mejor is None or n.prefixlen > mejor[0]):
                mejor = (n.prefixlen, z)
    if mejor is not None and _de_zona(mejor[1]):
        return _de_zona(mejor[1])
    conocidos = {d for d in doms_activos if d != SIN_DATO}
    if not conocidos:
        return SIN_DATO
    return next(iter(conocidos)) if len(conocidos) == 1 else MIXTO


# --------------------------------------------------------------------------- #
# Calculo
# --------------------------------------------------------------------------- #

def _iso(ts) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime(FORMATO) if ts else ""


def _acumular(d: dict, k, ini, fin) -> None:
    a = d.setdefault(k, [None, None])
    if ini:
        a[0] = ini if a[0] is None else min(a[0], ini)
    if fin:
        a[1] = fin if a[1] is None else max(a[1], fin)


def _tiempos(caps) -> tuple:
    """({ip: [primero, ultimo]}, {(src, dst, l4, puerto): [primero, ultimo]}) desde los flujos de las capturas."""
    por_ip: dict = {}
    por_flujo: dict = {}
    for c in caps:
        if c.error:
            continue
        for f in c.flows.values():
            ini, fin = f.get("first"), f.get("last")
            _acumular(por_flujo, (f["src"], f["dst"], f["l4"], f["dport"]), ini, fin)
            _acumular(por_ip, f["src"], ini, fin)
            _acumular(por_ip, f["dst"], ini, fin)
    return por_ip, por_flujo


def _iso_plataforma(texto) -> str:
    """'YYYY-MM-DD HH:MM:SS' (ultima actividad que guarda el importador) -> ISO con Z; '' si no tiene esa forma."""
    m = re.match(r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})", str(texto or ""))
    return f"{m.group(1)}T{m.group(2)}Z" if m else ""


def _as_of(res, cfg: dict) -> str:
    if cfg.get("as_of"):
        return cfg["as_of"]
    if not res.caps:        # modo diagrama: la fecha y hora de la corrida
        return datetime.now(timezone.utc).strftime(FORMATO)
    caps = [c for c in res.caps if not c.error]
    fines = [c.ventana[1] for c in caps if len(c.ventana) == 2 and c.ventana[1]]
    fines += [f["last"] for c in caps for f in c.flows.values() if f.get("last")]
    return _iso(max(fines)) if fines else ""


def _politica(reglas: list):
    exacta = {(r["origen"], r["destino"]): r["politica"] for r in reglas}

    def de(o, d):
        for clave in ((o, d), (o, COMODIN), (COMODIN, d), (COMODIN, COMODIN)):
            if clave in exacta:
                return exacta[clave]
        return t(SIN_DECLARAR)
    return de


def _clave_ip(txt: str) -> tuple:
    try:
        x = ipaddress.ip_address(txt)
        return 0, x.version, int(x)
    except ValueError:
        return 1, 0, txt


def calcular(res) -> dict:
    """{'tablas': {archivo: (columnas, filas)}, 'matriz': filas, 'json': {...}}; filas ya traducidas."""
    perfil = res.perfil or {}
    cfg = perfil.get(CLAVE) or {}
    sitio = cfg.get("sitio") or perfil.get("sitio", "")
    as_of = _as_of(res, cfg)
    assets, conductos = res.assets, res.conduits
    por_ip: dict = {}
    for a in assets.values():
        for ip in a["ips"]:
            por_ip.setdefault(ip, a)
    dom_ip: dict = {}

    def dominio(ip):
        if ip not in dom_ip:
            dom_ip[ip] = dominio_de(por_ip.get(ip), perfil)
        return dom_ip[ip]

    from .trazabilidad import _ids_activo
    ids = _ids_activo(res)
    t_ip, t_flujo = _tiempos(res.caps)
    ip_de = _zc._ip_de(assets)
    tablas: dict = {}
    n_primera = 0

    # inventario_normalizado.csv
    inv = res.inventario_normalizado or {}
    filas = []
    for f in inv.get("filas", ()):
        ips = [i for i in str((f["campos"].get("ips") or {}).get("valor", "")).split(";") if i]
        activos = [por_ip[i] for i in ips if i in por_ip]
        ini = [t_ip[i][0] for i in ips if i in t_ip and t_ip[i][0]]
        fin = [t_ip[i][1] for i in ips if i in t_ip and t_ip[i][1]]
        primera = _iso(min(ini)) if ini else ""
        ultima = max([x for x in ([_iso(max(fin))] if fin else []) + [_iso_plataforma(a.get("ultima"))
                                                                      for a in activos] if x], default="")
        n_primera += bool(primera)
        filas.append([sitio, dominio_de(activos[0] if activos else None, perfil), primera, ultima, as_of])
    if filas:
        tablas["inventario_normalizado.csv"] = (COL_INVENTARIO, filas)

    # comunicaciones.csv
    from . import manifiesto as _mf
    man = getattr(res, "manifiesto", None)
    filas, cruzan = [], 0
    for k in conductos:
        s, d = str(ip_de(k.get("src"))), str(ip_de(k.get("dst")))
        tt = t_flujo.get((k["src"], k["dst"], k["l4"], k["port"])) or [None, None]
        ds = ""
        if _mf.hay(man):
            ds = ";".join(dict.fromkeys(x["dataset_id"] for x in man["filas"]
                                        if set(k.get("capturas") or ()) & set(x.get("archivos") or ())))
        ds_, dd_ = dominio(s), dominio(d)
        if SIN_DATO in (ds_, dd_):
            cruza = t(SIN_DATO)
        elif {ds_, dd_} == {"IT", "OT"}:
            cruza, cruzan = t("si"), cruzan + 1
        else:
            cruza = t("no")
        filas.append([ids.get(s, ""), ids.get(d, ""), _iso(tt[0]), _iso(tt[1]), ds,
                      t(ds_) if ds_ == SIN_DATO else ds_, t(dd_) if dd_ == SIN_DATO else dd_, cruza])
    if filas:
        tablas["comunicaciones.csv"] = (COL_COMUNICACIONES, filas)

    # direccionamiento_ip.csv
    dr = res.direccionamiento or {}
    zonas_perfil = perfil.get("zonas") or []
    duenos = sorted(((ipaddress.ip_network(x["red"]), x["dueno"]) for x in cfg.get("duenos", ())),
                    key=lambda x: -x[0].prefixlen)
    parseadas = []
    for ip, a in por_ip.items():
        try:
            parseadas.append((ipaddress.ip_address(ip), ip))
        except ValueError:
            continue
    filas, por_dominio = [], {}
    for f in dr.get("filas", ()):
        red = ipaddress.ip_network(f["red"])
        dueno = next((d for n, d in duenos if n.version == red.version and red.subnet_of(n)), "")
        doms = [dominio(ip) for x, ip in parseadas if x.version == red.version and x in red]
        dom = _dominio_subred(red, zonas_perfil, doms)
        por_dominio[dom] = por_dominio.get(dom, 0) + 1
        filas.append([sitio, t(dom) if dom in (SIN_DATO, MIXTO) else dom, dueno or t(PENDIENTE)])
    if filas:
        tablas["direccionamiento_ip.csv"] = (COL_DIRECCIONAMIENTO, filas)

    # fuentes_log.csv
    filas = []
    for x in (res.fuentes_log or {}).get("filas", ()):
        mios = set(x["ips"])
        dest, nb, npk = set(), 0, 0
        for k in conductos:
            if str(ip_de(k.get("src"))) in mios and (str(k.get("l4") or "").lower(), str(k["port"])) in PUERTOS_LOG:
                dest.add((str(ip_de(k.get("dst"))), str(k["port"])))
                nb, npk = nb + k["bytes"], npk + k["pkts"]
        filas.append([";".join(f"{ip}:{p}" for ip, p in sorted(dest, key=lambda y: (_clave_ip(y[0]), y[1]))),
                      nb, npk])
    if filas:
        tablas["fuentes_log.csv"] = (COL_FUENTES, filas)

    matriz, pares_obs = _matriz(res, por_ip, cfg)
    return {"tablas": tablas, "matriz": matriz,
            "json": {"sitio": sitio, "as_of": as_of,
                     "conteos": {"activos_con_primera_vez": n_primera, "flujos_cruzan_it_ot": cruzan,
                                 "subredes_por_dominio": dict(sorted(por_dominio.items())),
                                 "pares_observados": pares_obs},
                     "tablas": [*sorted(tablas), ARCHIVO_MATRIZ] if matriz else sorted(tablas)}}


def _matriz(res, por_ip: dict, cfg: dict) -> tuple:
    """(filas de matriz_segmentacion.csv, pares observados)."""
    zonas = [(z["zona"], z["origen"]) for z in (res.zonas or {}).get("filas", ())]
    nombres = {z for z, _o in zonas}
    for z in (res.perfil or {}).get("zonas") or ():
        if z["nombre"] not in nombres:
            zonas.append((z["nombre"], "perfil"))
            nombres.add(z["nombre"])
    ip_de = _zc._ip_de(res.assets)

    def zona_de(ip):
        a = por_ip.get(ip)
        if a is not None and a.get("zona_asignada"):
            return a["zona_asignada"]
        x = _zc._ip(ip)
        if x is not None and not (x.is_private or x.is_loopback or x.is_link_local or x.is_multicast
                                  or x.is_reserved or x.is_unspecified):
            return _zc.INTERNET
        return None

    obs: dict = {}
    for k in res.conduits:
        zo, zd = zona_de(str(ip_de(k.get("src")))), zona_de(str(ip_de(k.get("dst"))))
        if zo is None or zd is None:
            continue
        p = obs.setdefault((zo, zd), {"servicios": set(), "conductos": 0, "bytes": 0})
        p["servicios"].add(str(k["servicio"]))
        p["conductos"] += 1
        p["bytes"] += k["bytes"]
        for z in (zo, zd):
            if z not in nombres:
                zonas.append((z, "internet" if z == _zc.INTERNET else "sin zona"))
                nombres.add(z)
    if not zonas:
        return [], 0
    reglas = cfg.get("politica_esperada", ())
    politica = _politica(list(reglas))
    exactas = {(r["origen"], r["destino"]) for r in reglas if COMODIN not in (r["origen"], r["destino"])}
    if len(zonas) > MAX_ZONAS_MATRIZ and not getattr(res, "_cm_avisado", False):
        print(t("[!] campos_minimos: {n} zonas; la matriz de segmentacion solo lista los pares observados o con "
                "politica declarada", n=len(zonas)))
        res._cm_avisado = True
    todos = len(zonas) <= MAX_ZONAS_MATRIZ
    filas = []
    for zo, oo in zonas:
        for zd, od in zonas:
            if not todos and (zo, zd) not in obs and (zo, zd) not in exactas:
                continue
            p = obs.get((zo, zd))
            filas.append([mostrar_zona(zo, oo), mostrar_zona(zd, od), t("si") if p else t("no"),
                          ";".join(sorted(p["servicios"])) if p else "", p["conductos"] if p else 0,
                          p["bytes"] if p else 0, politica(zo, zd)])
    return filas, len(obs)


# --------------------------------------------------------------------------- #
# Salidas
# --------------------------------------------------------------------------- #

def ampliar(res, tablas: list) -> list:
    """Agrega las columnas al final de las tablas que cambian y la matriz de segmentacion; sin la clave, `tablas`."""
    if not activa(res):
        return tablas
    c = calcular(res)
    out = []
    for archivo, hoja, cab, filas in tablas:
        extra = c["tablas"].get(archivo)
        if extra and len(extra[1]) == len(filas):
            cab, filas = [*cab, *extra[0]], [[*f, *e] for f, e in zip(filas, extra[1])]
        out.append((archivo, hoja, cab, filas))
    if c["matriz"]:
        out.append((ARCHIVO_MATRIZ, HOJA_MATRIZ, COL_MATRIZ, c["matriz"]))
    return out


def para_json(res) -> dict:
    return calcular(res)["json"]
