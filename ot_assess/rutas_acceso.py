"""RUTA1 (D134): inventario de rutas de acceso a OT: usadas, configuradas y declaradas por el cliente.

Cruza tres fuentes que la herramienta ya tiene por separado: lo usado (conductos cuyo servicio es de acceso remoto o
administracion y cruzan de zona, mas las herramientas de terceros de T8), lo configurado (lo que el firewall permitio
de esos conductos) y lo declarado (las rutas autorizadas que el proyecto escribe en la clave de perfil
`rutas_acceso`). Marca lo usado y no declarado. Es evidencia tecnica de lo observado: no dictamina cumplimiento ni
enumera reglas del firewall sin trafico. Sin la clave de perfil no hace nada. Funciones puras sobre el modelo ya
calculado.
"""
from __future__ import annotations

import collections
import datetime
import hashlib
import ipaddress
import re

from . import conductos_zcr as _zc
from . import tobe as _tb
from .firewalls import cruces as _cr
from .i18n import t, unir
from .indicadores import D_DESCARTADO, D_INTERNET, M_PUERTO
from .zonas import SIN_ZONA, mostrar_zona

CLAVE = "rutas_acceso"
ARCHIVO = "rutas_acceso.csv"
HOJA = "Rutas de acceso"
TITULO = "Rutas de acceso a OT"
COLUMNAS = ["id_ruta", "zona_origen", "zona_destino", "servicio", "herramienta", "activos_origen",
            "activos_destino", "conductos", "dias", "usada", "configurada", "regla", "declarada", "via", "proveedor",
            "autorizado_por", "vigencia", "clasificacion"]
COL_SECCION = ["id_ruta", "zona_origen", "zona_destino", "servicio", "herramienta", "usada", "configurada",
               "declarada", "clasificacion"]

C_USADA_SIN = "usada sin declarar"
C_DECL_USADA = "declarada y usada"
C_DECL_SIN_USO = "declarada sin uso observado"
CLASES = [C_USADA_SIN, C_DECL_USADA, C_DECL_SIN_USO]
VENCIDA = "vigencia vencida"
CFG_SI, CFG_NO, CFG_SIN_FW, CFG_NA = "si", "no", "sin firewall", "-"

TIT_SIN_DECLARAR = "Rutas de acceso a OT usadas sin declarar"
TIT_VENCIDA = "Rutas de acceso a OT declaradas con vigencia vencida"

MAX_SERVICIOS = 50
MAX_DECLARADAS = 200
MAX_ID = 30
MAX_TEXTO = 200
MAX_ACTIVOS = 10
MAX_SECCION = 20
MAX_LINEAS = 10
MAX_REGLAS = 5

NOTA = ("Evidencia tecnica de lo observado en la ventana de captura o de la exportacion, no un dictamen de "
        "cumplimiento. Usada: servicio de acceso remoto o administracion visto entre zonas distintas (o desde "
        "Internet), o una herramienta de acceso remoto de terceros. Configurada: si el firewall cargado permitio "
        "algun conducto de la ruta. Declarada: la ruta coincide con una ruta autorizada que declara el proyecto "
        "(origen y destino dentro de la zona o red declarada y el mismo servicio); no se listan las reglas del "
        "firewall que permitirian acceso sin trafico observado.")
TEXTO_SIN_DECLARAR = ("{n} rutas de acceso a OT se usaron sin estar declaradas por el proyecto: confirmar con el "
                      "cliente si estan autorizadas.")

_SERVICIO = re.compile(r"(tcp|udp)/(\d{1,5})")
_DIRECCION = re.compile(r"[0-9a-fA-F:.]*[.:][0-9a-fA-F:.]*(/\d{1,3})?")
_FECHA = re.compile(r"\d{4}-\d{2}-\d{2}")
_OPCIONALES = ("via", "proveedor", "autorizado_por", "vigencia")


# --------------------------------------------------------------------------- #
# Perfil
# --------------------------------------------------------------------------- #


def _servicio_valido(s) -> bool:
    m = _SERVICIO.fullmatch(s) if isinstance(s, str) else None
    return bool(m) and 0 < int(m.group(2)) < 65536


def _lado_valido(v, donde: str, fallo) -> str:
    if not isinstance(v, str) or not v.strip() or len(v) > MAX_TEXTO:
        fallo(f"'{donde}' debe ser un texto de 1 a {MAX_TEXTO} caracteres (zona, CIDR o IP).")
    v = v.strip()
    if _DIRECCION.fullmatch(v):
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            fallo(f"'{donde}': '{v}' no es una IP ni una red valida.")
    return v


def validar(v, fallo, objeto) -> dict:
    """Normaliza la clave de perfil `rutas_acceso` ({} vale)."""
    v = objeto(v, CLAVE, ("servicios", "declaradas"))
    out: dict = {"servicios": [], "declaradas": []}
    if "servicios" in v:
        s = v["servicios"]
        if not isinstance(s, list) or not 1 <= len(s) <= MAX_SERVICIOS:
            fallo(f"'{CLAVE}.servicios' debe ser una lista de 1 a {MAX_SERVICIOS} servicios proto/puerto.")
        for x in s:
            if not _servicio_valido(x):
                fallo(f"'{CLAVE}.servicios': '{x}' no es proto/puerto (por ejemplo tcp/22 o udp/500).")
        out["servicios"] = list(dict.fromkeys(s))
    d = v.get("declaradas", [])
    if not isinstance(d, list) or len(d) > MAX_DECLARADAS:
        fallo(f"'{CLAVE}.declaradas' debe ser una lista de 0 a {MAX_DECLARADAS} rutas.")
    vistos: set = set()
    for i, r in enumerate(d):
        donde = f"{CLAVE}.declaradas[{i}]"
        r = objeto(r, donde, ("id", "origen", "destino", "servicio", *_OPCIONALES))
        for k in ("id", "origen", "destino", "servicio"):
            if k not in r:
                fallo(f"falta '{k}' en '{donde}'.")
        ident = r["id"]
        if not isinstance(ident, str) or not 1 <= len(ident.strip()) <= MAX_ID:
            fallo(f"'{donde}.id' debe ser un texto de 1 a {MAX_ID} caracteres.")
        ident = ident.strip()
        if ident in vistos:
            fallo(f"'{donde}.id': '{ident}' esta repetido.")
        vistos.add(ident)
        n = {"id": ident, "origen": _lado_valido(r["origen"], donde + ".origen", fallo),
             "destino": _lado_valido(r["destino"], donde + ".destino", fallo)}
        if r["servicio"] != "*" and not _servicio_valido(r["servicio"]):
            fallo(f"'{donde}.servicio': '{r['servicio']}' no es proto/puerto (tcp/3389) ni \"*\".")
        n["servicio"] = r["servicio"]
        for k in _OPCIONALES:
            x = r.get(k, "")
            if not isinstance(x, str) or len(x) > MAX_TEXTO:
                fallo(f"'{donde}.{k}' debe ser un texto de hasta {MAX_TEXTO} caracteres.")
            n[k] = x.strip()
        if n["vigencia"]:
            if not _FECHA.fullmatch(n["vigencia"]):
                fallo(f"'{donde}.vigencia': '{n['vigencia']}' no es una fecha AAAA-MM-DD.")
            try:
                datetime.date.fromisoformat(n["vigencia"])
            except ValueError:
                fallo(f"'{donde}.vigencia': '{n['vigencia']}' no es una fecha valida.")
        out["declaradas"].append(n)
    return out


# --------------------------------------------------------------------------- #
# Calculo
# --------------------------------------------------------------------------- #


def id_ruta(zona_origen: str, zona_destino: str, servicio: str) -> str:
    h = hashlib.sha256(f"{zona_origen}|{zona_destino}|{servicio}".encode()).hexdigest()
    return "RA-" + h[:8]


def _puertos_lista(servicios: list) -> set:
    return {(m.group(1), int(m.group(2))) for m in map(_SERVICIO.fullmatch, servicios)}


def _cuenta(lista, l4: str, puerto, et: list) -> bool:
    """El conducto es un servicio de acceso: de la lista del perfil o, sin ella, por las etiquetas de cruces."""
    if lista is None:
        return _cr.ACCESO_REMOTO in et or _cr.ADMIN in et
    if puerto is None:
        return False
    return (l4, puerto) in lista if l4 else any(p == puerto for _l, p in lista)


def _red_o_zona(texto: str):
    if _DIRECCION.fullmatch(texto):
        return ipaddress.ip_network(texto, strict=False)
    return None


def _cae(texto: str, zona: str, ips: list) -> bool:
    red = _red_o_zona(texto)
    if red is None:
        return texto == zona
    try:
        return bool(ips) and all(ipaddress.ip_address(i) in red for i in ips)
    except ValueError:
        return False


def _serv_igual(declarado: str, servicio: str) -> bool:
    if declarado == "*" or declarado == servicio:
        return True
    return "/" not in servicio and declarado.split("/")[-1] == servicio     # exportaciones sin transporte


def _grupo() -> dict:
    return {"n": 0, "o": set(), "d": set(), "dias": [], "et": set(), "herr": set(), "perm": 0, "den": 0,
            "reglas": set()}


def construir(assets: dict, conductos: list, zcr: dict, firewall: dict | None, perfil: dict | None,
              indicadores=(), hoy: datetime.date | None = None) -> dict:
    """{'filas', 'declaradas', 'info', 'respuestas_probables', 'servicios'}; {} sin la clave de perfil."""
    cfg = (perfil or {}).get(CLAVE)
    if cfg is None:
        return {}
    info = (zcr or {}).get("zonas") or {}
    lista = _puertos_lista(cfg["servicios"]) if cfg.get("servicios") else None
    por_ip: dict = {}
    for a in assets.values():
        for ip in a["ips"]:
            por_ip.setdefault(ip, a)
    ip_de = _zc._ip_de(assets)
    fw = firewall or {}
    res_fw = fw.get("resultados") or []
    con_fw = "hostname" in fw and len(res_fw) == len(conductos)

    def zona_de(ip):
        a = por_ip.get(ip)
        if a is not None and a.get("zona_asignada"):
            return a["zona_asignada"]
        x = _zc._ip(ip)
        if x is not None and not (x.is_private or x.is_loopback or x.is_link_local or x.is_multicast
                                  or x.is_reserved or x.is_unspecified):
            return _zc.INTERNET
        return SIN_ZONA

    puertos_par: dict = {}
    for c in conductos:
        p = _cr._puerto(c)
        if p is not None:
            puertos_par.setdefault((str(ip_de(c.get("src"))), str(ip_de(c.get("dst")))), set()).add(p)
    grupos: dict = {}
    cache_et: dict = {}
    probables = 0
    for i, c in enumerate(conductos):
        r = res_fw[i] if con_fw else {}
        if r.get("resultado") == "respuesta":
            continue
        s, d = str(ip_de(c.get("src"))), str(ip_de(c.get("dst")))
        if _tb._respuesta_probable(c, s, d, puertos_par):
            probables += 1
            continue
        if r.get("sentido") == "invertido":
            s, d = d, s
        zs, zd = zona_de(s), zona_de(d)
        if zs == zd:
            continue
        puerto = _cr._puerto(c)
        l4 = str(c.get("l4") or "").strip().lower()
        servicio = str(c.get("servicio") or "")
        app = "" if servicio == "-" else servicio
        denegado = r.get("resultado") == "denegado_observado"
        et: list = []
        if lista is None:
            tipo = (por_ip.get(d) or {}).get("tipo", "")
            k = (puerto, l4, app, _cr._global(d), _cr._global(s), tipo, denegado)
            if k not in cache_et:
                cache_et[k] = _cr.etiquetas_de(puerto, l4, app, d if k[3] else "", s if k[4] else "", tipo, denegado)
            et = cache_et[k]
        if not _cuenta(lista, l4, puerto, et):
            continue
        g = grupos.setdefault((zs, zd, _zc._servicio(c)), _grupo())
        g["n"] += 1
        g["o"].add(s)
        g["d"].add(d)
        if c.get("dias"):
            g["dias"].append(int(c["dias"]))
        if con_fw:
            if r.get("resultado") == "permitido":
                g["perm"] += 1
                regla = ((r.get("regla") or "") + (" " + r["regla_nombre"] if r.get("regla_nombre") else "")).strip()
                if regla:
                    g["reglas"].add(regla)
            elif denegado:
                g["den"] += 1
    for x in indicadores:       # T8: cada herramienta de terceros es una ruta usada
        if x.get("estado") == D_DESCARTADO or not x.get("ip"):
            continue
        destinos = [i for i in str(x.get("destino_ip") or "").split(";") if i]
        zs = zona_de(x["ip"])
        zd = zona_de(destinos[0]) if destinos else (_zc.INTERNET if x.get("destino") == D_INTERNET else SIN_ZONA)
        if zs == zd:
            continue
        servicio = x["indicador"] if x.get("metodo") == M_PUERTO else "-"
        existe = (zs, zd, servicio) in grupos
        g = grupos.setdefault((zs, zd, servicio), _grupo())
        g["herr"].add(x["herramienta"])
        g["o"].add(x["ip"])
        g["d"].update(destinos)
        if not (existe and x.get("metodo") == M_PUERTO):        # el conducto del puerto ya cuenta
            g["n"] += int(x.get("conductos") or 0)
    filas = []
    for (zs, zd, servicio), g in grupos.items():
        if g["n"] and con_fw and g["perm"]:
            cfg_fw = CFG_SI
        elif g["n"] and con_fw and g["den"]:
            cfg_fw = CFG_NO
        else:
            cfg_fw = CFG_SIN_FW
        filas.append({
            "id": id_ruta(zs, zd, servicio), "zona_origen": zs, "zona_destino": zd,
            "origen_o": _origen(zs, info), "origen_d": _origen(zd, info), "servicio": servicio,
            "herramienta": sorted(g["herr"]), "activos_origen": sorted(g["o"], key=_cr._orden_ip),
            "activos_destino": sorted(g["d"], key=_cr._orden_ip), "conductos": g["n"],
            "dias": max(g["dias"]) if g["dias"] else "", "usada": True, "configurada": cfg_fw,
            "regla": "; ".join(sorted(g["reglas"])[:MAX_REGLAS]) if cfg_fw == CFG_SI else "",
            "declaradas": [], "vencida": False})
    _declarar(filas, cfg["declaradas"], hoy or datetime.date.today(), info)
    orden = {c: i for i, c in enumerate(CLASES)}
    filas.sort(key=lambda f: (orden[f["clase"]], f["zona_origen"], f["zona_destino"], f["servicio"], f["id"]))
    return {"filas": filas, "declaradas": len(cfg["declaradas"]), "info": info,
            "respuestas_probables": probables, "personalizado": lista is not None}


def _origen(zona: str, info: dict) -> str:
    return "sin zona" if zona == SIN_ZONA else (info.get(zona) or _zc._SIN_INFO)["origen"]


def _declarar(filas: list, declaradas: list, hoy: datetime.date, info: dict) -> None:
    """Marca cada ruta usada con las declaradas que la cubren y agrega las declaradas sin uso."""
    iso = hoy.isoformat()
    usadas: set = set()
    for f in filas:
        for d in declaradas:
            if (_serv_igual(d["servicio"], f["servicio"]) and _cae(d["origen"], f["zona_origen"], f["activos_origen"])
                    and _cae(d["destino"], f["zona_destino"], f["activos_destino"])):
                f["declaradas"].append(d)
                usadas.add(d["id"])
        f["clase"] = C_DECL_USADA if f["declaradas"] else C_USADA_SIN
        f["vencida"] = any(d["vigencia"] and d["vigencia"] < iso for d in f["declaradas"])
    for d in declaradas:
        if d["id"] in usadas:
            continue
        filas.append({
            "id": d["id"], "zona_origen": d["origen"], "zona_destino": d["destino"], "origen_o": "", "origen_d": "",
            "servicio": d["servicio"], "herramienta": [], "activos_origen": [], "activos_destino": [],
            "conductos": 0, "dias": "", "usada": False, "configurada": CFG_NA, "regla": "", "declaradas": [d],
            "vencida": bool(d["vigencia"] and d["vigencia"] < iso), "clase": C_DECL_SIN_USO})


# --------------------------------------------------------------------------- #
# Tablas y secciones
# --------------------------------------------------------------------------- #


def hay(ra: dict) -> bool:
    return bool(ra and ra.get("filas"))


def _unicos(f: dict, k: str) -> str:
    return "; ".join(dict.fromkeys(d[k] for d in f["declaradas"] if d[k]))


def _lista(ips: list) -> str:
    if len(ips) <= MAX_ACTIVOS:
        return ";".join(ips)
    return ";".join(ips[:MAX_ACTIVOS]) + t(" y {n} mas", n=len(ips) - MAX_ACTIVOS)


def _clase(f: dict) -> str:
    return t(f["clase"]) + ("; " + t(VENCIDA) if f["vencida"] else "")


def _cfg(f: dict) -> str:
    return CFG_NA if f["configurada"] == CFG_NA else t(f["configurada"])


def fila_tabla(f: dict) -> list:
    return [f["id"], mostrar_zona(f["zona_origen"], f["origen_o"]), mostrar_zona(f["zona_destino"], f["origen_d"]),
            f["servicio"], "; ".join(f["herramienta"]), _lista(f["activos_origen"]), _lista(f["activos_destino"]),
            f["conductos"], f["dias"], t(CFG_SI if f["usada"] else CFG_NO), _cfg(f), f["regla"],
            _unicos(f, "id"), _unicos(f, "via"), _unicos(f, "proveedor"), _unicos(f, "autorizado_por"),
            _unicos(f, "vigencia"), _clase(f)]


def tablas(ra: dict) -> list:
    """[(archivo, hoja, cabecera, filas)] para el CSV y el XLSX."""
    if not hay(ra):
        return []
    return [(ARCHIVO, HOJA, COLUMNAS, [fila_tabla(f) for f in ra["filas"]])]


def cuenta(ra: dict) -> dict:
    c = collections.Counter(f["clase"] for f in ra["filas"])
    out = {k: c[k] for k in CLASES}
    out[VENCIDA] = sum(1 for f in ra["filas"] if f["vencida"])
    return out


def resumen_texto(ra: dict) -> str:
    c = cuenta(ra)
    txt = t("{n} rutas de acceso: {u} usadas sin declarar, {a} declaradas y usadas, {s} declaradas sin uso "
            "observado. Detalle en rutas_acceso.csv.", n=len(ra["filas"]), u=c[C_USADA_SIN], a=c[C_DECL_USADA],
            s=c[C_DECL_SIN_USO])
    if c[VENCIDA]:
        txt += " " + t("{n} con vigencia vencida.", n=c[VENCIDA])
    return txt


def seccion(ra: dict) -> dict:
    """Datos de la seccion de los reportes (todo traducido)."""
    mas = len(ra["filas"]) - MAX_SECCION
    nota = t(NOTA)
    if ra.get("respuestas_probables"):
        nota += " " + t(_tb.NOTA_RESP, n=ra["respuestas_probables"])
    ix = [COLUMNAS.index(c) for c in COL_SECCION]
    return {"titulo": t(TITULO), "nota": nota, "resumen": resumen_texto(ra), "cab": [t(c) for c in COL_SECCION],
            "filas": [[fila_tabla(f)[i] for i in ix] for f in ra["filas"][:MAX_SECCION]],
            "mas": t("Se muestran {n} filas; {m} mas estan en rutas_acceso.csv.", n=MAX_SECCION, m=mas)
            if mas > 0 else ""}


def para_json(ra: dict) -> dict:
    if not hay(ra):
        return {}
    filas = []
    for f in ra["filas"]:
        fila = dict(zip(COLUMNAS, fila_tabla(f)))
        fila.update(clasificacion=f["clase"], vigencia_vencida=f["vencida"], usada=f["usada"],
                    configurada=f["configurada"], herramienta=f["herramienta"],
                    activos_origen=f["activos_origen"], activos_destino=f["activos_destino"])
        filas.append(fila)
    return {"conteos": cuenta(ra), "declaradas": ra["declaradas"], "respuestas_probables": ra["respuestas_probables"],
            "filas": filas, "nota": t(NOTA)}


# --------------------------------------------------------------------------- #
# Hallazgos
# --------------------------------------------------------------------------- #


def _linea(f: dict) -> str:
    herr = f" ({'; '.join(f['herramienta'])})" if f["herramienta"] else ""
    return t("{o} -> {d} {s}{h}: {n} conductos, firewall: {c}", o=mostrar_zona(f["zona_origen"], f["origen_o"]),
             d=mostrar_zona(f["zona_destino"], f["origen_d"]), s=f["servicio"], h=herr, n=f["conductos"],
             c=_cfg(f))


def agregar_hallazgos(cap, ra: dict) -> None:
    """Hallazgos de las rutas en 'cap' (un Capture de extras). Marcas para el equipo, no cumplimiento."""
    from .rules.base import finding

    if not hay(ra):
        return
    sin = [f for f in ra["filas"] if f["clase"] == C_USADA_SIN]
    if sin:
        lineas = [_linea(f) for f in sin[:MAX_LINEAS]]
        if len(sin) > MAX_LINEAS:
            lineas.append(t(" y {n} mas", n=len(sin) - MAX_LINEAS))
        finding(cap, "Media", TIT_SIN_DECLARAR,
                unir("\n", [t(TEXTO_SIN_DECLARAR, n=len(sin))] + lineas),
                "Una ruta de acceso remoto o administrativo que se usa y nadie declaro puede ser acceso de un "
                "proveedor sin autorizacion vigente o una puerta que nadie vigila.",
                "Confirmar con el cliente quien usa cada ruta y quien la autoriza; declararla en el perfil o "
                "cerrarla en el firewall y llevar el acceso de terceros a un punto controlado con MFA.",
                "Segmentacion", activos=[i for f in sin for i in (*f["activos_origen"], *f["activos_destino"])])
    venc = [f for f in ra["filas"] if f["vencida"]]
    if venc:
        lineas = [t("{i}: vigencia {v}", i=f["id"], v=_unicos(f, "vigencia")) for f in venc[:MAX_LINEAS]]
        if len(venc) > MAX_LINEAS:
            lineas.append(t(" y {n} mas", n=len(venc) - MAX_LINEAS))
        finding(cap, "Baja", TIT_VENCIDA,
                unir("\n", [t("{n} rutas declaradas tienen la vigencia vencida a la fecha de la corrida.",
                               n=len(venc))] + lineas),
                "Un acceso autorizado con la vigencia vencida deja de estar respaldado por la autorizacion del "
                "cliente aunque siga abierto.",
                "Renovar la autorizacion o retirar el acceso y cerrar la ruta en el firewall.", "Segmentacion",
                activos=[i for f in venc for i in (*f["activos_origen"], *f["activos_destino"])])
