"""T1a (D85): arquitectura TO-BE, lista de comunicaciones permitidas zona x zona.

Parte de los conductos entre zonas (Z1a/Z1b) y propone, por (zona origen, zona destino, servicio), una de cuatro
decisiones: permitir (restringido a los pares observados), pasar por una DMZ industrial, revisar o bloquear.
Metodo propio, sin revisar: es una propuesta a partir de lo observado que valida el cliente, no un diseno de
ingenieria y nunca un juicio de cumplimiento. No usa el firewall (si hay, solo el sentido real del conducto) y no
cambia M3a ni Z1b. Funciones puras sobre el modelo ya calculado.
"""
from __future__ import annotations

import collections
import re

from . import conductos_zcr as _zc
from .catalog import SEV_ORDER
from .firewalls import cruces as _cr
from .firewalls.validar_politica import PUERTO_DINAMICO_MIN
from .i18n import t
from .riesgo import id_hallazgo
from .zonas import mostrar_zona

SLUG = "diagrama_tobe"
TITULO = "Arquitectura TO-BE (segmentacion propuesta)"
TITULO_DIAGRAMA = "Segmentacion propuesta (TO-BE)"
ARCHIVO_ALLOW = "allowlist_tobe.csv"
HOJA_ALLOW = "Allowlist TO-BE"
ARCHIVO_MATRIZ = "matriz_tobe.csv"
HOJA_MATRIZ = "Matriz TO-BE"
COLUMNAS = ["id_conducto_zcr", "zona_origen", "zona_destino", "servicio", "decision", "motivo", "conductos",
            "activos_origen", "activos_destino", "dias", "ids_hallazgo", "estado_revision", "revisado_por", "fecha",
            "comentario"]
COL_MATRIZ = ["zona_origen", "zona_destino", "permitir", "por_dmz", "revisar", "bloquear"]
COL_SECCION = ["id_conducto_zcr", "zona_origen", "zona_destino", "servicio", "decision", "motivo"]

D_BLOQUEAR = "bloquear"
D_DMZ = "por DMZ"
D_REVISAR = "revisar"
D_PERMITIR = "permitir"
DECISIONES = [D_BLOQUEAR, D_DMZ, D_REVISAR, D_PERMITIR]
_CLAVE = {D_PERMITIR: "permitir", D_DMZ: "por_dmz", D_REVISAR: "revisar", D_BLOQUEAR: "bloquear"}
_LETRA = {D_PERMITIR: "P", D_DMZ: "D", D_REVISAR: "R", D_BLOQUEAR: "B"}

DMZ_PROPUESTA = "DMZ industrial (propuesta)"
MAX_ACTIVOS = 10
MAX_HALLAZGOS = 5
MAX_SECCION = 20
MAX_DIAGRAMA = 40
MAX_SERV_ETIQUETA = 3

M_INTERNET_ENTRA = "origen Internet hacia una zona interna"
M_DNS = "DNS a resolvers publicos desde una zona interna: usar DNS interno"
M_OT_SALE = "zona con equipos de nivel Purdue 0 a 2 hacia Internet"
M_SALTO = "salta niveles Purdue entre IT/empresa y control sin pasar por la DMZ; servicio intermedio sugerido: {s}"
M_RIESGO = "servicio de riesgo ({e})"
M_UN_DIA = "servicio visto un solo dia"
M_ALTO = "puerto alto sin protocolo de aplicacion"
M_SIN_PUERTO = "sin puerto (cualquier protocolo IP)"
M_PERMITIR ="restringido a los pares origen/destino observados"
S_SALTO = "servidor de salto en la DMZ con MFA"
S_HISTORIADOR = "replica del historiador en la DMZ"
S_PARCHES = "servidor de distribucion en la DMZ"
S_OTRO = "servicio intermedio en la DMZ"

NOTA = ("Propuesta a partir de lo observado; la valida el cliente; no es un diseno de ingenieria. Metodo propio, "
        "sin revisar: la primera regla que aplique decide. Bloquear: origen Internet hacia una zona interna, DNS a "
        "resolvers publicos desde una zona interna y zonas con equipos de nivel Purdue 0 a 2 hacia Internet. Por "
        "DMZ: conductos entre IT/empresa (nivel 4 o mas, o zona IT) y control (nivel 0 a 2) sin pasar por la DMZ. "
        "Revisar: servicios de riesgo, servicios vistos un solo dia y puertos altos sin protocolo de aplicacion. "
        "Permitir: el resto, restringido a los pares origen/destino observados. Para cada par de zonas se "
        "sobreentiende la ultima regla: denegar el resto con registro. Esto es evidencia tecnica, no una "
        "determinacion de cumplimiento.")
NOTA_RESP = "{n} conductos se tomaron como respuestas probables (puerto de cliente) y no generan fila."
TEXTO_VACIO = ("Sin comunicacion observada entre zonas distintas: el TO-BE necesita zonas (perfil `zonas` o "
               "inferidas) y conductos que las crucen.")
NOTA_DMZ = ("No hay una zona DMZ en el analisis (perfil con dmz: true o nombre con DMZ): se propone una, "
            "\"DMZ industrial (propuesta)\".")
NOTA_DIAGRAMA = "Propuesta a partir de lo observado; la valida el cliente; no es un diseno de ingenieria."
LEYENDA = "P = permitir, D = por DMZ, R = revisar, B = bloquear. Celda vacia: sin comunicacion observada, denegar."

# Puertos por defecto habituales y nombres de aplicacion, sin verificar con el fabricante: solo orientan el servicio
# intermedio sugerido.
# aplicacion -> puertos de servidor conocidos (reconoce respuestas hacia el puerto del cliente); ampliable
_SERVIDOR = tuple((re.compile(rx, re.IGNORECASE), frozenset(ps)) for rx, ps in (
    (r"\bmdns\b", (5353,)), (r"\bllmnr\b", (5355,)), (r"\bc?ldap\b", (389,)), (r"\bdns\b", (53,)),
    (r"\bntp\b", (123,)), (r"\bsnmp", (161,)), (r"\bdhcp|\bbootp", (67, 68)), (r"netbios|\bnbns\b|\bnbdgm\b", (137, 138)),
    (r"\bssdp\b", (1900,)), (r"\bsyslog\b", (514,)), (r"\btftp\b", (69,)), (r"\bkerberos\b", (88,))))
_PROCESO = {4840, 4843, 135, 5450, 5457, 5459}
_PARCHES = {8530, 8531}
_APP_PROCESO = re.compile(r"histor|osisoft|\bpi\b|\bopc\b|aveva|wonderware|proficy", re.IGNORECASE)
_APP_PARCHES = re.compile(r"wsus|update|patch|antivir|parche", re.IGNORECASE)
_ZONA_IT = re.compile(r"\b(it|ti|corp\w*|empresa\w*|enterprise)\b", re.IGNORECASE)
_FAMILIA = re.compile(r"acceso remoto|texto claro|\bdns\b|internet|conducto|zonas", re.IGNORECASE)


# --------------------------------------------------------------------------- #
# Calculo
# --------------------------------------------------------------------------- #


def _dmz_zonas(info: dict, perfil: dict | None) -> tuple:
    """(conjunto de zonas DMZ, nombre de la DMZ a usar o ''): `dmz: true` del perfil o nombre con DMZ."""
    declaradas = [z["nombre"] for z in (perfil or {}).get("zonas", ()) if z.get("dmz")]
    por_nombre = sorted(z for z in info if "dmz" in z.lower())
    todas = set(declaradas) | set(por_nombre)
    return todas, (declaradas or por_nombre or [""])[0]


def _niveles_zona(i: dict):
    ns = i.get("niveles") or []
    return (min(n[0] for n in ns), max(n[1] for n in ns)) if ns else None


def _servicio_intermedio(puerto, app: str, et: list) -> str:
    if _cr.ACCESO_REMOTO in et:
        return S_SALTO
    if puerto in _PROCESO or _APP_PROCESO.search(app or ""):
        return S_HISTORIADOR
    if puerto in _PARCHES or _APP_PARCHES.search(app or ""):
        return S_PARCHES
    return S_OTRO


def _lado(zona: str, ip: str, por_ip: dict, info: dict) -> tuple:
    """(bajo, alto) del extremo: nivel Purdue del activo o, sin el, el de su zona; o zona IT por su nombre."""
    a = por_ip.get(ip)
    n = _zc._niveles(a.get("purdue")) if a else None
    n = n or _niveles_zona(info.get(zona) or {})
    alto = bool(_ZONA_IT.search(zona)) or (n is not None and n[1] >= 4)
    return (n is not None and n[0] <= 2), alto


def construir(assets: dict, conductos: list, zonas: dict, zcr: dict, firewall: dict | None = None,
              hallazgos=(), perfil: dict | None = None) -> dict:
    """{'filas', 'matriz', 'zonas', 'dmz', 'dmz_propuesta', 'internos', 'info'}; vacio sin conductos entre zonas."""
    if not _zc.hay(zcr) or not conductos:
        return _vacio(0)
    info = zcr["zonas"]
    por_ip: dict = {}
    for a in assets.values():
        for ip in a["ips"]:
            por_ip.setdefault(ip, a)
    ip_de = _zc._ip_de(assets)
    fw = firewall or {}
    res_fw = fw.get("resultados") or []
    con_fw = "hostname" in fw and len(res_fw) == len(conductos)
    id_zcr = {frozenset((f["zona_a"], f["zona_b"])): f["id"] for f in zcr["filas"]}
    dmz_set, dmz_nombre = _dmz_zonas(info, perfil)

    def zona_de(ip):
        a = por_ip.get(ip)
        if a is not None and a.get("zona_asignada"):
            return a["zona_asignada"]
        x = _zc._ip(ip)
        if x is not None and not (x.is_private or x.is_loopback or x.is_link_local or x.is_multicast
                                  or x.is_reserved or x.is_unspecified):
            return _zc.INTERNET
        return None

    def es_internet(z):
        return z == _zc.INTERNET or (info.get(z) or {}).get("origen") == "internet"

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
        if r.get("resultado") == "respuesta":       # la respuesta de una sesion no es una comunicacion nueva
            continue
        s, d = str(ip_de(c.get("src"))), str(ip_de(c.get("dst")))
        if _respuesta_probable(c, s, d, puertos_par):
            probables += 1
            continue
        if r.get("sentido") == "invertido":
            s, d = d, s
        zs, zd = zona_de(s), zona_de(d)
        if zs is None or zd is None or zs == zd:
            continue
        puerto = _cr._puerto(c)
        l4 = str(c.get("l4") or "").strip().lower()
        servicio = str(c.get("servicio") or "")
        app = "" if servicio == "-" else servicio
        tipo = (por_ip.get(d) or {}).get("tipo", "")
        denegado = r.get("resultado") == "denegado_observado"
        k = (puerto, l4, app, _cr._global(d), _cr._global(s), tipo, denegado)
        if k not in cache_et:
            cache_et[k] = _cr.etiquetas_de(puerto, l4, app, d if k[3] else "", s if k[4] else "", tipo, denegado)
        et = cache_et[k]
        g = grupos.get((zs, zd, _zc._servicio(c)))
        if g is None:
            g = grupos[(zs, zd, _zc._servicio(c))] = {
                "n": 0, "o": set(), "d": set(), "dias": [], "et": set(), "alto": False, "dura": None,
                "sin_puerto": puerto is None}
        g["n"] += 1
        g["o"].add(s)
        g["d"].add(d)
        g["et"].update(et)
        g["alto"] = g["alto"] or _cr.ALTO in et
        if c.get("dias"):
            g["dias"].append(int(c["dias"]))
        dec = _regla_dura(zs, zd, s, d, et, puerto, app, por_ip, info, dmz_set, es_internet)
        if dec and (g["dura"] is None or DECISIONES.index(dec[0]) < DECISIONES.index(g["dura"][0])):
            g["dura"] = dec

    if not grupos:
        return _vacio(probables)
    familia = _hallazgos_familia(hallazgos)
    filas = []
    for (zs, zd, servicio), g in grupos.items():
        dec, motivo = g["dura"] or _blanda(g)
        ips = g["o"] | g["d"]
        filas.append({
            "id_conducto_zcr": id_zcr.get(frozenset((zs, zd)), ""), "zona_origen": zs, "zona_destino": zd,
            "origen_o": (info.get(zs) or _zc._SIN_INFO)["origen"], "origen_d": (info.get(zd) or _zc._SIN_INFO)["origen"],
            "servicio": servicio, "decision": dec, "motivo": motivo, "conductos": g["n"],
            "activos_origen": sorted(g["o"], key=_cr._orden_ip), "activos_destino": sorted(g["d"], key=_cr._orden_ip),
            "dias": max(g["dias"]) if g["dias"] else "", "ids_hallazgo": _ids(familia, ips)})
    filas.sort(key=lambda f: (DECISIONES.index(f["decision"]), f["zona_origen"], f["zona_destino"], f["servicio"]))
    hay_dmz = any(f["decision"] == D_DMZ for f in filas)
    propone = hay_dmz and not dmz_nombre
    dmz_final = dmz_nombre or (DMZ_PROPUESTA if propone else "")
    dmz_set = dmz_set | ({dmz_final} if dmz_final else set())
    celdas: dict = collections.OrderedDict()
    for f in filas:
        c = celdas.setdefault((f["zona_origen"], f["zona_destino"]), dict.fromkeys(_CLAVE.values(), 0))
        c[_CLAVE[f["decision"]]] += 1
    matriz = [dict(zona_origen=a, zona_destino=b, **v) for (a, b), v in sorted(celdas.items())]
    usadas = {z for f in filas for z in (f["zona_origen"], f["zona_destino"])}
    if hay_dmz:
        usadas.add(dmz_final)
    return {"filas": filas, "matriz": matriz, "zonas": sorted(usadas, key=lambda z: _orden_zona(z, info, dmz_set)),
            "dmz": dmz_final, "dmz_propuesta": propone,
            "internos": zcr.get("internos", 0), "info": info, "respuestas_probables": probables}


def _vacio(probables: int) -> dict:
    return {"filas": [], "vacio": True, "respuestas_probables": probables}


def _respuesta_probable(c: dict, s: str, d: str, puertos_par: dict) -> bool:
    """Conducto hacia un puerto de cliente, no una comunicacion nueva: mismo criterio de M5b (D67) mas la
    aplicacion identificada (a) o el puerto dinamico con el conducto inverso hacia un puerto de servidor (b)."""
    puerto = _cr._puerto(c)
    if puerto is None or puerto < 1024:
        return False
    servicio = str(c.get("servicio") or "")
    for rx, puertos in _SERVIDOR:
        if rx.search(servicio):
            return puerto not in puertos
    if puerto < PUERTO_DINAMICO_MIN:
        return False
    return any(p < PUERTO_DINAMICO_MIN for p in puertos_par.get((d, s), ()))


def _regla_dura(zs, zd, s, d, et, puerto, app, por_ip, info, dmz_set, es_internet):
    """Reglas 1 y 2 de un conducto: (decision, motivo) o None."""
    o_int, d_int = es_internet(zs), es_internet(zd)
    bajo_s, alto_s = _lado(zs, s, por_ip, info)
    bajo_d, alto_d = _lado(zd, d, por_ip, info)
    if o_int:
        return D_BLOQUEAR, (M_INTERNET_ENTRA, {})
    if _cr.DNS_EXT in et:
        return D_BLOQUEAR, (M_DNS, {})
    if d_int and bajo_s:
        return D_BLOQUEAR, (M_OT_SALE, {})
    if not d_int and zs not in dmz_set and zd not in dmz_set and ((bajo_s and alto_d) or (bajo_d and alto_s)):
        return D_DMZ, (M_SALTO, {"s": _servicio_intermedio(puerto, app, et)})
    return None


def _blanda(g: dict) -> tuple:
    """Regla 3 (revisar) o 4 (permitir) de un grupo de conductos."""
    riesgo = [e for e in g["et"] if e in (_cr.ACCESO_REMOTO, _cr.ARCHIVOS, _cr.ADMIN)
              or (e == _cr.CLARO and _cr.OT not in g["et"])]
    if riesgo:
        return D_REVISAR, (M_RIESGO, {"e": _cr._txt_et(_cr._ordenar(riesgo))})
    if g["dias"] and max(g["dias"]) == 1:
        return D_REVISAR, (M_UN_DIA, {})
    if g["alto"]:
        return D_REVISAR, (M_ALTO, {})
    if g["sin_puerto"]:          # la regla abriria cualquier protocolo IP entre esos equipos (como M3a)
        return D_REVISAR, (M_SIN_PUERTO, {})
    return D_PERMITIR, (M_PERMITIR, {})


def _hallazgos_familia(hallazgos) -> list:
    """Hallazgos de segmentacion/conductos (categoria o titulo): [(id, severidad, titulo, ips)]."""
    out = []
    for f in hallazgos:
        if f.get("categoria") == "Segmentacion" or _FAMILIA.search(f.get("titulo", "")):
            ips = set(f.get("activos") or _zc_ips(f.get("evidencia") or ""))
            if ips:
                out.append((f.get("id") or id_hallazgo(f["titulo"]), f.get("severidad", ""), f["titulo"], ips))
    return sorted(out, key=lambda x: (SEV_ORDER.get(x[1], 9), x[2]))


_IPV4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?!\d)")


def _zc_ips(texto: str) -> list:
    return _IPV4.findall(texto)


def _ids(familia: list, ips: set) -> list:
    out: list = []
    for hid, _sev, _tit, h_ips in familia:
        if hid not in out and h_ips & ips:
            out.append(hid)
    return out[:MAX_HALLAZGOS]


def _orden_zona(z: str, info: dict, dmz_set: set) -> tuple:
    """De arriba (Internet, empresa) a abajo (control); la DMZ queda entre ambas."""
    i = info.get(z) or _zc._SIN_INFO
    if i["origen"] == "internet":
        return (0, 0.0, z)
    if z in dmz_set:
        return (1, -3.5, z)
    n = _niveles_zona(i)
    if n is not None:
        return (1, -n[0], z)
    return (1, -4.0, z) if _ZONA_IT.search(z) else (2, 0.0, z)


# --------------------------------------------------------------------------- #
# Tablas
# --------------------------------------------------------------------------- #


def hay(tobe: dict) -> bool:
    return bool(tobe and tobe.get("filas"))


def nombre_zona(f: dict, lado: str) -> str:
    return mostrar_zona(f["zona_" + lado], f["origen_" + ("o" if lado == "origen" else "d")])


def _lista(ips: list) -> str:
    if len(ips) <= MAX_ACTIVOS:
        return ";".join(ips)
    return ";".join(ips[:MAX_ACTIVOS]) + t(" y {n} mas", n=len(ips) - MAX_ACTIVOS)


def _motivo(f: dict) -> str:
    clave, args = f["motivo"]
    args = {k: (t(v) if k == "s" else v) for k, v in args.items()}
    return t(clave, **args) if args else t(clave)


def fila_tabla(f: dict) -> list:
    return [f["id_conducto_zcr"], nombre_zona(f, "origen"), nombre_zona(f, "destino"), f["servicio"],
            t(f["decision"]), _motivo(f), f["conductos"], _lista(f["activos_origen"]), _lista(f["activos_destino"]),
            f["dias"], "; ".join(f["ids_hallazgo"]), "", "", "", ""]


def filas_tabla(tobe: dict) -> list:
    return [fila_tabla(f) for f in tobe["filas"]]


def filas_matriz(tobe: dict) -> list:
    info = tobe["info"]

    def n(z):
        return mostrar_zona(z, (info.get(z) or _zc._SIN_INFO)["origen"])
    return [[n(m["zona_origen"]), n(m["zona_destino"]), m["permitir"], m["por_dmz"], m["revisar"], m["bloquear"]]
            for m in tobe["matriz"]]


def tablas(tobe: dict) -> list:
    """[(archivo, hoja, cabecera, filas)] para el CSV y el XLSX."""
    if not hay(tobe):
        if tobe and tobe.get("allowlist_proyecto"):     # ALLOW1 (D133): solo los flujos declarados por el equipo
            from . import allowlist_proyecto as _ap
            return [(ARCHIVO_ALLOW, HOJA_ALLOW, *_ap.tabla(tobe, COLUMNAS, []))]
        return []
    cab, filas = COLUMNAS, filas_tabla(tobe)
    if tobe.get("allowlist_proyecto"):       # ALLOW1 (D133): columnas del proyecto al final
        from . import allowlist_proyecto as _ap
        cab, filas = _ap.tabla(tobe, COLUMNAS, filas)
    return [(ARCHIVO_ALLOW, HOJA_ALLOW, cab, filas),
            (ARCHIVO_MATRIZ, HOJA_MATRIZ, COL_MATRIZ, filas_matriz(tobe))]


def cuenta(tobe: dict) -> dict:
    c = collections.Counter(f["decision"] for f in tobe["filas"])
    return {d: c[d] for d in DECISIONES}


def _nombre_dmz(tobe: dict) -> str:
    return t(DMZ_PROPUESTA) if tobe["dmz_propuesta"] else tobe["dmz"]


def nota_texto(tobe: dict) -> str:
    txt = t(NOTA) + (" " + t(NOTA_DMZ) if tobe["dmz_propuesta"] else "")
    if tobe.get("respuestas_probables"):
        txt += " " + t(NOTA_RESP, n=tobe["respuestas_probables"])
    return txt


def hay_seccion(tobe: dict) -> bool:
    """La seccion sale con filas o, sin conductos entre zonas, con el texto de la seccion vacia."""
    return bool(tobe and (tobe.get("filas") or tobe.get("vacio")))


def seccion_vacia(tobe: dict) -> dict:
    nota = t(NOTA_RESP, n=tobe["respuestas_probables"]) if tobe.get("respuestas_probables") else ""
    return {"titulo": t(TITULO), "nota": nota, "texto": t(TEXTO_VACIO)}


def aviso(tobe: dict) -> str:
    """Linea de consola cuando el TO-BE queda vacio ("" si hay filas)."""
    return "[!] TO-BE: " + t(TEXTO_VACIO) if tobe and tobe.get("vacio") and not tobe.get("filas") else ""


def resumen_texto(tobe: dict) -> str:
    c = cuenta(tobe)
    txt = t("{n} comunicaciones entre zonas por servicio: permitir {p}, por DMZ {d}, revisar {r}, bloquear {b}. "
            "{i} conductos dentro de una misma zona no entran. Detalle en allowlist_tobe.csv.",
            n=len(tobe["filas"]), p=c[D_PERMITIR], d=c[D_DMZ], r=c[D_REVISAR], b=c[D_BLOQUEAR],
            i=tobe["internos"])
    if any(f["decision"] == D_DMZ for f in tobe["filas"]) and tobe["dmz"]:
        txt += " " + t("DMZ: {z}.", z=_nombre_dmz(tobe))
    if tobe.get("allowlist_proyecto"):       # ALLOW1 (D133)
        from . import allowlist_proyecto as _ap
        txt += " " + _ap.frase(tobe)
    return txt


def cuadricula(tobe: dict) -> tuple:
    """(cabecera, filas): zona origen en filas x zona destino en columnas; cada celda "P 3 · D 1 · R 2 · B 1"."""
    info = tobe["info"]
    celdas = {(m["zona_origen"], m["zona_destino"]): m for m in tobe["matriz"]}
    orig = [z for z in tobe["zonas"] if any(a == z for a, _b in celdas)]
    dest = [z for z in tobe["zonas"] if any(b == z for _a, b in celdas)]

    def n(z):
        return mostrar_zona(z, (info.get(z) or _zc._SIN_INFO)["origen"])

    def txt(m):
        return " · ".join(f"{_LETRA[d]} {m[_CLAVE[d]]}" for d in (D_PERMITIR, D_DMZ, D_REVISAR, D_BLOQUEAR)
                          if m[_CLAVE[d]])
    cab = [t("Origen \\ Destino")] + [n(z) for z in dest]
    filas = [[n(a)] + [txt(celdas[(a, b)]) if (a, b) in celdas else "" for b in dest] for a in orig]
    return cab, filas


def seccion(tobe: dict) -> dict:
    """Datos de la seccion de los reportes (todo traducido)."""
    cab_m, filas_m = cuadricula(tobe)
    destacadas = [f for f in tobe["filas"] if f["decision"] in (D_DMZ, D_BLOQUEAR)]
    mas = len(destacadas) - MAX_SECCION
    return {"titulo": t(TITULO), "nota": nota_texto(tobe), "resumen": resumen_texto(tobe), "leyenda": t(LEYENDA),
            "cab_matriz": cab_m, "matriz": filas_m, "cab": [t(c) for c in COL_SECCION],
            "filas": [[fila_tabla(f)[COLUMNAS.index(c)] for c in COL_SECCION] for f in destacadas[:MAX_SECCION]],
            "mas": t("Se muestran {n} filas por DMZ o a bloquear; {m} mas estan en allowlist_tobe.csv.",
                     n=MAX_SECCION, m=mas) if mas > 0 else "",
            "diagrama": t("Diagrama: diagrama_tobe.svg (tambien .mmd y .drawio).")}


def para_json(tobe: dict) -> dict:
    if not hay(tobe):
        if tobe and tobe.get("vacio"):
            return {"filas": [], "respuestas_probables": tobe["respuestas_probables"],
                    "nota": seccion_vacia(tobe)["texto"]}
        return {}
    filas = [dict(zip(COLUMNAS[:11], fila_tabla(f)[:11]), decision=f["decision"],
                  activos_origen=f["activos_origen"], activos_destino=f["activos_destino"],
                  ids_hallazgo=f["ids_hallazgo"]) for f in tobe["filas"]]
    out = {"filas": filas, "matriz": tobe["matriz"], "dmz": tobe["dmz"], "dmz_propuesta": tobe["dmz_propuesta"],
           "respuestas_probables": tobe["respuestas_probables"], "nota": nota_texto(tobe)}
    if tobe.get("allowlist_proyecto"):       # ALLOW1 (D133)
        from . import allowlist_proyecto as _ap
        out["allowlist_proyecto"] = _ap.para_json(tobe)
    return out


# --------------------------------------------------------------------------- #
# Diagrama
# --------------------------------------------------------------------------- #


def _aristas(tobe: dict) -> list:
    """[(origen, destino, servicio, via_dmz)] sin repetir: "por DMZ" son dos tramos origen -> DMZ -> destino."""
    dmz = tobe["dmz"]
    out: set = set()
    for f in tobe["filas"]:
        if f["decision"] == D_PERMITIR:
            out.add((f["zona_origen"], f["zona_destino"], f["servicio"], False))
        elif f["decision"] == D_DMZ and dmz:
            out.add((f["zona_origen"], dmz, f["servicio"], True))
            out.add((dmz, f["zona_destino"], f["servicio"], True))
    return sorted(out)


def _rotulo(servicios: list) -> str:
    return ", ".join(servicios[:MAX_SERV_ETIQUETA]) + (
        f" +{len(servicios) - MAX_SERV_ETIQUETA}" if len(servicios) > MAX_SERV_ETIQUETA else "")


def grafo(tobe: dict):
    """Grafo de zonas: una arista por par de zonas con los servicios permitidos o por DMZ; maximo MAX_DIAGRAMA."""
    from .diagram.graph import Arista, Grafo, Nodo

    info = tobe["info"]
    orden = {z: i for i, z in enumerate(tobe["zonas"])}
    pares: dict = {}
    for o, d, s, via in _aristas(tobe):
        a, b = sorted((o, d), key=lambda z: (orden.get(z, 99), z))
        p = pares.setdefault((a, b), {"fwd": False, "back": False, "directo": set(), "dmz": set()})
        p["fwd" if o == a else "back"] = True
        p["dmz" if via else "directo"].add(s)
    todas = sorted(pares.items(), key=lambda kv: (-len(kv[1]["directo"] | kv[1]["dmz"]), kv[0]))
    elegidas = todas[:MAX_DIAGRAMA]
    usadas = {z for (a, b), _p in elegidas for z in (a, b)}
    nodos = []
    for z in sorted(usadas, key=lambda z: (orden.get(z, 99), z)):
        i = info.get(z)
        if i is None:                                   # DMZ propuesta: no existe en el analisis
            nodos.append(Nodo(z, t(DMZ_PROPUESTA), t("propuesta"), z, "zona"))
            continue
        sub = t("{n} activos", n=i["activos"]) + ((" - " + t("SL-T {sl}", sl=i["sl_t"])) if i["sl_t"] else "")
        nodos.append(Nodo(z, mostrar_zona(z, i["origen"]), sub, z, "externo" if i["origen"] == "internet" else "zona"))
    aristas = []
    for (a, b), p in elegidas:
        todos = sorted(p["directo"] | p["dmz"])
        etiqueta = " + ".join(t(x) for x in ((D_PERMITIR,) if p["directo"] else ()) + ((D_DMZ,) if p["dmz"] else ()))
        det = [t("Servicios: {s}", s=", ".join(todos)), etiqueta]
        aristas.append(Arista(
            a, b, fwd=p["fwd"], back=p["back"], crit="Baja" if p["directo"] else "Media",
            servicios={s: 1 for s in todos}, conductos=len(todos), rotulo=_rotulo(todos), rotulo2=etiqueta,
            detalle="\n".join(det), discontinua=not p["directo"]))
    c = cuenta(tobe)
    leyenda = t("No se dibujan: {b} a bloquear y {r} a revisar (estan en allowlist_tobe.csv).",
                b=c[D_BLOQUEAR], r=c[D_REVISAR]) + "\n" + t(NOTA_DIAGRAMA)
    if tobe["dmz_propuesta"]:
        leyenda += " " + t("La DMZ es una propuesta: no existe en el analisis.")
    return Grafo(nodos, aristas, [n.id for n in nodos], zonas=True, tobe=leyenda,
                 aristas_omitidas=len(todas) - len(elegidas))


def nota_diagrama(tobe: dict) -> str:
    fuera = len(_pares_total(tobe)) - MAX_DIAGRAMA
    txt = t(NOTA_DIAGRAMA)
    if fuera > 0:
        txt += " " + t("Se dibujan las {n} aristas con mas servicios; {fuera} mas estan en allowlist_tobe.csv.",
                       n=MAX_DIAGRAMA, fuera=fuera)
    return txt


def _pares_total(tobe: dict) -> set:
    return {frozenset((o, d)) for o, d, _s, _v in _aristas(tobe)}
