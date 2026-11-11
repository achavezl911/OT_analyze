"""V1a (D89): vulnerabilidades candidatas por fabricante, modelo y firmware del inventario.

Sin red (D1). Compara el inventario normalizado (I1a) contra el `product_tree` de los avisos ICS de CISA en CSAF
(`--avisos-ics`, archivo o carpeta) y contra un catalogo del analista (`--catalogo-vulnerabilidades`, CSV o XLSX).
Entrega CANDIDATOS a confirmar con el aviso o el fabricante: nunca dice "vulnerable" ni "cumple / no cumple".
El cruce por CVE exacto contra el archivo de la plataforma sigue siendo de T6 (`avisos_cisa`, D66) y E1b.
Memoria acotada: solo se guardan los avisos cuyo fabricante case con algun fabricante del inventario.
"""
from __future__ import annotations

import functools
import json
import re
import unicodedata
from pathlib import Path

from . import cvss4
from .avisos_cisa import (
    _fecha,
    avisos_de_antiguedad,
    avisos_de_carga,
    cargar_avisos,
    cargar_kev,
    cvss4_de_vulnerabilidad,
    detalle_vulnerabilidad,
)
from .i18n import t
from .importers.lector import leer_tabla
from .rules.base import finding
from .vulnerabilidades import _CVE, _sev_de_cvss

E_AFECTADA, E_NC, E_SIN = "version afectada", "version no comparable: revisar", "sin firmware: posible"
ESTADOS = (E_AFECTADA, E_NC, E_SIN)
COINCIDENCIA = "modelo exacto"
COINCIDENCIA_FAMILIA = "familia (sin numero de modelo)"
_ORDEN_COINC = {COINCIDENCIA: 0, COINCIDENCIA_FAMILIA: 1}
TITULO_HALLAZGO = "Posibles vulnerabilidades conocidas por fabricante, modelo y firmware (a confirmar)"
TITULO = "Vulnerabilidades candidatas por fabricante, modelo y firmware"
ARCHIVO, HOJA = "vulnerabilidades_firmware.csv", "Vulnerabilidades por firmware"
NOTA = ("Cruce por texto de fabricante, modelo y firmware del inventario contra los avisos ICS locales y el "
        "catalogo del analista. Son candidatos a confirmar con el aviso o el fabricante: la herramienta no "
        "consulta la red y no concluye que un equipo sea vulnerable. Las columnas de revision estan vacias a "
        "proposito.")
COLUMNAS = ["activo", "ip", "fabricante", "modelo", "firmware", "procedencia", "cve", "cvss", "severidad", "cvss_v4",
            "vector_cvss_v4", "aviso", "producto_aviso", "version_afectada", "coincidencia", "estado", "kev", "en_plataforma", "remediacion",
            "fuente", "estado_revision", "revisado_por", "fecha", "comentario"]
NOTA_V4 = ("Severidad y orden por CVSS v4.0 segun el perfil; donde el aviso o el catalogo no trae v4, por v3 "
           "(columna cvss_decide).")
CAB_SECCION = ["activo", "fabricante", "modelo", "firmware", "cve", "cvss", "estado", "kev", "en_plataforma",
               "aviso"]
MAX_FILAS_SECCION = 30
TEXTO_VACIO = "Ningun activo tiene fabricante y modelo para cruzar"
ALIAS_COLUMNAS = {
    "fabricante": ("fabricante", "vendor", "manufacturer", "marca"),
    "producto": ("producto", "product", "modelo", "model"),
    "version_afectada": ("version_afectada", "versiones_afectadas", "version", "versiones", "affected_version",
                         "affected_versions"),
    "cve": ("cve", "cve_id"),
    "cvss": ("cvss", "cvss_score", "cvss_v3", "score"),
    "cvss_v4": ("cvss_v4", "cvss4", "cvss_v4_score", "cvss_v4_base_score"),
    "vector_cvss_v4": ("vector_cvss_v4", "cvss_v4_vector", "vector_v4"),
    "aviso": ("aviso", "advisory", "boletin", "id_aviso"),
    "remediacion": ("remediacion", "remediation", "mitigacion", "solucion"),
    "fuente": ("fuente", "source"),
}
REQUERIDAS = ("fabricante", "producto", "version_afectada")
_SUFIJOS = {"inc", "corp", "corporation", "co", "ltd", "llc", "gmbh", "ag", "sa", "plc"}
_GENERICAS = {"controller", "switch", "module", "device", "series", "software", "firmware", "system", "server",
              "gateway", "router", "processor", "family", "product", "interface", "station", "panel", "network",
              "communication", "communications", "adapter", "drive", "sensor", "relay", "meter", "console"}
_RE_NUM = re.compile(r"\d+")
_RE_OP = re.compile(r"(<=|>=|<|>|=)\s*[^\d<>=,;|]*?(\d+(?:[._-]\d+)*)")
_RE_EXACTA = re.compile(r"^(?:v|ver\.?|version|firmware|fw)?\s*(\d+(?:[._-]\d+)*)\s*[a-z]?$")
_RE_VERS = re.compile(r"^vers:([a-z0-9._+-]+)/(.*)$")
_TODAS = {"*", "all", "all versions", "todas", "todas las versiones", "any"}
_ORDEN_ESTADO = {e: i for i, e in enumerate(ESTADOS)}


# ---------------------------------------------------------------------------
# Fabricante

def _sin_acentos(s) -> str:
    s = unicodedata.normalize("NFKD", str(s or ""))
    return "".join(c for c in s if not unicodedata.combining(c)).lower()


def normalizar_nombre(s) -> str:
    """Minusculas, sin acentos ni puntuacion ni sufijos societarios (inc, corp, gmbh, s.a., ...)."""
    s = _sin_acentos(s).replace(".", "").replace("'", "")
    toks = re.sub(r"[^a-z0-9]+", " ", s).split()
    return " ".join([x for x in toks if x not in _SUFIJOS] or toks)


@functools.lru_cache(maxsize=1)
def _grupos() -> tuple:
    """({nombre normalizado: clave del grupo}, {clave: [nombres normalizados]}) de data/fabricantes_alias.json."""
    d = json.loads((Path(__file__).parent / "data" / "fabricantes_alias.json").read_text(encoding="utf-8"))
    por_nombre, por_clave = {}, {}
    for g in d["grupos"]:
        nombres = [normalizar_nombre(x) for x in g]
        por_clave[nombres[0]] = nombres
        for n in nombres:
            por_nombre.setdefault(n, nombres[0])
    return por_nombre, por_clave


def clave_fabricante(nombre) -> str:
    n = normalizar_nombre(nombre)
    return _grupos()[0].get(n, n)


_RE_PARENS = re.compile(r"\(([^()]*)\)")
_RE_PARTES = re.compile(r"\s+and\s+|\s+&\s+|/", re.IGNORECASE)   # "B&R" y "M&M" no se parten


def claves_fabricante(nombre, _prof=0) -> frozenset:
    """Claves de un nombre de aviso: la de hoy, la del nombre sin lo que va entre parentesis, la de lo de dentro
    y la de cada parte separada por 'and', ' & ' o '/' (recursivo; cada clave pasa por los grupos de alias).
    Sin claves de una letra."""
    texto = str(nombre or "")
    claves = {clave_fabricante(texto)}
    if _prof < 4:
        sin = _RE_PARENS.sub(" ", texto)
        partes = [sin] + _RE_PARENS.findall(texto) + _RE_PARTES.split(sin)
        for x in partes:
            if x.strip() and x != texto:
                claves |= claves_fabricante(x, _prof + 1)
    return frozenset(c for c in claves if len(c) > 1)


def _nombres_de(clave: str) -> list:
    return _grupos()[1].get(clave, [clave])


# ---------------------------------------------------------------------------
# Producto contra modelo

def _tokens(texto, quitar=()) -> list:
    toks = re.sub(r"[^a-z0-9]+", " ", _sin_acentos(texto)).split()
    for frase in sorted((f.split() for f in quitar if f), key=len, reverse=True):
        n = len(frase)
        i, out = 0, []
        while i < len(toks):
            if toks[i:i + n] == frase:
                i += n
            else:
                out.append(toks[i])
                i += 1
        if out:
            toks = out
    return toks


def _significativo(toks) -> bool:
    """Algun token con digito, o de 5 letras o mas que no sea una palabra generica (controller, switch...)."""
    return any(any(c.isdigit() for c in x) or (len(x) >= 5 and x.isalpha() and x not in _GENERICAS) for x in toks)


def _contiene(largo: list, corto: list) -> bool:
    n = len(corto)
    return n > 0 and any(largo[i:i + n] == corto for i in range(len(largo) - n + 1))


# Palabras que acompanan al nombre de un producto en un aviso sin cambiar de producto ("CPU family",
# "Industrial Distribution Switches"). Cualquier otra palabra extra ("TM MFP", "Software Controller", "CPU 1511-1 PN")
# nombra una variante que el modelo del inventario no confirma.
_DESCRIPTIVAS = {"family", "series", "cpu", "cpus", "controller", "controllers", "plc", "plcs", "switch", "switches",
                 "industrial", "distribution", "managed", "ethernet", "module", "modules", "device", "devices",
                 "product", "products", "model", "models", "variant", "variants", "and", "all", "incl", "including",
                 "related", "line", "versions", "familia", "serie", "modulo", "modulos", "equipo", "equipos"}
_RE_PARENTESIS = re.compile(r"\([^)]*\)")


def _posicion(largo: list, corto: list) -> int:
    n = len(corto)
    return next((i for i in range(len(largo) - n + 1) if largo[i:i + n] == corto), -1)


_RE_DENTRO_PARENTESIS = re.compile(r"\(([^)]*)\)")


def _compacto(texto) -> str:
    return re.sub(r"[^a-z0-9]+", "", _sin_acentos(texto))


def _pedido_exacto(producto, modelo) -> bool:
    """El modelo del inventario (numero de pedido o variante, p. ej. el MLFB de S7) es un elemento completo del aviso:
    el producto entero o uno de sus parentesis ("... CPU 1511-1 PN (6ES7511-1AK02-0AB0)"); espacios y guiones no
    cuentan (6ES7 511-... = 6ES7511-...). Solo con 8 caracteres o mas, con letras y digitos."""
    m = _compacto(modelo)
    if len(m) < 8 or not re.search(r"[0-9]", m) or not re.search(r"[a-z]", m):
        return False
    texto = str(producto or "")
    partes = [texto] + [p for x in _RE_DENTRO_PARENTESIS.findall(texto) for p in re.split(r"[,;]", x)]
    return any(_compacto(p) == m for p in partes)


def _dentro_del_catalogo(producto, modelo) -> bool:
    """El producto del aviso, compactado, esta dentro del modelo del inventario compactado (numero de catalogo:
    "cpe330" dentro de "ic695cpe330abaf"). Solo con 5 caracteres o mas, con letras y digitos, y sin partir una cifra ("plc500" no esta en "plc5000")."""
    p = _compacto(producto)
    if len(p) < 5 or not re.search(r"[0-9]", p) or not re.search(r"[a-z]", p):
        return False
    antes, despues = ("(?<![0-9])" if p[0].isdigit() else ""), ("(?![0-9])" if p[-1].isdigit() else "")
    return bool(re.search(antes + re.escape(p) + despues, _compacto(modelo)))


def nivel_producto(producto, modelo, quitar=()) -> str:
    """'modelo exacto', 'familia (sin numero de modelo)' o '' (no casa).

    Exacto: nombres iguales; o el producto del aviso completo dentro del modelo del inventario (el activo es al menos
    tan especifico); o el modelo dentro de un nombre de producto mas largo cuyas palabras extra (sin lo que va entre
    parentesis) solo describen ("CPU family"). Familia: el modelo esta dentro de un producto que nombra una variante
    ("S7-1500" dentro de "S7-1500 CPU 1511-1 PN" o "S7-1500 TM MFP"): se lista, no cuenta para el hallazgo."""
    a, b = _tokens(producto, quitar), _tokens(modelo, quitar)
    if not a or not b:
        return ""
    if a == b or _pedido_exacto(producto, modelo) or _dentro_del_catalogo(producto, modelo):
        return COINCIDENCIA
    if len(a) < len(b):
        return COINCIDENCIA if _contiene(b, a) and _significativo(a) else ""
    if not (_contiene(a, b) and _significativo(b)):
        return ""
    limpio = _tokens(_RE_PARENTESIS.sub(" ", str(producto or "")), quitar)
    i = _posicion(limpio, b)
    if i < 0:
        return COINCIDENCIA_FAMILIA
    extra = limpio[:i] + limpio[i + len(b):]
    return COINCIDENCIA if all(x in _DESCRIPTIVAS for x in extra) else COINCIDENCIA_FAMILIA


def producto_casa(producto, modelo, quitar=()) -> bool:
    return bool(nivel_producto(producto, modelo, quitar))


# ---------------------------------------------------------------------------
# Version

def _tupla(s):
    g = _RE_NUM.findall(str(s or ""))
    return tuple(int(x) for x in g) or None


_RE_VER_PUNTO = re.compile(r"(?<![A-Za-z0-9.])v?(\d+(?:\.\d+)+)", re.IGNORECASE)


def _tupla_fw(s):
    """Firmware del inventario: el primer token con forma de version con punto; si no hay, todos los numeros."""
    m = _RE_VER_PUNTO.search(str(s or ""))
    return _tupla(m.group(1)) if m else _tupla(s)


_RE_FORMA_VERSION = re.compile(r"\d+\.\d+|[<>=*]|^vers:")
_RE_PREFIJO_VERSION = re.compile(r"^(?:v|ver|rev|r|sv|fw|sp|version|revision|firmware|build)[ ._-]*\d", re.IGNORECASE)
_RE_PALABRA_RANGO = re.compile(
    r"^(?:prior|before|earlier|below|through|thru|up|all|any|from|after|older|newer|until)\b", re.IGNORECASE)


def modelo_en_version(producto, version) -> tuple:
    """(producto, version): una 'version' que empieza con letra, tiene digitos y no tiene forma de version (ni
    punto numerico, ni rango, ni prefijo Rev/R/SV/V) es un modelo ('W744-1'): se une al producto y no hay version."""
    v = str(version or "").strip()
    if (v and v[0].isalpha() and re.search(r"\d", v) and not _RE_FORMA_VERSION.search(v)
            and not _RE_PREFIJO_VERSION.match(v) and not _RE_PALABRA_RANGO.match(v)):
        return (str(producto or "") + " " + v).strip(), ""
    return producto, version


def _cmp(a: tuple, b: tuple) -> int:
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def _cumple(op: str, fw: tuple, ref: tuple) -> bool:
    c = _cmp(fw, ref)
    return {"<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0, "=": c == 0, "!=": c != 0}[op]


def es_todas(expr) -> bool:
    e = " ".join(str(expr or "").lower().split())
    return e in _TODAS or e == "vers:all/*"


def _evaluar_vers(rest: str, fw: tuple):
    cs = []
    for x in rest.split("|"):
        m = re.match(r"^(<=|>=|!=|<|>|=)?(.*)$", x.strip())
        ref = _tupla(m.group(2))
        if ref is None:
            return "nc"
        cs.append((m.group(1) or "=", ref))
    i = 0
    while i < len(cs):
        op, ref = cs[i]
        if op == "!=":
            if _cumple("=", fw, ref):
                return "no"
        elif op in (">", ">=") and i + 1 < len(cs) and cs[i + 1][0] in ("<", "<="):
            if _cumple(op, fw, ref) and _cumple(cs[i + 1][0], fw, cs[i + 1][1]):
                return "si"
            i += 1
        elif _cumple(op, fw, ref):
            return "si"
        i += 1
    return "no"


def evaluar(expr, firmware) -> str:
    """'si' (dentro del rango), 'no' (fuera) o 'nc' (sin numeros comparables) para un firmware y una expresion."""
    if es_todas(expr):
        return "si"
    e = " ".join(str(expr or "").split())
    fw = _tupla_fw(firmware)
    if not e or fw is None:
        return "nc"
    m = _RE_VERS.match(e.lower())
    if m:
        return "si" if m.group(2).strip() == "*" else _evaluar_vers(m.group(2), fw)
    ops = _RE_OP.findall(e)
    if ops:
        return "si" if all(_cumple(op, fw, _tupla(v)) for op, v in ops) else "no"
    partes = [_RE_EXACTA.match(x.strip()) for x in e.lower().split("|")]     # "5.5|5.0|5.1": cualquiera
    if not all(partes):
        return "nc"
    return "si" if any(_cmp(fw, _tupla(m.group(1))) == 0 for m in partes) else "no"


# ---------------------------------------------------------------------------
# Indice CSAF y catalogo del analista

def _recorrer(ramas, vendor, producto, version, out, prof=0):
    for b in ramas or ():
        if not isinstance(b, dict) or prof > 30:
            continue
        cat, nombre = b.get("category"), str(b.get("name") or "")
        v, p, ver = vendor, producto, version
        if cat == "vendor":
            v = nombre
        elif cat == "product_name":
            p = nombre
        elif cat == "product_family":
            p = p or nombre
        elif cat in ("product_version", "product_version_range"):
            ver = nombre
        prod = b.get("product")
        if isinstance(prod, dict) and prod.get("product_id") and v:
            out[str(prod["product_id"])] = (v, p or str(prod.get("name") or ""), ver)
        _recorrer(b.get("branches"), v, p, ver, out, prof + 1)


def productos_csaf(datos: dict) -> dict:
    """{product_id: (fabricante, producto, version)} del product_tree: ramas y relationships."""
    arbol = datos.get("product_tree")
    out: dict = {}
    if not isinstance(arbol, dict):
        return out
    _recorrer(arbol.get("branches"), "", "", "", out)
    for r in arbol.get("relationships") or ():
        if not isinstance(r, dict):
            continue
        pid = (r.get("full_product_name") or {}).get("product_id") if isinstance(r.get("full_product_name"),
                                                                                    dict) else None
        ref = str(r.get("product_reference") or "")
        if pid and ref in out:
            out[str(pid)] = out[ref]
    return out


def _grupos_csaf(datos: dict) -> dict:
    arbol = datos.get("product_tree")
    g = arbol.get("product_groups") if isinstance(arbol, dict) else None
    return {str(x["group_id"]): [str(i) for i in x.get("product_ids") or ()]
            for x in g or () if isinstance(x, dict) and x.get("group_id")}


def _alias_columnas(encabezados) -> dict:
    claves = {re.sub(r"[\s-]+", "_", _sin_acentos(h).strip()): h for h in encabezados}
    return {campo: next((claves[a] for a in alias if a in claves), None) for campo, alias in ALIAS_COLUMNAS.items()}


class Indice:
    """Registros de producto afectado por fabricante (solo los fabricantes del inventario)."""

    def __init__(self, vendores: set):
        self.vendores = vendores
        self.por_fabricante: dict = {}
        self.catalogo = None            # {"archivo", "filas", "descartadas"}
        self.avisos_leidos = 0
        self.avisos_con_fabricante = 0
        self.ultimo = ""

    def _agregar(self, clave: str, reg: dict) -> None:
        self.por_fabricante.setdefault(clave, []).append(reg)

    def visitar(self, datos, ruta: str) -> None:
        """Visitante para avisos_cisa.cargar_avisos: indexa un aviso CSAF ya leido."""
        doc = datos.get("document") if isinstance(datos, dict) else None
        seg = doc.get("tracking") if isinstance(doc, dict) else None
        if not isinstance(seg, dict) or not seg.get("id"):
            return
        self.avisos_leidos += 1
        fecha = str(seg.get("current_release_date") or "")[:10]
        if _fecha(fecha) and fecha > self.ultimo:
            self.ultimo = fecha
        productos = {k: v for k, v in productos_csaf(datos).items() if claves_fabricante(v[0]) & self.vendores}
        if not productos:
            return
        self.avisos_con_fabricante += 1
        grupos = _grupos_csaf(datos)

        def ids(estado, v):
            out = set()
            for i in (v.get("product_status") or {}).get(estado) or ():
                out.update(grupos.get(str(i), [str(i)]))
            return out
        for v in datos.get("vulnerabilities") or ():
            cve = str(v.get("cve") or "").strip().upper() if isinstance(v, dict) else ""
            if not _CVE.match(cve):
                continue
            afectados = ids("known_affected", v) - ids("fixed", v) - ids("known_not_affected", v)
            cvss, _cats, extracto = detalle_vulnerabilidad(v)
            cvss_v4, vector_v4 = cvss4_de_vulnerabilidad(v)
            for pid in sorted(afectados & set(productos)):
                fab, prod, ver = productos[pid]
                prod, ver = modelo_en_version(prod, ver)
                for clave in sorted(claves_fabricante(fab) & self.vendores):
                    self._agregar(clave, {
                        "producto": prod, "version": ver, "cve": cve, "cvss": cvss, "aviso": str(seg["id"]),
                        "cvss_v4": cvss_v4, "vector_cvss_v4": vector_v4, "remediacion": extracto, "fuente": ruta})

    def cargar_catalogo(self, ruta) -> list:
        """Lee el catalogo del analista; devuelve los avisos de consola. SystemExit si faltan columnas."""
        p = Path(ruta)
        filas = leer_tabla(p)
        cols = _alias_columnas(filas[0].keys()) if filas else {}
        faltan = [c for c in REQUERIDAS if not cols.get(c)]
        if not filas or faltan:
            raise SystemExit(f"[!] '{p.name}': el catalogo de vulnerabilidades necesita las columnas "
                             f"{', '.join(REQUERIDAS)} y cve" + (f" (faltan: {', '.join(faltan)})" if faltan else ""))
        if not cols.get("cve"):
            raise SystemExit(f"[!] '{p.name}': el catalogo de vulnerabilidades necesita la columna cve")
        descartadas = 0

        def dato(f, campo):
            return str(f.get(cols[campo]) or "").strip() if cols.get(campo) else ""
        for f in filas:
            cve = dato(f, "cve").upper()
            if not _CVE.match(cve) or not dato(f, "fabricante") or not dato(f, "producto"):
                descartadas += 1
                continue
            try:
                cvss = float(dato(f, "cvss").replace(",", "."))
            except ValueError:
                cvss = None
            clave = clave_fabricante(dato(f, "fabricante"))
            if clave not in self.vendores:
                continue
            cvss_v4, vector_v4 = cvss4.resolver(dato(f, "cvss_v4"), dato(f, "vector_cvss_v4"))
            fuente = p.name + (f" ({dato(f, 'fuente')})" if dato(f, "fuente") else "")
            self._agregar(clave, {"producto": dato(f, "producto"), "version": dato(f, "version_afectada"),
                                  "cve": cve, "cvss": cvss, "aviso": dato(f, "aviso"),
                                  "cvss_v4": cvss_v4, "vector_cvss_v4": vector_v4,
                                  "remediacion": dato(f, "remediacion"), "fuente": fuente})
        self.catalogo = {"archivo": p.name, "filas": len(filas) - descartadas, "descartadas": descartadas}
        return ([(f"--catalogo-vulnerabilidades: {descartadas} filas sin CVE valido, fabricante o producto "
                  "se ignoran")] if descartadas else [])


def fabricantes_de(registros) -> set:
    """Claves de fabricante de los registros del inventario (antes de consolidar)."""
    return {clave_fabricante(v) for r in registros for campo, v, *_ in r["entradas"] if campo == "fabricante" and v}


def de_args(args, registros):
    """Indice vacio si se dio --avisos-ics o --catalogo-vulnerabilidades; None si no (V1a no corre)."""
    if not (getattr(args, "avisos_ics", None) or getattr(args, "catalogo_vulnerabilidades", None)):
        return None
    ind = Indice(fabricantes_de(registros))
    if getattr(args, "catalogo_vulnerabilidades", None):
        for adv in ind.cargar_catalogo(args.catalogo_vulnerabilidades):
            print(f"[!] {adv}")
    return ind


def completar(ind: Indice, args, kev=None, av=None, leyo_avisos: bool = False, hoy=None) -> tuple:
    """Lee lo que T6 no leyo (sin --vulnerabilidades): avisos y KEV. Devuelve (kev, avisos).

    Con --vulnerabilidades, `preparar` ya leyo la carpeta una sola vez con el visitante del indice."""
    if not leyo_avisos and getattr(args, "avisos_ics", None):
        av = cargar_avisos(args.avisos_ics, set(), ind.visitar)
        args.avisos_entrada = av["entrada"]
        for adv in avisos_de_carga(av):
            print(f"[!] {adv}")
    if kev is None and getattr(args, "kev", None):
        kev = cargar_kev(args.kev)
        args.kev_entrada = kev["entrada"]
    if not leyo_avisos:
        for adv in avisos_de_antiguedad(kev, av, hoy):
            print(f"[!] {adv}")
    return kev, av


# ---------------------------------------------------------------------------
# Cruce

def _ips_en_plataforma(cruces, assets) -> dict:
    """{cve: {ip}} de las vulnerabilidades que ya llegan asociadas a un activo por --vulnerabilidades."""
    out: dict = {}
    for c in cruces or ():
        if c.get("activo") is None:
            continue
        ips = set((assets.get(c["activo"]) or {}).get("ips") or ())
        if c["vuln"].get("ip"):
            ips.add(c["vuln"]["ip"])
        out.setdefault(c["vuln"]["cve"], set()).update(ips)
    return out


def _efectiva(r: dict, v4: bool) -> tuple:
    """(puntuacion, version que decide) del registro: con v4 (D114) cvss_v4 si existe, si no v3."""
    if v4 and r.get("cvss_v4") is not None:
        return r["cvss_v4"], "4.0"
    if r["cvss"] is not None:
        return r["cvss"], "3.x"
    return None, ""


def _sev_de(punt, dec: str) -> str:
    if punt is None:
        return ""
    return t(cvss4.severidad(punt) if dec == "4.0" else _sev_de_cvss(punt))


def construir(ind: Indice, inv: dict, cruces=None, assets=None, kev=None, av=None, version_cvss: str = "3") -> dict:
    """Candidatas por activo y CVE del inventario normalizado `inv` contra el indice.

    version_cvss "4" (D114): severidad, orden y umbral por CVSS v4.0 con caida a v3; agrega la columna cvss_decide."""
    v4 = version_cvss == "4"
    plat = _ips_en_plataforma(cruces, assets or {})
    con_modelo = con_fw = 0
    mejores: dict = {}
    vistos_fuera: set = set()
    for fila in (inv or {}).get("filas", ()):
        c = fila["campos"]

        def val(k, c=c):
            return c[k]["valor"] if k in c else ""

        def fte(k, c=c):
            return c[k]["fuente"] if k in c else ""
        fab, modelo, fw = val("fabricante"), val("modelo"), val("firmware")
        if not fab or not modelo:
            continue
        con_modelo += 1
        con_fw += bool(fw)
        clave = clave_fabricante(fab)
        ips = [i for i in val("ips").split(";") if i]
        for r in ind.por_fabricante.get(clave, ()):
            coinc = nivel_producto(r["producto"], modelo, _nombres_de(clave) + [normalizar_nombre(fab)])
            if not coinc:
                continue
            ev = "si" if es_todas(r["version"]) else evaluar(r["version"], fw) if fw else "sin"
            llave = (fila["id"], r["cve"])
            if ev == "no":
                vistos_fuera.add(llave)
                continue
            estado = E_AFECTADA if ev == "si" else E_NC if ev == "nc" else E_SIN
            clasif = (_ORDEN_ESTADO[estado], _ORDEN_COINC[coinc], -(_efectiva(r, v4)[0] if _efectiva(r, v4)[0] is not None else -1), r["aviso"])
            if llave in mejores and mejores[llave][0] <= clasif:
                continue
            mejores[llave] = (clasif, {
                "id": fila["id"], "nombre": val("nombre") or val("ips"), "ips": ips, "fab": fab, "modelo": modelo,
                "fw": fw, "procedencia": t("modelo: {m}; firmware: {f}", m=fte("modelo"), f=fte("firmware") or "-"),
                "reg": r, "estado": estado, "coinc": coinc,
                "en_plat": bool(set(ips) & plat.get(r["cve"], set()))})
    fuera = len(vistos_fuera - set(mejores))
    kev_cves = kev["por_cve"] if kev else None
    filas = []
    for _clasif, x in mejores.values():
        r = x["reg"]
        en_kev = bool(kev_cves is not None and r["cve"] in kev_cves)
        ef, dec = _efectiva(r, v4)
        x.update(cve=r["cve"], cvss=r["cvss"], kev=en_kev, cvss_ef=ef, cvss_dec=dec)
        sev = _sev_de(ef, dec) if v4 else (t(_sev_de_cvss(r["cvss"])) if r["cvss"] is not None else "")
        x["celdas"] = [x["nombre"], ";".join(x["ips"]), x["fab"], x["modelo"], x["fw"], x["procedencia"], r["cve"],
                       "" if r["cvss"] is None else r["cvss"], sev,
                       "" if r.get("cvss_v4") is None else r["cvss_v4"], r.get("vector_cvss_v4") or "", *([dec] if v4 else []),
                       r["aviso"], r["producto"], r["version"],
                       t(x["coinc"]), t(x["estado"]),
                       "" if kev_cves is None else t("si" if en_kev else "no"),
                       t("si" if x["en_plat"] else "no"), r["remediacion"], r["fuente"], "", "", "", ""]
        filas.append(x)
    filas.sort(key=lambda x: (_ORDEN_ESTADO[x["estado"]], _ORDEN_COINC[x["coinc"]], -(x["cvss_ef"] if x["cvss_ef"] is not None else -1),
                              x["nombre"], x["cve"]))
    por_estado = {e: sum(1 for x in filas if x["estado"] == e) for e in ESTADOS}
    resumen = {"activos_con_fabricante_y_modelo": con_modelo, "activos_con_firmware": con_fw,
               "avisos_leidos": ind.avisos_leidos, "avisos_con_fabricante_del_inventario": ind.avisos_con_fabricante,
               "filas_catalogo": ind.catalogo["filas"] if ind.catalogo else 0,
               "filas": len(filas), "por_estado": por_estado, "firmware_fuera_de_rango": fuera,
               "revision_mas_reciente": av["ultimo"] if av else ind.ultimo, "kev": bool(kev)}
    cols = [*COLUMNAS[:COLUMNAS.index("vector_cvss_v4") + 1], *(["cvss_decide"] if v4 else []),
            *COLUMNAS[COLUMNAS.index("vector_cvss_v4") + 1:]]
    return {"filas": filas, "resumen": resumen, "columnas": cols, "version_cvss": "4" if v4 else "3"}


# ---------------------------------------------------------------------------
# Hallazgo y salidas

def _candidatas(vf: dict) -> list:
    """Solo 'version afectada' con modelo exacto y que no este ya en la plataforma; la familia solo se lista."""
    return [x for x in vf["filas"] if x["estado"] == E_AFECTADA and x["coinc"] == COINCIDENCIA and not x["en_plat"]]


def agregar_hallazgo(cap, vf: dict) -> None:
    """Un hallazgo: version afectada y no presente ya en la plataforma. Alta si KEV o CVSS >= 9.0, si no Media."""
    cand = _candidatas(vf) if vf else []
    if not cand:
        return
    alta = any(x["kev"] or (x["cvss_ef"] is not None and x["cvss_ef"] >= 9.0) for x in cand)
    por_cve: dict = {}
    for x in cand:
        por_cve.setdefault(x["cve"], []).append(x)
    v4 = vf.get("version_cvss") == "4"
    top = sorted(por_cve, key=lambda c: (-max((x["cvss_ef"] if x["cvss_ef"] is not None else -1) for x in por_cve[c]), c))
    lineas = []
    for cve in top[:5]:
        xs = por_cve[cve]
        con = [x for x in xs if x["cvss_ef"] is not None]
        mejor = max(con, key=lambda x: x["cvss_ef"]) if con else None
        cvss = mejor["cvss_ef"] if mejor else None
        nombres = sorted({x["nombre"] for x in xs})
        plantilla = ("{cve} (CVSS v4.0 {c}; {a})" if mejor["cvss_dec"] == "4.0" else "{cve} (CVSS v3 {c}; {a})") \
            if v4 and mejor else "{cve} (CVSS {c}; {a})"
        lineas.append(t(plantilla, cve=cve, c="-" if cvss is None else cvss,
                        a=", ".join(nombres[:3]) + (f" (+{len(nombres) - 3})" if len(nombres) > 3 else "")))
    activos = sorted({x["id"] for x in cand})
    ev = t("Cruce por texto contra los avisos locales y el catalogo del analista; candidatos a confirmar con el "
           "aviso o el fabricante. Filas con version afectada que no estan ya en la plataforma: {n}, en {a} "
           "activos. Mayor CVSS: {lineas}. Detalle en vulnerabilidades_firmware.csv.",
           n=len(cand), a=len(activos), lineas="; ".join(lineas))
    finding(cap, "Alta" if alta else "Media", TITULO_HALLAZGO, ev,
            "El fabricante, el modelo y el firmware de un activo coinciden con un producto afectado en un aviso "
            "o en el catalogo del analista; si se confirma, el equipo tiene una falla publicada en una red de "
            "control.",
            "Confirmar con el aviso del fabricante que el modelo y la version del activo son los afectados y "
            "revisar su remediacion; aplicar el parche o la mitigacion en la ventana acordada con operacion y, "
            "mientras tanto, restringir los conductos que alcanzan al activo.",
            "Vulnerabilidades", activos=[ip for x in cand for ip in x["ips"]])


def hay(vf: dict) -> bool:
    return bool(vf and vf.get("resumen") is not None)


def tablas(vf: dict) -> list:
    if not hay(vf) or not vf["filas"]:
        return []
    return [(ARCHIVO, HOJA, vf.get("columnas", COLUMNAS), [x["celdas"] for x in vf["filas"]])]


def _texto_resumen(r: dict) -> str:
    pe = r["por_estado"]
    ult = r["revision_mas_reciente"]
    return t("Activos con fabricante y modelo: {a}; con firmware: {f}. Avisos CSAF leidos: {v} ({vf} con "
             "fabricante del inventario); filas del catalogo del analista: {c}. Filas: {x} {e1}, {y} {e2}, "
             "{z} {e3}. Firmware fuera de rango (no listado): {w}.{u}",
             a=r["activos_con_fabricante_y_modelo"], f=r["activos_con_firmware"], v=r["avisos_leidos"],
             vf=r["avisos_con_fabricante_del_inventario"], c=r["filas_catalogo"], x=pe[E_AFECTADA],
             y=pe[E_NC], z=pe[E_SIN], e1=t(E_AFECTADA), e2=t(E_NC), e3=t(E_SIN),
             w=r["firmware_fuera_de_rango"],
             u=" " + t("Revision mas reciente de los avisos leidos: {f}.", f=ult) if ult else "")


def seccion(vf: dict) -> dict:
    r = vf["resumen"]
    v4 = vf.get("version_cvss") == "4"
    todas = vf.get("columnas", COLUMNAS)
    cols = [todas.index(c) for c in CAB_SECCION]
    ic = CAB_SECCION.index("cvss")
    filas = [[x["celdas"][i] for i in cols] for x in vf["filas"][:MAX_FILAS_SECCION]]
    if v4:      # D114: la seccion muestra la puntuacion que decidio
        for f, x in zip(filas, vf["filas"]):
            f[ic] = "" if x["cvss_ef"] is None else x["cvss_ef"]
    mas = len(vf["filas"]) - len(filas)
    vacio = "" if r["activos_con_fabricante_y_modelo"] else t(TEXTO_VACIO)
    return {"titulo": t(TITULO), "nota": t(NOTA) + (" " + t(NOTA_V4) if v4 else ""), "resumen": _texto_resumen(r),
            "tabla": ([t(c) for c in CAB_SECCION], filas),
            "mas": t("Se muestran {n} filas; {m} mas estan en vulnerabilidades_firmware.csv.",
                     n=len(filas), m=mas) if mas > 0 else "",
            "vacio": vacio}


def para_json(vf: dict) -> dict:
    if not hay(vf):
        return {}
    return {"nota": t(NOTA), "resumen": vf["resumen"],
            "filas": [dict(zip(vf.get("columnas", COLUMNAS), x["celdas"])) for x in vf["filas"]]}
