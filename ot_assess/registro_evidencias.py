"""EVID2 (D127): registro de evidencias de la corrida.

Una fila por archivo de entrada (capturas, respaldos, inventarios, exportaciones, avisos, perfil...) con un
id estable (prefijo + 10 hex del sha256), su huella y los metadatos del proyecto (recolector, planta, metodo,
sensibilidad, entregables) que salen de la clave de perfil `registro_evidencias` o de un registro anterior
que el equipo lleno (--registro-evidencias). Solo nombres de archivo, nunca rutas. No lee contenido mas alla
del sha256 y no vuelve a calcular el que la corrida ya calculo. Sin la clave ni la opcion no hace nada.
"""
from __future__ import annotations

import csv
import fnmatch
import hashlib
import io
import re
from pathlib import Path

from .entorno import NO_DISPONIBLE, sha256_archivo
from .i18n import t

CLAVE = "registro_evidencias"
ARCHIVO = "registro_evidencias.csv"
HOJA = "Registro de evidencias"
ATRIBUTO = "registro_evidencias_tabla"            # resultado de preparar(), colgado de args
ATRIBUTO_PREVIO = "registro_evidencias_previo"    # lectura de --registro-evidencias, colgada de args
COLUMNAS = ["id_evidencia", "archivo", "opcion", "tipo_fuente", "bytes", "sha256", "recolector", "planta",
            "metodo", "sensibilidad", "clase_evidencia", "entregables", "custodia", "nota_equipo"]
_C = {c: i for i, c in enumerate(COLUMNAS)}
CAMPOS = ("recolector", "planta", "metodo", "sensibilidad")
NO_DECLARADO = "no declarado"
PREFIJO = "EV"
_RE_PREFIJO = re.compile(r"[A-Za-z0-9]{1,10}")
_RE_ID = re.compile(r"[A-Za-z0-9._-]{1,20}")
MAX_BYTES = 20 * 1024 * 1024
MAX_FILAS = 100000
# Un archivo escrito con --idioma en lleva las cabeceras traducidas: se aceptan ambas.
ALIAS = {"id_evidencia": ("id_evidencia", "evidence_id"), "recolector": ("recolector", "collector"),
         "planta": ("planta", "plant"), "metodo": ("metodo", "method"),
         "sensibilidad": ("sensibilidad", "sensitivity"), "entregables": ("entregables", "deliverables"),
         "nota_equipo": ("nota_equipo", "team_note")}
# Tabla explicita {dest de argparse: tipo_fuente}, en el orden de las filas. Nada se infiere: una opcion de
# archivo o carpeta nueva se agrega aqui (la prueba compara contra los parsers). Excluidos a proposito: -o,
# --cache y --registro-evidencias (salidas y caches, no evidencia recibida).
OPCIONES = (
    ("inputs", "captura"), ("fuente_flujos", "plataforma"), ("activos", "plataforma"),
    ("enlaces", "plataforma"), ("perfil", "perfil"), ("firewall", "firewall"), ("switch", "switch"),
    ("rutas_firewall", "rutas_firewall"), ("reglas_firewall", "reglas_firewall"),
    ("firewall_contadores", "firewall_contadores"), ("zonas_fw", "zonas_firewall"),
    ("vulnerabilidades", "vulnerabilidades"), ("kev", "kev"), ("avisos_ics", "avisos_ics"),
    ("paquete_avisos", "paquete_avisos"), ("catalogo_vulnerabilidades", "catalogo_vulnerabilidades"),
    ("alertas", "alertas"), ("tor_relays", "tor_relays"), ("linea_base", "linea_base"),
    ("madurez", "madurez"), ("csf_tiers", "csf_tiers"), ("cis", "cis"), ("cis_mapeo", "cis_mapeo"),
    ("iec62351_estados", "iec62351_estados"), ("vulnerabilidades_revision", "vulnerabilidades_revision"),
    ("valoraciones_riesgo", "valoraciones_riesgo"), ("allowlist_revision", "allowlist_revision"),
    ("inventario_manual", "manual"),
    ("fin_de_soporte", "fin_de_soporte"), ("mapeo", "mapeo"), ("estandar_archivo", "estandar"),
    ("custodia", "custodia"),
)
# Clave de entorno que ya trae el sha256 del archivo (no se vuelve a calcular).
_ENTORNO = {"perfil": "perfil", "reglas_firewall": "reglas_firewall", "vulnerabilidades": "vulnerabilidades",
            "alertas": "alertas", "catalogo_vulnerabilidades": "catalogo_vulnerabilidades", "kev": "kev",
            "tor_relays": "tor_relays", "valoraciones_riesgo": "valoraciones_riesgo",
            "allowlist_revision": "allowlist_revision"}


# ---- perfil ---------------------------------------------------------------------------------------------

def _texto(v, donde, fallo) -> str:
    if not isinstance(v, str) or not v.strip() or len(v.strip()) > 80 or "\n" in v or "\r" in v:
        fallo(donde + ": se admite un texto de 1 a 80 caracteres sin saltos de linea.")
    return v.strip()


def _campos(d: dict, donde: str, fallo) -> dict:
    return {k: _texto(d[k], donde + "." + k, fallo) for k in CAMPOS if k in d}


def validar(v, fallo, catalogo=None) -> dict:
    """Clave de perfil `registro_evidencias` -> {prefijo, valores, sensibilidades, por_archivo}.

    `catalogo`: ids del catalogo de entregables (ENT1) si el perfil lo trae; None si no."""
    if v is True:
        return {"prefijo": PREFIJO, "valores": {}, "sensibilidades": None, "por_archivo": []}
    if not isinstance(v, dict):
        fallo("'registro_evidencias' debe ser true o un objeto.")
    for k in v:
        if k not in ("prefijo", "valores", "sensibilidades", "por_archivo"):
            fallo("clave desconocida '" + str(k) + "' en 'registro_evidencias'.")
    pre = v.get("prefijo", PREFIJO)
    if not isinstance(pre, str) or not _RE_PREFIJO.fullmatch(pre):
        fallo("'registro_evidencias.prefijo' admite 1 a 10 caracteres A-Z, a-z, 0-9.")
    val = v.get("valores", {})
    if not isinstance(val, dict):
        fallo("'registro_evidencias.valores' debe ser un objeto.")
    for k in val:
        if k not in CAMPOS:
            fallo("clave desconocida '" + str(k) + "' en 'registro_evidencias.valores'.")
    valores = _campos(val, "registro_evidencias.valores", fallo)
    sens = None
    if "sensibilidades" in v:
        lst = v["sensibilidades"]
        if not isinstance(lst, list) or not 1 <= len(lst) <= 10:
            fallo("'registro_evidencias.sensibilidades' debe ser una lista de 1 a 10 textos.")
        sens = [_texto(x, "registro_evidencias.sensibilidades", fallo) for x in lst]
        if len(set(sens)) != len(sens):
            fallo("'registro_evidencias.sensibilidades' tiene textos repetidos.")
    por = v.get("por_archivo", [])
    if not isinstance(por, list) or len(por) > 200:
        fallo("'registro_evidencias.por_archivo' debe ser una lista de 0 a 200 objetos.")
    reglas = []
    for n, r in enumerate(por):
        donde = "registro_evidencias.por_archivo[" + str(n) + "]"
        if not isinstance(r, dict) or "patron" not in r:
            fallo(donde + ": debe ser un objeto con 'patron'.")
        for k in r:
            if k not in ("patron", "entregables", *CAMPOS):
                fallo("clave desconocida '" + str(k) + "' en '" + donde + "'.")
        p = r["patron"]
        if not isinstance(p, str) or not p.strip() or len(p) > 120 or "\n" in p or "\r" in p:
            fallo(donde + ".patron: se admite un texto de 1 a 120 caracteres sin saltos de linea.")
        regla = {"patron": p, **_campos(r, donde, fallo)}
        if "entregables" in r:
            regla["entregables"] = _entregables(r["entregables"], donde + ".entregables", fallo, catalogo)
        reglas.append(regla)
    if sens is not None:
        for donde, d in [("valores", valores), *[("por_archivo[" + str(n) + "]", x) for n, x in enumerate(reglas)]]:
            if "sensibilidad" in d and d["sensibilidad"] not in sens:
                fallo("'registro_evidencias." + donde + ".sensibilidad' no esta en 'sensibilidades'.")
    return {"prefijo": pre, "valores": valores, "sensibilidades": sens, "por_archivo": reglas}


def _entregables(lst, donde, fallo, catalogo) -> list:
    if not isinstance(lst, list) or len(lst) > 20:
        fallo("'" + donde + "' debe ser una lista de 0 a 20 ids.")
    out = []
    for x in lst:
        if not isinstance(x, str) or not _RE_ID.fullmatch(x):
            fallo("'" + donde + "': id invalido " + repr(x) + " (1 a 20 caracteres de A-Z, a-z, 0-9, punto, guion y "
                  "guion bajo).")
        if catalogo is not None and x not in catalogo:
            fallo("'" + donde + "': '" + x + "' no esta en el catalogo de 'entregables'.")
        if x not in out:
            out.append(x)
    return out


def _config(perfil, args) -> dict | None:
    """Configuracion efectiva: la del perfil, la de defecto si solo hay opcion, None si no se pide."""
    cfg = (perfil or {}).get(CLAVE)
    if cfg is None:
        if not getattr(args, "registro_evidencias", None):
            return None
        cfg = {"prefijo": PREFIJO, "valores": {}, "sensibilidades": None, "por_archivo": []}
    return cfg


def _catalogo(perfil):
    e = (perfil or {}).get("entregables")
    return {c["id"] for c in e["catalogo"]} if e else None


# ---- importacion ----------------------------------------------------------------------------------------

def _vacio(c: str) -> str:
    c = c.strip()
    return "" if c in (NO_DECLARADO, "not declared") else c


def leer(ruta, sensibilidades=None, catalogo=None) -> dict:
    """{id_evidencia: {campo: valor, 'entregables': [...], 'nota_equipo': texto}} (solo celdas no vacias) de un
    registro_evidencias.csv llenado por el equipo. ValueError si no sirve."""
    p = Path(ruta)
    if not p.is_file():
        raise ValueError(t("--registro-evidencias espera un archivo existente: '{a}'", a=p.name))
    try:
        if p.stat().st_size > MAX_BYTES:
            raise ValueError(t("'{a}' pesa mas de 20 MB.", a=p.name))
        texto = p.read_bytes().decode("utf-8-sig")
    except (OSError, UnicodeDecodeError) as e:
        raise ValueError(t("No pude leer '{a}': {e}", a=p.name, e=str(e)))
    cab = texto.split("\n", 1)[0]
    sep = ";" if cab.count(";") > cab.count(",") else ","
    out: dict = {}
    crudo: dict = {}
    try:
        lector = csv.reader(io.StringIO(texto), delimiter=sep)
        cols = [c.strip() for c in (next(lector, None) or [])]
        idx = {}
        for k, alias in ALIAS.items():
            hay = [cols.index(a) for a in alias if a in cols]
            if hay:
                idx[k] = hay[0]
        if "id_evidencia" not in idx:
            raise ValueError(t("'{a}' no tiene la columna id_evidencia.", a=p.name))
        n = 0
        for fila in lector:
            if not any(c.strip() for c in fila):
                continue
            n += 1
            if n > MAX_FILAS:
                raise ValueError(t("'{a}' tiene mas de {n} filas.", a=p.name, n=MAX_FILAS))
            cel = {k: (fila[i] if i < len(fila) else "") for k, i in idx.items()}
            ident = cel["id_evidencia"].strip()
            if not ident:
                continue
            datos = {k: _vacio(cel[k]) for k in CAMPOS if k in cel}
            if cel.get("nota_equipo", "").strip():
                datos["nota_equipo"] = cel["nota_equipo"]
            ents = [x.strip() for x in re.split(r"[;,]", cel.get("entregables", "")) if x.strip()]
            if ents:
                datos["entregables"] = list(dict.fromkeys(ents))
            datos = {k: v for k, v in datos.items() if v}
            if ident in out and crudo[ident] != datos:
                raise ValueError(t("id_evidencia repetido con valores distintos: {i}.", i=ident))
            crudo[ident] = datos
            if sensibilidades is not None and datos.get("sensibilidad", sensibilidades[0]) not in sensibilidades:
                raise ValueError(t("sensibilidad no permitida en {i}. Permitidas: {s}.",
                                   i=ident, s=", ".join(sensibilidades)))
            for x in datos.get("entregables", ()):
                if not _RE_ID.fullmatch(x) or (catalogo is not None and x not in catalogo):
                    raise ValueError(t("entregable fuera del catalogo en {i}: {x}.", i=ident, x=x))
            out[ident] = datos
    except csv.Error as e:
        raise ValueError(t("'{a}' no es un CSV valido: {e}", a=p.name, e=str(e)))
    return out


def leer_opcion(ap, args, perfil) -> None:
    """Lee --registro-evidencias antes de crear salidas; cualquier error termina con codigo 2 (ap.error)."""
    ruta = getattr(args, "registro_evidencias", None)
    setattr(args, ATRIBUTO_PREVIO, None)
    if not ruta:
        return
    cfg = (perfil or {}).get(CLAVE) or {}
    try:
        setattr(args, ATRIBUTO_PREVIO, leer(ruta, cfg.get("sensibilidades"), _catalogo(perfil)))
    except ValueError as e:
        ap.error(str(e))


# ---- recopilacion ---------------------------------------------------------------------------------------

def _tamano(p: Path) -> int:
    try:
        return p.stat().st_size
    except OSError:
        return 0


def _sha_entorno(entorno, clave, ruta):
    e = (entorno or {}).get(clave)
    if (isinstance(e, dict) and e.get("archivo") == Path(ruta).name and e.get("sha256")
            and e["sha256"] != NO_DISPONIBLE):
        return e["sha256"]
    return None


def _carpeta(p: Path, archivos=None) -> dict:
    """Una fila para una carpeta: bytes = suma; sha256 = el de las lineas 'sha256  ruta_relativa' ordenadas."""
    if archivos is None:
        archivos = [f for f in p.rglob("*") if f.is_file() and not f.is_symlink()]
    lineas, total = [], 0
    for f in archivos:
        lineas.append((f.relative_to(p).as_posix(), sha256_archivo(f)))
        total += _tamano(f)
    lineas.sort()
    huella = hashlib.sha256("".join(s + "  " + r + "\n" for r, s in lineas).encode("utf-8")).hexdigest()
    return {"archivo": p.name, "bytes": total, "sha256": huella,
            "nota": t("carpeta con {n} archivos", n=len(lineas))}


def _entrada(opcion, orden, tipo, p: Path, sha=None) -> dict:
    return {"archivo": p.name, "bytes": _tamano(p), "sha256": sha or sha256_archivo(p), "nota": "",
            "opcion": opcion, "orden": orden, "tipo": tipo}


def _de_fuente_flujos(valor: str, orden: int):
    """--fuente-flujos NOMBRE=RUTA: archivo -> una fila; carpeta -> cada captura una fila y el resto, una carpeta."""
    from .fuentes import es_captura, expandir
    p = Path(valor.partition("=")[2])
    if p.is_file():
        yield _entrada("fuente-flujos", orden, "captura" if es_captura(p) else "plataforma", p)
    elif p.is_dir():
        try:
            archivos = [Path(x) for x in expandir(str(p))]
        except SystemExit:
            return
        resto = []
        for f in archivos:
            if es_captura(f):
                yield _entrada("fuente-flujos", orden, "captura", f)
            else:
                resto.append(f)
        if resto:
            yield {**_carpeta(p, resto), "opcion": "fuente-flujos", "orden": orden, "tipo": "plataforma"}


def recopilar(args, entorno, caps=()) -> list:
    """Entradas de la corrida (sin duplicados por contenido), segun la tabla OPCIONES."""
    out = []
    paquete = getattr(args, "paquete_avisos", None)
    info = getattr(args, "paquete_avisos_info", None) or {}
    for orden, (dest, tipo) in enumerate(OPCIONES):
        opcion = dest.replace("_", "-")      # sin "--": una celda que empieza con "-" se neutraliza (SEG-02)
        if dest == "inputs":
            for c, e in zip(caps, (entorno or {}).get("capturas", ())):
                out.append({"archivo": c.name, "bytes": _tamano(Path(c.path)), "sha256": e["sha256"], "nota": "",
                            "opcion": t("capturas"), "orden": orden, "tipo": tipo})
            continue
        v = getattr(args, dest, None)
        if not v:
            continue
        if dest in ("avisos_ics", "kev") and paquete:        # ya verificados dentro del paquete (AVK1)
            continue
        if dest == "fuente_flujos":
            for x in v:
                out.extend(_de_fuente_flujos(x, orden))
            continue
        for ruta in (v if isinstance(v, (list, tuple)) else [v]):
            p = Path(ruta)
            if p.is_dir():
                e = {**_carpeta(p), "opcion": opcion, "orden": orden, "tipo": tipo}
                if dest == "paquete_avisos" and info.get("sha256"):
                    e["sha256"] = info["sha256"]           # huella del manifiesto, ya verificada
                out.append(e)
            elif p.is_file():
                out.append(_entrada(opcion, orden, tipo, p, _sha_entorno(entorno, _ENTORNO.get(dest), p)
                                    if dest in _ENTORNO else None))
    unicos: dict = {}
    for e in out:
        k = e["sha256"] if e["sha256"] != NO_DISPONIBLE else (e["archivo"], e["tipo"])
        if k in unicos:
            u = unicos[k]
            u["archivos"].add(e["archivo"])
            u["opciones"].add(e["opcion"])
            u["nota"] = u["nota"] or e["nota"]
        else:
            unicos[k] = {**e, "archivos": {e["archivo"]}, "opciones": {e["opcion"]}}
    return sorted(unicos.values(), key=lambda u: (u["orden"], min(u["archivos"])))


# ---- tabla ----------------------------------------------------------------------------------------------

def _id(prefijo: str, e: dict) -> str:
    h = e["sha256"] if e["sha256"] != NO_DISPONIBLE else hashlib.sha256(e["archivo"].encode("utf-8")).hexdigest()
    return prefijo + "-" + h[:10]


def _clase(modelo, tipo: str, nombre: str) -> str:
    if not modelo:
        return ""
    por = modelo["por_fuente"]
    return por.get((tipo + ":" + nombre).lower()) or por.get(tipo) or ""


def _meta(cfg: dict, perfil, nombres: list) -> dict:
    meta = {"planta": (perfil or {}).get("sitio", ""), "recolector": "", "metodo": "", "sensibilidad": "",
            "entregables": []}
    meta.update(cfg["valores"])
    mejor = None
    for n in nombres:
        for i, r in enumerate(cfg["por_archivo"]):
            if fnmatch.fnmatchcase(n.lower(), r["patron"].lower()):
                if mejor is None or i < mejor:
                    mejor = i
                break
    if mejor is not None:
        meta.update({k: v for k, v in cfg["por_archivo"][mejor].items() if k != "patron"})
    return meta


def preparar(args, perfil, entorno, caps=()):
    """Arma la tabla si el perfil o --registro-evidencias la piden y la guarda en args; None si no."""
    cfg = _config(perfil, args)
    if cfg is None:
        return None
    from .inventario_normalizado import modelo_de
    modelo = modelo_de(perfil)
    previo = getattr(args, ATRIBUTO_PREVIO, None) or {}
    cust = {x["sha256"]: x["estado"] for x in ((entorno or {}).get("custodia") or {}).get("capturas", ())}
    filas, usados = [], set()
    por_tipo: dict = {}
    for e in recopilar(args, entorno, caps):
        nombres = sorted(e["archivos"])
        m = _meta(cfg, perfil, nombres)
        ident = _id(cfg["prefijo"], e)
        nota = e["nota"]
        if ident in previo:
            usados.add(ident)
            p = previo[ident]
            m.update({k: v for k, v in p.items() if k not in ("nota_equipo",)})
            nota = p.get("nota_equipo", nota)
        fila = [ident, "; ".join(nombres), "; ".join(sorted(e["opciones"])), e["tipo"], e["bytes"], e["sha256"],
                *[m[k] or t(NO_DECLARADO) for k in CAMPOS], _clase(modelo, e["tipo"], nombres[0]),
                "; ".join(m["entregables"]), cust.get(e["sha256"], "") if e["tipo"] == "captura" else "", nota]
        filas.append(fila)
        por_tipo[e["tipo"]] = por_tipo.get(e["tipo"], 0) + 1
    falta = len(set(previo) - usados)
    if falta:
        print(t("[!] --registro-evidencias: {n} id_evidencia del archivo ya no existen en esta corrida; "
                "no se trasladan.", n=falta))
    nd = t(NO_DECLARADO)
    res = {"filas": filas,
           "json": {"filas": len(filas), "por_tipo": dict(sorted(por_tipo.items())),
                    "sin_recolector": sum(1 for f in filas if f[_C["recolector"]] == nd),
                    "sin_sensibilidad": sum(1 for f in filas if f[_C["sensibilidad"]] == nd),
                    "importadas": len(usados), "ids_no_encontrados": falta}}
    setattr(args, ATRIBUTO, res)
    return res


def tablas(args) -> list:
    d = getattr(args, ATRIBUTO, None)
    if not isinstance(d, dict):
        return []
    return [(ARCHIVO, HOJA, COLUMNAS, d["filas"])]


def para_json(args):
    d = getattr(args, ATRIBUTO, None)
    return d["json"] if isinstance(d, dict) else None
