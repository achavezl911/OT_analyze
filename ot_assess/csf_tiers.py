"""Niveles (Tiers) de NIST CSF 2.0 por funcion (CSF2T, D110).

Los Tiers caracterizan el rigor de las practicas de gobierno y gestion del riesgo; la herramienta no los mide. Da la
hoja de trabajo por funcion (GV, ID, PR, DE, RS, RC): la meta del perfil (`csf_tiers_objetivo`), el tier que declara
la organizacion en la entrevista (`--csf-tiers`, el mismo csf_tiers.csv llenado), la brecha y la evidencia tecnica
relacionada de la corrida: las filas NIST de la matriz de controles alcanzadas por la funcion a traves de las
referencias informativas de CSF 2.0 (solo identificadores). Con un tier declarado >= 3 y un hallazgo Alta en esas
filas lo marca para revision; no cambia el tier. Nunca dice "cumple" ni "no cumple". Solo lee el modelo ya calculado.
"""
from __future__ import annotations

import csv
import re
from pathlib import Path

from . import matriz_controles as _mc
from .i18n import catalogo, t

TITULO = "Niveles (Tiers) de NIST CSF 2.0 por funcion"
HOJA = "Tiers CSF 2.0"
ARCHIVO = "csf_tiers.csv"
NOTA = ("Los Tiers de NIST CSF 2.0 caracterizan el rigor de las practicas de gobierno y gestion del riesgo; la "
        "herramienta no los mide. El tier actual lo declara la organizacion (NIST SP 1302) y la meta la fija el "
        "perfil. Las filas NIST por funcion salen de las referencias informativas de CSF 2.0 y son evidencia "
        "relacionada de la corrida, no un veredicto; nunca una determinacion de cumplimiento.")
SIN_ARCHIVO = ("No se cargo el tier actual: la seccion muestra la meta y la evidencia tecnica. El tier actual se "
               "llena en {archivo} y se entrega con --csf-tiers ARCHIVO.")
ORIGEN_PERFIL = "declarado en el perfil (csf_tiers_objetivo)"
ORIGEN_PROPUESTO = "propuesto por la herramienta; lo fija el cliente"
OBJETIVO_DEFECTO = 2
REVISAR = "revisar: la evidencia de red no respalda el tier declarado ({titulos})"
NIVEL_REVISION = 3
MAX_TITULOS = 5

FUNCIONES = ("GV", "ID", "PR", "DE", "RS", "RC")
NOMBRES = {"GV": "Gobernar", "ID": "Identificar", "PR": "Proteger", "DE": "Detectar", "RS": "Responder",
           "RC": "Recuperar"}
TIERS = {1: "Parcial", 2: "Informado por el riesgo", 3: "Repetible", 4: "Adaptativo"}

COL_ANALISTA = ("evidencia_presentada", "entrevistado", "fecha", "comentario")
COLUMNAS = ["funcion", "nombre", "tier_objetivo", "origen_objetivo", "tier_actual", "brecha", "filas_nist_brecha",
            "filas_nist_observado", "filas_nist_sin_evidencia", "filas_nist_no_evaluables", "subcategorias",
            "controles_800_53", "revision", *COL_ANALISTA]
CAB_SECCION = ["Funcion", "Tier actual", "Meta", "Brecha", "Filas NIST (brecha/observado/sin evidencia/no evaluables)",
               "Revision"]


class ErrorCsfTiers(ValueError):
    """Archivo de tiers o perfil invalido; el mensaje trae el numero de linea cuando aplica."""


def _norm(x) -> str:
    return re.sub(r"\s+", " ", str(x).strip().casefold())


def _nombres_tier() -> dict:
    """{nombre normalizado: tier} en espanol y, si el catalogo se lee, en ingles."""
    en = catalogo("en")
    out = {}
    for n, nombre in TIERS.items():
        out[_norm(nombre)] = n
        if en.get(nombre):
            out[_norm(en[nombre])] = n
    return out


def tier_de(valor, fallo) -> int:
    """Tier 1 a 4 desde un entero, su texto o el nombre (espanol o ingles, sin distinguir mayusculas).
    Cualquier otro valor llama a `fallo(mensaje)`, que debe lanzar."""
    if isinstance(valor, int) and not isinstance(valor, bool) and 1 <= valor <= 4:
        return valor
    if isinstance(valor, str):
        s = _norm(valor)
        if re.fullmatch(r"[1-4]", s):
            return int(s)
        if s in _nombres_tier():
            return _nombres_tier()[s]
    opciones = "; ".join(f"{n} {nombre}" for n, nombre in TIERS.items())
    fallo(f"el tier '{valor}' no es valido (use {opciones}).")
    raise ErrorCsfTiers(f"el tier '{valor}' no es valido.")


def objetivos_validos(d, fallo) -> dict:
    """Valida `csf_tiers_objetivo` del perfil: {codigo de funcion: tier 1 a 4}."""
    if not isinstance(d, dict):
        fallo("'csf_tiers_objetivo' debe ser un objeto funcion -> tier (use funciones: " + ", ".join(FUNCIONES) + ").")
    out = {}
    for k, v in d.items():
        if k not in FUNCIONES:
            fallo(f"csf_tiers_objetivo: '{k}' no es una funcion de CSF 2.0 (use: {', '.join(FUNCIONES)}).")
        out[k] = tier_de(v, lambda m, k=k: fallo(f"csf_tiers_objetivo.{k}: {m}"))
    return out


# --- archivo del analista ---------------------------------------------------------------------------------- #

def _separador(texto: str) -> str:
    primera = texto.splitlines()[0] if texto.strip() else ""
    return ";" if primera.count(";") > primera.count(",") else ","


def _alias_columnas() -> dict:
    """{cabecera normalizada: columna} con los nombres de columna en espanol y en ingles."""
    en = catalogo("en")
    out = {}
    for c in ("funcion", "tier_actual", *COL_ANALISTA):
        out[_norm(c)] = c
        if en.get(c):
            out[_norm(en[c])] = c
    return out


def leer(ruta) -> dict:
    """Lee el csf_tiers.csv llenado: {funcion: {tier_actual (1-4 o None), evidencia_presentada, entrevistado, fecha,
    comentario}}. Falla con ErrorCsfTiers y todas las lineas con error; no devuelve nada a medias."""
    ruta = Path(ruta)
    try:
        texto = ruta.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as e:
        raise ErrorCsfTiers(f"No pude leer el archivo de tiers '{ruta.name}': {e}")
    lector = csv.reader(texto.splitlines(), delimiter=_separador(texto))
    try:
        alias = _alias_columnas()
        cab = [alias.get(_norm(c), _norm(c)) for c in next(lector)]
    except StopIteration:
        raise ErrorCsfTiers(f"{ruta.name}: el archivo esta vacio.")
    except csv.Error as e:
        raise ErrorCsfTiers(f"{ruta.name} linea 1: no es un CSV valido ({e}).")
    for c in ("funcion", "tier_actual"):
        if c not in cab:
            raise ErrorCsfTiers(f"{ruta.name} linea 1: falta la columna '{c}'.")
    out, errores = {}, []
    for fila in lector:
        n = lector.line_num
        if not any(x.strip() for x in fila):
            continue
        d = {c: (fila[i].strip() if i < len(fila) else "") for i, c in enumerate(cab)}
        fun = d["funcion"].upper()
        if fun not in FUNCIONES:
            errores.append(f"{ruta.name} linea {n}: la funcion '{d['funcion']}' no existe (use: "
                           f"{', '.join(FUNCIONES)}).")
            continue
        if fun in out:
            errores.append(f"{ruta.name} linea {n}: la funcion '{fun}' esta repetida.")
            continue
        actual = None
        if d["tier_actual"]:
            msgs = []
            try:
                actual = tier_de(d["tier_actual"], msgs.append)
            except ErrorCsfTiers:
                errores.append(f"{ruta.name} linea {n}: {msgs[0]}" if msgs else f"{ruta.name} linea {n}: tier no valido.")
                continue
        out[fun] = {"tier_actual": actual, **{c: d.get(c, "") for c in COL_ANALISTA}}
    if errores:
        raise ErrorCsfTiers("\n".join(errores[:20]) + (f"\n... y {len(errores) - 20} errores mas"
                                                       if len(errores) > 20 else ""))
    return out


def leer_opcion(ap, ruta):
    """Para `--csf-tiers ARCHIVO` de los CLI de analisis: None sin la opcion; con ella, lo que devuelve `leer`
    o un error de argumentos (antes de analizar nada)."""
    if not ruta:
        return None
    if not Path(ruta).is_file():
        ap.error(f"--csf-tiers espera un archivo existente: '{ruta}'")
    try:
        return leer(ruta)
    except ErrorCsfTiers as e:
        ap.error(str(e))


# --- calculo ----------------------------------------------------------------------------------------------- #

def _objetivo(fun: str, perfil: dict) -> tuple:
    por_fun = perfil.get("csf_tiers_objetivo") or {}
    if fun in por_fun:
        return por_fun[fun], ORIGEN_PERFIL
    return OBJETIVO_DEFECTO, ORIGEN_PROPUESTO


def _titulos_alta(res) -> set:
    from .report.common import agrupar_hallazgos

    return {f["titulo"] for f in agrupar_hallazgos([*getattr(res, "caps", ()), *getattr(res, "extras", ())])
            if f["severidad"] == "Alta"}


def _evidencia(fun: str, filas: list, alta: set) -> dict:
    refs = _mc.referencias_csf()
    subs = [s for s in refs if s.startswith(fun + ".")]
    controles = {_mc.base_de(c) for s in subs for c in refs[s]["sp800_53"]}
    rows = sorted((r for r in filas if _mc.base_de(r["id"]) in controles), key=lambda r: r["prioridad"])
    from .linea_base import E_BRECHA, E_CONTROL, E_NOEVAL, E_SIN

    cuenta = {e: sum(1 for r in rows if r["estado"] == e) for e in (E_BRECHA, E_CONTROL, E_SIN, E_NOEVAL)}
    titulos = list(dict.fromkeys(h for r in rows for h in r["hallazgos"] if h in alta))
    return {"subcategorias": len(subs), "controles": len(controles), "brecha": cuenta[E_BRECHA],
            "observado": cuenta[E_CONTROL], "sin_evidencia": cuenta[E_SIN], "no_evaluable": cuenta[E_NOEVAL],
            "titulos_alta": titulos}


def construir(res, declarados: dict | None = None) -> dict:
    """{"funciones", "con_archivo", "declarados"}; {} si ni el perfil trae `csf_tiers_objetivo` ni se dio
    `--csf-tiers`. Textos ya traducidos al idioma de la corrida. `declarados` es lo que devuelve `leer` (o None)."""
    perfil = getattr(res, "perfil", None) or {}
    if declarados is None and "csf_tiers_objetivo" not in perfil:
        return {}
    filas = (((getattr(res, "matriz_controles", None) or {}).get("nist")) or {}).get("filas") or []
    alta = _titulos_alta(res)
    funciones = []
    for fun in FUNCIONES:
        objetivo, origen = _objetivo(fun, perfil)
        d = (declarados or {}).get(fun, {})
        actual = d.get("tier_actual")
        ev = _evidencia(fun, filas, alta)
        revision = ""
        if actual is not None and actual >= NIVEL_REVISION and ev["titulos_alta"]:
            revision = t(REVISAR, titulos="; ".join(t(x) for x in ev["titulos_alta"][:MAX_TITULOS]))
        funciones.append({
            "clave": fun, "nombre": t(NOMBRES[fun]), "objetivo": objetivo, "origen_objetivo": t(origen),
            "actual": actual, "brecha": max(0, objetivo - actual) if actual is not None else None,
            "evidencia": ev, "revision": revision, "analista": {c: d.get(c, "") for c in COL_ANALISTA}})
    return {"funciones": funciones, "con_archivo": declarados is not None, "declarados": declarados or {}}


# --- salidas ----------------------------------------------------------------------------------------------- #

def hay(m: dict) -> bool:
    return bool(m and m.get("funciones"))


def _tier(n) -> str:
    return "" if n is None else t(TIERS[n])


def filas_tabla(m: dict) -> list:
    out = []
    for x in m["funciones"]:
        e = x["evidencia"]
        out.append([x["clave"], x["nombre"], _tier(x["objetivo"]), x["origen_objetivo"], _tier(x["actual"]),
                    "" if x["brecha"] is None else x["brecha"], e["brecha"], e["observado"], e["sin_evidencia"],
                    e["no_evaluable"], e["subcategorias"], e["controles"], x["revision"],
                    *[x["analista"][c] for c in COL_ANALISTA]])
    return out


def tablas(m: dict) -> list:
    if not hay(m):
        return []
    return [(ARCHIVO, HOJA, [t(c) for c in COLUMNAS], filas_tabla(m))]


def _resumen(m: dict) -> str:
    if not m["con_archivo"]:
        return t(SIN_ARCHIVO, archivo=ARCHIVO)
    con = [x for x in m["funciones"] if x["actual"] is not None]
    con_brecha = sum(1 for x in con if x["brecha"])
    return t("Tier actual declarado en {c} de {n} funciones; {b} con brecha frente a la meta. Detalle en {a}.",
             c=len(con), n=len(m["funciones"]), b=con_brecha, a=ARCHIVO)


def seccion(m: dict) -> dict:
    """Datos de la seccion de los reportes: tabla breve y avisos de revision."""
    filas, revisiones = [], []
    for x in m["funciones"]:
        e = x["evidencia"]
        filas.append([f"{x['clave']} {x['nombre']}", _tier(x["actual"]) or "-", _tier(x["objetivo"]),
                      "-" if x["brecha"] is None else x["brecha"],
                      f"{e['brecha']}/{e['observado']}/{e['sin_evidencia']}/{e['no_evaluable']}",
                      x["revision"] or "-"])
        if x["revision"]:
            revisiones.append(f"{x['nombre']}: {x['revision']}")
    return {"titulo": t(TITULO), "nota": t(NOTA), "resumen": _resumen(m), "cab": [t(c) for c in CAB_SECCION],
            "filas": filas, "revisiones": revisiones,
            "origen_objetivo": "; ".join(sorted({x["origen_objetivo"] for x in m["funciones"]}))}


def imprimir(m: dict) -> None:
    if not hay(m):
        return
    if not m["con_archivo"]:
        print("    csf tiers: sin tier actual (hoja de trabajo en csf_tiers.csv)")
    else:
        con = [x for x in m["funciones"] if x["actual"] is not None]
        print(f"    csf tiers: tier actual en {len(con)} de {len(m['funciones'])} funciones, "
              f"{sum(1 for x in con if x['brecha'])} con brecha")
    for x in m["funciones"]:
        if x["revision"]:
            print(f"[!] csf tiers {x['clave']}: {x['revision']}")


def para_json(m: dict) -> dict:
    if not hay(m):
        return {}
    return {"con_archivo": m["con_archivo"], "nota": t(NOTA),
            "funciones": [{"clave": x["clave"], "nombre": x["nombre"], "tier_actual": x["actual"],
                           "tier_objetivo": x["objetivo"], "origen_objetivo": x["origen_objetivo"],
                           "brecha": x["brecha"],
                           "filas_nist": {k: x["evidencia"][k] for k in ("brecha", "observado", "sin_evidencia",
                                                                          "no_evaluable")},
                           "subcategorias": x["evidencia"]["subcategorias"],
                           "controles_800_53": x["evidencia"]["controles"], "revision": x["revision"]}
                          for x in m["funciones"]]}
