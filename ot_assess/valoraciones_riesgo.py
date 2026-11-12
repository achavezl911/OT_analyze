"""RM2b (D130): valoracion inherente, residual actual y residual objetivo de cada riesgo.

La herramienta solo calcula la residual actual (registro de riesgos). La inherente (sin controles) y la objetivo
(despues del tratamiento planeado) las valora el equipo en una plantilla (valoraciones_riesgo.csv) que devuelve con
--valoraciones-riesgo; la ida y vuelta es el mismo archivo. Puntuacion = probabilidad x impacto con la escala y los
niveles del proyecto (RM2), sin elevacion. Las observaciones son avisos, nunca errores. Sin la subclave de perfil
`riesgo.valoraciones` ni la opcion no hace nada.
"""
from __future__ import annotations

import csv
import datetime
import io
import re
from pathlib import Path

from .i18n import catalogo, t

CLAVE = "valoraciones"
ARCHIVO = "valoraciones_riesgo.csv"
HOJA = "Valoracion de riesgos"
ATRIBUTO = "valoraciones_plan"
TRATAMIENTOS_DEFECTO = ["mitigar", "aceptar", "transferir", "evitar"]
MAX_TEXTO = 500
MAX_BYTES = 20 * 1024 * 1024
MAX_FILAS = 100000

COL_HERRAMIENTA = ["id_riesgo", "id_hallazgo", "titulo", "probabilidad_actual", "impacto_actual",
                   "puntuacion_actual", "nivel_actual"]
COL_EQUIPO = ["probabilidad_inherente", "impacto_inherente", "controles_existentes", "tratamiento",
              "controles_planeados", "probabilidad_objetivo", "impacto_objetivo", "responsable", "fecha_objetivo",
              "justificacion"]
COL_CALCULADAS = ["puntuacion_inherente", "nivel_inherente", "puntuacion_objetivo", "nivel_objetivo",
                  "dentro_de_apetito", "observaciones"]
COLUMNAS = COL_HERRAMIENTA + COL_EQUIPO + COL_CALCULADAS
COL_REGISTRO = ["puntuacion_inherente", "nivel_inherente", "puntuacion_objetivo", "nivel_objetivo", "tratamiento",
                "dentro_de_apetito"]
_TEXTOS = ("controles_existentes", "controles_planeados", "responsable", "justificacion")
_EJES = ("probabilidad_inherente", "impacto_inherente", "probabilidad_objetivo", "impacto_objetivo")
_FECHA = re.compile(r"\d{4}-\d{2}-\d{2}")

TITULO = "Valoracion del riesgo"
FILAS_RESUMEN = ("Inherente", "Residual actual", "Residual objetivo")
SIN_VALORAR = "Sin valorar"
TITULO_MAPAS = {"inherente": "Mapa de calor: riesgo inherente", "objetivo": "Mapa de calor: riesgo residual objetivo"}
HOJAS = {"resumen": "Valoracion del riesgo", "inherente": "Mapa de riesgo inherente",
         "objetivo": "Mapa de riesgo objetivo"}


def defecto() -> dict:
    return {"tratamientos": list(TRATAMIENTOS_DEFECTO), "nivel_aceptable": None}


def validar(v, fallo, objeto, nombres: list) -> dict:
    """Normaliza la subclave de perfil `riesgo.valoraciones`: {tratamientos, nivel_aceptable}."""
    v = objeto(v, "riesgo.valoraciones", ("tratamientos", "nivel_aceptable"))
    trat = v.get("tratamientos", TRATAMIENTOS_DEFECTO)
    if not isinstance(trat, list) or not 2 <= len(trat) <= 8:
        fallo("'riesgo.valoraciones.tratamientos' debe ser una lista de 2 a 8 textos.")
    for x in trat:
        if not isinstance(x, str) or not 1 <= len(x) <= 30 or x != x.strip() or "\n" in x or "\r" in x:
            fallo("'riesgo.valoraciones.tratamientos': cada tratamiento es un texto de 1 a 30 caracteres, "
                  "sin saltos de linea ni espacios en los extremos.")
    if len(set(trat)) != len(trat):
        fallo("'riesgo.valoraciones.tratamientos' tiene tratamientos repetidos.")
    nivel = v.get("nivel_aceptable")
    if "nivel_aceptable" in v and (not isinstance(nivel, str) or nivel not in nombres):
        fallo(f"'riesgo.valoraciones.nivel_aceptable': {nivel!r} no es un nivel del proyecto ({', '.join(nombres)}).")
    return {"tratamientos": list(trat), "nivel_aceptable": nivel}


# ---- lectura del archivo del equipo ---------------------------------------------------------------------

def _alias(col: str) -> tuple:
    """Nombre de la columna en espanol y su traduccion al ingles (un archivo escrito con --idioma en)."""
    return (col, catalogo("en").get(col, col))


def _clave(ident: str) -> str:
    """H-x y R-x con el mismo hash son el mismo riesgo: la clave canonica es R-x en minusculas."""
    m = re.fullmatch(r"[HhRr]-(.+)", ident)
    return "R-" + m.group(1).lower() if m else ident


def _canon_trat(valor: str, lista: list):
    if valor in lista:
        return valor
    if lista == TRATAMIENTOS_DEFECTO:
        en = catalogo("en")
        for es in lista:
            if en.get(es) == valor:
                return es
    return None


def _entero(valor: str, eje: str, tope: int, ident: str, nombre: str) -> int:
    if not re.fullmatch(r"\d{1,3}", valor) or not 1 <= int(valor) <= tope:
        raise ValueError(t("{c} fuera de 1 a {n} en el id {i} de '{a}'.", c=eje, n=tope, i=ident, a=nombre))
    return int(valor)


def leer(ruta, m: dict, tratamientos: list) -> dict:
    """{clave: {columna del equipo: valor}} (en el orden del archivo). ValueError si el archivo no sirve."""
    p = Path(ruta)
    try:
        if p.stat().st_size > MAX_BYTES:
            raise ValueError(t("'{a}' pesa mas de 20 MB.", a=p.name))
        texto = p.read_bytes().decode("utf-8-sig")
    except (OSError, UnicodeDecodeError) as e:
        raise ValueError(t("No pude leer '{a}': {e}", a=p.name, e=str(e)))
    cab = texto.split("\n", 1)[0]
    sep = ";" if cab.count(";") > cab.count(",") else ","
    topes = {"probabilidad": m["np"], "impacto": m["ni"]}
    out: dict = {}
    try:
        lector = csv.reader(io.StringIO(texto), delimiter=sep)
        cols = [c.strip() for c in (next(lector, None) or [])]
        idx = {}
        for c in ("id_riesgo", "id_hallazgo", *COL_EQUIPO):
            hay = [cols.index(a) for a in _alias(c) if a in cols]
            if hay:
                idx[c] = hay[0]
        if "id_riesgo" not in idx and "id_hallazgo" not in idx:
            raise ValueError(t("'{a}' no tiene la columna id_riesgo ni id_hallazgo.", a=p.name))
        n = 0
        for fila in lector:
            if not any(c.strip() for c in fila):
                continue
            n += 1
            if n > MAX_FILAS:
                raise ValueError(t("'{a}' tiene mas de {n} filas.", a=p.name, n=MAX_FILAS))
            cel = {c: (fila[i] if i < len(fila) else "").strip() for c, i in idx.items()}
            ident = cel.get("id_riesgo") or cel.get("id_hallazgo") or ""
            if not ident:
                continue
            clave = _clave(ident)
            if clave in out:
                raise ValueError(t("id repetido en '{a}': {i}.", a=p.name, i=ident))
            reg = {}
            for c in COL_EQUIPO:
                v = cel.get(c, "")
                if len(v) > MAX_TEXTO:
                    raise ValueError(t("Texto de mas de 500 caracteres en el id {i} de '{a}'.", i=ident, a=p.name))
                if v and c in _EJES:
                    v = _entero(v, c, topes[c.split("_")[0]], ident, p.name)
                elif v and c == "tratamiento":
                    canon = _canon_trat(v, tratamientos)
                    if canon is None:
                        raise ValueError(t("Tratamiento no permitido '{e}' en el id {i}. Permitidos: {l}.",
                                           e=v, i=ident, l=", ".join(tratamientos)))
                    v = canon
                elif v and c == "fecha_objetivo" and not _fecha_valida(v):
                    raise ValueError(t("fecha_objetivo '{f}' no es AAAA-MM-DD valida en el id {i} de '{a}'.",
                                       f=v, i=ident, a=p.name))
                reg[c] = v
            out[clave] = reg
    except csv.Error as e:
        raise ValueError(t("'{a}' no es un CSV valido: {e}", a=p.name, e=str(e)))
    return out


def _fecha_valida(v: str) -> bool:
    if not _FECHA.fullmatch(v):
        return False
    try:
        datetime.date(int(v[:4]), int(v[5:7]), int(v[8:]))
    except ValueError:
        return False
    return True


# ---- plan y opcion --------------------------------------------------------------------------------------

class Plan:
    """Configuracion activa y lo importado del archivo del equipo."""

    def __init__(self, cfg: dict, previos: dict):
        self.cfg = cfg
        self.previos = previos


def de_args(args):
    return getattr(args, ATRIBUTO, None)


def leer_opcion(ap, args, perfil) -> None:
    """Lee --valoraciones-riesgo antes de crear salidas (codigo 2 si no sirve) y deja el plan en args."""
    from .riesgo import metodo

    cfg = ((perfil or {}).get("riesgo") or {}).get(CLAVE)
    ruta = getattr(args, "valoraciones_riesgo", None)
    setattr(args, ATRIBUTO, None)
    if cfg is None and not ruta:
        return
    cfg = cfg or defecto()
    previos: dict = {}
    if ruta:
        try:
            previos = leer(ruta, metodo(perfil), cfg["tratamientos"])
        except ValueError as e:
            ap.error(str(e))
    setattr(args, ATRIBUTO, Plan(cfg, previos))


# ---- calculo --------------------------------------------------------------------------------------------

def _par(p, i, m: dict):
    """(puntuacion, nivel) si el par esta completo; si no ('', '')."""
    from .riesgo import nivel

    if p == "" or i == "":
        return "", ""
    return p * i, nivel(p * i, m)


def _fila(plan: Plan, base, previo: dict, m: dict) -> dict:
    cfg = plan.cfg
    v = {c: previo.get(c, "") for c in COL_EQUIPO}
    if base is not None:
        v.update({"id_riesgo": base["id_riesgo"], "id_hallazgo": base["id_hallazgo"], "titulo": base["titulo"],
                  "probabilidad_actual": base["probabilidad"], "impacto_actual": base["impacto"],
                  "puntuacion_actual": base["puntuacion"], "nivel_actual": base["nivel"]})
    else:
        v.update({c: "" for c in COL_HERRAMIENTA})
    v["puntuacion_inherente"], v["nivel_inherente"] = _par(v["probabilidad_inherente"], v["impacto_inherente"], m)
    v["puntuacion_objetivo"], v["nivel_objetivo"] = _par(v["probabilidad_objetivo"], v["impacto_objetivo"], m)
    obs = []
    for eje, (a, b) in (("inherente", ("probabilidad_inherente", "impacto_inherente")),
                        ("objetivo", ("probabilidad_objetivo", "impacto_objetivo"))):
        if (v[a] == "") != (v[b] == ""):
            obs.append(t("valoracion incompleta ({e})", e=t(eje)))
    actual = v["puntuacion_actual"]
    if actual != "":
        if v["puntuacion_inherente"] != "" and v["puntuacion_inherente"] < actual:
            obs.append(t("inherente menor que la actual"))
        if v["puntuacion_objetivo"] != "" and v["puntuacion_objetivo"] > actual:
            obs.append(t("objetivo mayor que la actual"))
    if v["puntuacion_objetivo"] != "" and not v["tratamiento"]:
        obs.append(t("objetivo sin tratamiento"))
    v["dentro_de_apetito"] = ""
    acept = cfg["nivel_aceptable"]
    if acept and v["nivel_objetivo"]:
        fuera = m["nombres"].index(v["nivel_objetivo"]) > m["nombres"].index(acept)
        v["dentro_de_apetito"] = "no" if fuera else "si"
        if fuera:
            obs.append(t("fuera de apetito"))
    if base is None:
        obs.append(t("no aparece en esta corrida"))
    v["observaciones"] = "; ".join(obs)
    return v


def calcular(plan: Plan, filas: list, m: dict) -> dict:
    """Valoraciones de todos los riesgos del registro (en su orden) y de las filas importadas que no aparecen."""
    from .riesgo import _mapa

    presentes = {}
    for f in filas:
        presentes[_clave(f["id_riesgo"])] = f
    out = [_fila(plan, f, plan.previos.get(_clave(f["id_riesgo"]), {}), m) for f in filas]
    sobran = [k for k in plan.previos if k not in presentes]
    for k in sobran:
        v = _fila(plan, None, plan.previos[k], m)
        v["id_riesgo"], v["id_hallazgo"] = k, "H-" + k[2:]
        out.append(v)
    reales = out[:len(filas)]
    mapas = {}
    for eje in ("inherente", "objetivo"):
        pts = [{"id_riesgo": v["id_riesgo"], "puntuacion": v["puntuacion_" + eje],
                "impacto": v["impacto_" + eje], "probabilidad": v["probabilidad_" + eje]}
               for v in reales if v["puntuacion_" + eje] != ""]
        if pts:
            mapas[eje] = _mapa(pts, m)
    por_nivel = {}
    for eje in ("inherente", "actual", "objetivo"):
        cuenta = {n: 0 for n in m["nombres"]}
        cuenta[SIN_VALORAR] = 0
        for v in reales:
            n = v["nivel_" + eje]
            cuenta[n if n in cuenta else SIN_VALORAR] += 1
        por_nivel[eje] = cuenta
    return {"filas": out, "por_id": {v["id_riesgo"]: v for v in out}, "mapas": mapas, "por_nivel": por_nivel,
            "valoradas": {e: sum(1 for v in reales if v["puntuacion_" + e] != "") for e in ("inherente", "objetivo")},
            "fuera_de_apetito": sum(1 for v in reales if v["dentro_de_apetito"] == "no"),
            "con_apetito": sum(1 for v in reales if v["dentro_de_apetito"] != ""),
            "no_presentes": len(sobran), "nivel_aceptable": plan.cfg["nivel_aceptable"],
            "tratamientos": list(plan.cfg["tratamientos"])}


def aviso(val: dict) -> list:
    if not val["no_presentes"]:
        return []
    return [t("--valoraciones-riesgo: {n} id del archivo no aparecen en esta corrida; se conservan al final de "
              "valoraciones_riesgo.csv.", n=val["no_presentes"])]


# ---- salidas --------------------------------------------------------------------------------------------

def _mostrar(v: dict, m: dict, val: dict) -> dict:
    """Fila para escribir: niveles del proyecto sin traducir; los por defecto, si."""
    tn = (lambda x: x) if m["propio_niveles"] else t
    out = dict(v)
    for c in ("nivel_actual", "nivel_inherente", "nivel_objetivo"):
        out[c] = tn(v[c]) if v[c] else ""
    if v["dentro_de_apetito"]:
        out["dentro_de_apetito"] = t(v["dentro_de_apetito"])
    if v["tratamiento"] and val["tratamientos"] == TRATAMIENTOS_DEFECTO:
        out["tratamiento"] = t(v["tratamiento"])
    return out


def tabla(val: dict, m: dict) -> list:
    return [[x[c] for c in COLUMNAS] for x in (_mostrar(v, m, val) for v in val["filas"])]


def extra_registro(val: dict, id_riesgo: str, m: dict) -> dict:
    """Columnas agregadas a riesgos.csv para un riesgo."""
    v = val["por_id"].get(id_riesgo)
    return {c: _mostrar(v, m, val)[c] for c in COL_REGISTRO} if v else {}


def resumen(val: dict, m: dict) -> dict:
    """Tabla 'Valoracion del riesgo' (filas = tipos de valoracion; columnas = niveles y sin valorar) y la frase."""
    tn = (lambda x: x) if m["propio_niveles"] else t
    cab = [t(TITULO)] + [tn(n) for n in m["nombres"]] + [t(SIN_VALORAR)]
    filas = []
    for nombre, eje in zip(FILAS_RESUMEN, ("inherente", "actual", "objetivo")):
        c = val["por_nivel"][eje]
        filas.append([t(nombre)] + [c[n] for n in m["nombres"]] + [c[SIN_VALORAR]])
    if val["nivel_aceptable"]:
        frase = t("Fuera de apetito (nivel aceptable: {n}): {k} de {v} riesgos con valoracion objetivo.",
                  n=tn(val["nivel_aceptable"]), k=val["fuera_de_apetito"], v=val["con_apetito"])
    else:
        frase = t("Sin nivel aceptable declarado en el perfil: no se evalua el apetito de riesgo.")
    return {"cab": cab, "filas": filas, "frase": frase}


def para_json(val: dict) -> dict:
    return {"valoradas": dict(val["valoradas"]),
            "por_nivel": {e: dict(c) for e, c in val["por_nivel"].items()},
            "fuera_de_apetito": val["fuera_de_apetito"], "no_presentes": val["no_presentes"]}
