"""ALLOW1 (D133): la allowlist TO-BE con el vocabulario y las columnas del proyecto, y su traslado entre corridas.

La herramienta propone una decision por (zona origen, zona destino, servicio); el proyecto la llama como quiere
(Allow / Review / Deny) y agrega columnas que llena el equipo (funcion, frecuencia, owner, necesidad). El equipo
devuelve allowlist_tobe.csv con --allowlist-revision y se traslada por id_flujo (o por zonas + servicio); los flujos
que el equipo declara y no se observaron se conservan al final. No infiere nada del equipo ni cambia las reglas de
decision. Sin la clave de perfil `allowlist_tobe` ni la opcion no hace nada.
"""
from __future__ import annotations

import csv
import hashlib
import io
import re
from pathlib import Path

from .i18n import Traducido, catalogo, t

CLAVE = "allowlist_tobe"
ATRIBUTO = "allowlist_plan"
COLUMNAS_DEFECTO = ["funcion", "frecuencia", "owner", "necesidad"]
COL_REVISION = ["estado_revision", "revisado_por", "fecha", "comentario"]
COL_ID = "id_flujo"
COL_PROYECTO = "decision_proyecto"
COL_DECISION_EQUIPO = "decision_equipo"
COL_OBSERVADO = "observado"
COL_NUEVAS = [COL_ID, COL_PROYECTO, COL_DECISION_EQUIPO, COL_OBSERVADO]
CLAVES_DECISION = ("permitir", "por DMZ", "revisar", "bloquear")
MAX_TEXTO = 500
MAX_BYTES = 20 * 1024 * 1024
MAX_FILAS = 100000
_NOMBRE_COL = re.compile(r"[a-z0-9_]{1,30}")


def id_flujo(zona_origen: str, zona_destino: str, servicio: str) -> str:
    h = hashlib.sha256(f"{zona_origen}|{zona_destino}|{servicio}".encode()).hexdigest()
    return "FL-" + h[:8]


def _etiqueta_valida(x) -> bool:
    return isinstance(x, str) and 1 <= len(x) <= 30 and x == x.strip() and "\n" not in x and "\r" not in x


def validar(v, fallo, objeto) -> dict:
    """Normaliza la clave de perfil `allowlist_tobe`."""
    from .tobe import COLUMNAS

    v = objeto(v, CLAVE, ("decisiones", "decisiones_equipo", "columnas_equipo"))
    dec = {d: d for d in CLAVES_DECISION}
    if "decisiones" in v:
        d = v["decisiones"]
        if not isinstance(d, dict) or set(d) != set(CLAVES_DECISION):
            fallo("'allowlist_tobe.decisiones' debe ser un objeto con las cuatro claves: "
                  + ", ".join(f'"{k}"' for k in CLAVES_DECISION) + ".")
        for k in CLAVES_DECISION:
            if not _etiqueta_valida(d[k]):
                fallo(f"'allowlist_tobe.decisiones.{k}': la etiqueta es un texto de 1 a 30 caracteres, "
                      "sin saltos de linea ni espacios en los extremos.")
        dec = {k: d[k] for k in CLAVES_DECISION}
    equipo = []
    for k in CLAVES_DECISION:
        if dec[k] not in equipo:
            equipo.append(dec[k])
    if "decisiones_equipo" in v:
        equipo = v["decisiones_equipo"]
        if not isinstance(equipo, list) or not 2 <= len(equipo) <= 8:
            fallo("'allowlist_tobe.decisiones_equipo' debe ser una lista de 2 a 8 textos.")
        for x in equipo:
            if not _etiqueta_valida(x):
                fallo("'allowlist_tobe.decisiones_equipo': cada etiqueta es un texto de 1 a 30 caracteres, "
                      "sin saltos de linea ni espacios en los extremos.")
        if len(set(equipo)) != len(equipo):
            fallo("'allowlist_tobe.decisiones_equipo' tiene etiquetas repetidas.")
    elif not 2 <= len(equipo) <= 8:
        fallo("'allowlist_tobe.decisiones_equipo': con las etiquetas de 'decisiones' queda menos de 2 etiquetas "
              "distintas; declare 'decisiones_equipo' (2 a 8).")
    cols = list(COLUMNAS_DEFECTO)
    if "columnas_equipo" in v:
        cols = v["columnas_equipo"]
        if not isinstance(cols, list) or not 1 <= len(cols) <= 10:
            fallo("'allowlist_tobe.columnas_equipo' debe ser una lista de 1 a 10 nombres.")
        for x in cols:
            if not isinstance(x, str) or not _NOMBRE_COL.fullmatch(x):
                fallo(f"allowlist_tobe.columnas_equipo: {x!r} no es un nombre valido "
                      "(minusculas a-z, digitos y _, de 1 a 30 caracteres).")
        if len(set(cols)) != len(cols):
            fallo("'allowlist_tobe.columnas_equipo' tiene nombres repetidos.")
    for x in cols:
        if x in COLUMNAS or x in COL_NUEVAS:
            fallo(f"'allowlist_tobe.columnas_equipo': {x!r} choca con una columna de allowlist_tobe.csv.")
    return {"decisiones": dec, "decisiones_equipo": list(equipo), "columnas_equipo": list(cols),
            "propias": "decisiones" in v, "equipo_propias": "decisiones_equipo" in v or "decisiones" in v}


def defecto() -> dict:
    return {"decisiones": {d: d for d in CLAVES_DECISION}, "decisiones_equipo": list(CLAVES_DECISION),
            "columnas_equipo": list(COLUMNAS_DEFECTO), "propias": False, "equipo_propias": False}


# ---- lectura del archivo del equipo ---------------------------------------------------------------------

def _alias(col: str) -> tuple:
    return (col, catalogo("en").get(col, col))


def _canon_decision(valor: str, cfg: dict):
    lista = cfg["decisiones_equipo"]
    if valor in lista:
        return valor
    if not cfg["equipo_propias"]:
        en = catalogo("en")
        for es in lista:
            if en.get(es) == valor:
                return es
    return None


def leer(ruta, cfg: dict) -> dict:
    """{id_flujo: {zona_origen, zona_destino, servicio, decision_equipo, columnas del equipo, revision}} en el orden
    del archivo. ValueError si el archivo no sirve."""
    p = Path(ruta)
    try:
        if p.stat().st_size > MAX_BYTES:
            raise ValueError(t("'{a}' pesa mas de 20 MB.", a=p.name))
        texto = p.read_bytes().decode("utf-8-sig")
    except (OSError, UnicodeDecodeError) as e:
        raise ValueError(t("No pude leer '{a}': {e}", a=p.name, e=str(e)))
    cab = texto.split("\n", 1)[0]
    sep = ";" if cab.count(";") > cab.count(",") else ","
    out: dict = {}
    try:
        lector = csv.reader(io.StringIO(texto), delimiter=sep)
        cols = [c.strip() for c in (next(lector, None) or [])]
        idx = {}
        for c in (COL_ID, "zona_origen", "zona_destino", "servicio", COL_DECISION_EQUIPO, *cfg["columnas_equipo"],
                  *COL_REVISION):
            hay = [cols.index(a) for a in _alias(c) if a in cols]
            if hay:
                idx[c] = hay[0]
        if COL_ID not in idx and not all(c in idx for c in ("zona_origen", "zona_destino", "servicio")):
            raise ValueError(t("'{a}' no tiene la columna id_flujo ni zona_origen, zona_destino y servicio.",
                               a=p.name))
        n = 0
        for fila in lector:
            if not any(c.strip() for c in fila):
                continue
            n += 1
            if n > MAX_FILAS:
                raise ValueError(t("'{a}' tiene mas de {n} filas.", a=p.name, n=MAX_FILAS))
            cel = {c: (fila[i] if i < len(fila) else "").strip() for c, i in idx.items()}
            zonas = [cel.get(c, "") for c in ("zona_origen", "zona_destino", "servicio")]
            ident = cel.get(COL_ID) or (id_flujo(*zonas) if all(zonas) else "")
            if not ident:
                continue
            if ident in out:
                raise ValueError(t("id repetido en '{a}': {i}.", a=p.name, i=ident))
            for c, v in cel.items():
                if len(v) > MAX_TEXTO:
                    raise ValueError(t("Texto de mas de 500 caracteres en el id {i} de '{a}'.", i=ident, a=p.name))
            reg = {"zona_origen": zonas[0], "zona_destino": zonas[1], "servicio": zonas[2]}
            v = cel.get(COL_DECISION_EQUIPO, "")
            if v:
                canon = _canon_decision(v, cfg)
                if canon is None:
                    raise ValueError(t("decision_equipo no permitida '{e}' en el id {i}. Permitidas: {l}.",
                                       e=v, i=ident, l=", ".join(cfg["decisiones_equipo"])))
                v = canon
            reg[COL_DECISION_EQUIPO] = v
            for c in (*cfg["columnas_equipo"], *COL_REVISION):
                reg[c] = cel.get(c, "")
            out[ident] = reg
    except csv.Error as e:
        raise ValueError(t("'{a}' no es un CSV valido: {e}", a=p.name, e=str(e)))
    return out


# ---- plan y opcion --------------------------------------------------------------------------------------

class Plan:
    def __init__(self, cfg: dict, previos: dict):
        self.cfg = cfg
        self.previos = previos


def de_args(args):
    return getattr(args, ATRIBUTO, None)


def leer_opcion(ap, args, perfil) -> None:
    """Lee --allowlist-revision antes de crear salidas (codigo 2 si no sirve) y deja el plan en args."""
    cfg = (perfil or {}).get(CLAVE)
    ruta = getattr(args, "allowlist_revision", None)
    setattr(args, ATRIBUTO, None)
    if cfg is None and not ruta:
        return
    cfg = cfg or defecto()
    previos: dict = {}
    if ruta:
        try:
            previos = leer(ruta, cfg)
        except ValueError as e:
            ap.error(str(e))
    setattr(args, ATRIBUTO, Plan(cfg, previos))


# ---- combinacion con la allowlist -----------------------------------------------------------------------

def combinar(tobe: dict, plan) -> list:
    """Deja en tobe["allowlist_proyecto"] el plan y los flujos del archivo no observados; devuelve avisos."""
    if plan is None:
        return []
    if not tobe.get("filas"):
        if not plan.previos:
            return []
        # sin flujos observados entre zonas: la allowlist lleva solo los del archivo (no observados) para no perderlos
        tobe["allowlist_proyecto"] = {"cfg": plan.cfg, "previos": plan.previos,
                                      "no_observados": list(plan.previos.items())}
        return [t("--allowlist-revision: sin comunicacion observada entre zonas; la allowlist lleva solo los {n} "
                  "flujos del archivo, como no observados.", n=len(plan.previos))]
    vistos = {id_flujo(f["zona_origen"], f["zona_destino"], f["servicio"]) for f in tobe["filas"]}
    sobran = [(k, r) for k, r in plan.previos.items() if k not in vistos]
    tobe["allowlist_proyecto"] = {"cfg": plan.cfg, "previos": plan.previos, "no_observados": sobran}
    if sobran:
        return [t("--allowlist-revision: {n} flujos del archivo no se observaron en esta corrida; se conservan al "
                  "final de allowlist_tobe.csv.", n=len(sobran))]
    return []


def _etiqueta(cfg: dict, decision: str) -> str:
    return cfg["decisiones"][decision] if cfg["propias"] else t(decision)


def _decision_equipo(cfg: dict, valor: str) -> str:
    return t(valor) if valor and not cfg["equipo_propias"] else valor


def cabecera(cfg: dict) -> list:
    return [COL_ID, COL_PROYECTO, COL_DECISION_EQUIPO, *(Traducido(c) for c in cfg["columnas_equipo"]), COL_OBSERVADO]


def tabla(tobe: dict, cab_base: list, filas_base: list) -> tuple:
    """(cabecera, filas) de allowlist_tobe.csv con las columnas del proyecto; los no observados van al final."""
    ap = tobe["allowlist_proyecto"]
    cfg, previos = ap["cfg"], ap["previos"]
    pos = {c: cab_base.index(c) for c in COL_REVISION}

    def extras(ident: str, etiqueta: str, obs: str, reg: dict) -> list:
        return [ident, etiqueta, _decision_equipo(cfg, reg.get(COL_DECISION_EQUIPO, "")),
                *(reg.get(c, "") for c in cfg["columnas_equipo"]), t(obs)]

    filas = []
    for f, base in zip(tobe["filas"], filas_base):
        ident = id_flujo(f["zona_origen"], f["zona_destino"], f["servicio"])
        reg = previos.get(ident, {})
        fila = list(base)
        for c in COL_REVISION:
            fila[pos[c]] = reg.get(c, "")
        filas.append(fila + extras(ident, _etiqueta(cfg, f["decision"]), "si", reg))
    for ident, reg in ap["no_observados"]:
        fila = [""] * len(cab_base)
        for c in ("zona_origen", "zona_destino", "servicio", *COL_REVISION):
            fila[cab_base.index(c)] = reg.get(c, "")
        filas.append(fila + extras(ident, "", "no", reg))
    return list(cab_base) + cabecera(cfg), filas


def _contar(etiquetas: list, valores: list) -> dict:
    return {e: sum(1 for v in valores if v == e) for e in etiquetas}


def resumen(tobe: dict) -> dict:
    """Conteos de la funcion: por decision del proyecto (observados), por decision del equipo y pendientes."""
    ap = tobe["allowlist_proyecto"]
    cfg, previos = ap["cfg"], ap["previos"]
    etiquetas = []
    for k in CLAVES_DECISION:
        if cfg["decisiones"][k] not in etiquetas:
            etiquetas.append(cfg["decisiones"][k])
    del_equipo = []
    for f in tobe["filas"]:
        ident = id_flujo(f["zona_origen"], f["zona_destino"], f["servicio"])
        del_equipo.append(previos.get(ident, {}).get(COL_DECISION_EQUIPO, ""))
    del_equipo += [r.get(COL_DECISION_EQUIPO, "") for _k, r in ap["no_observados"]]
    return {"por_decision_proyecto": _contar(etiquetas, [cfg["decisiones"][f["decision"]] for f in tobe["filas"]]),
            "por_decision_equipo": _contar(cfg["decisiones_equipo"], del_equipo),
            "pendientes": sum(1 for v in del_equipo if not v), "no_observados": len(ap["no_observados"])}


def _lista(c: dict, traducir: bool) -> str:
    return ", ".join(f"{t(k) if traducir else k} {n}" for k, n in c.items())


def frase(tobe: dict) -> str:
    r, cfg = resumen(tobe), tobe["allowlist_proyecto"]["cfg"]
    return t("Decision del proyecto: {a}. Decision del equipo: {b}; pendientes {p}. Flujos declarados por el "
             "equipo y no observados: {n}.", a=_lista(r["por_decision_proyecto"], not cfg["propias"]),
             b=_lista(r["por_decision_equipo"], not cfg["equipo_propias"]),
             p=r["pendientes"], n=r["no_observados"])


def para_json(tobe: dict) -> dict:
    return resumen(tobe)
