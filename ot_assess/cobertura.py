"""Matriz de cobertura por marco: que requisitos pueden tener evidencia en el trafico.

Los datos viven en `ot_assess/marcos/cobertura/<clave>.json` (lista oficial de requisitos y
el texto de apoyo de las salidas de la herramienta). La clasificacion se CALCULA, no se
almacena:
  directa          el id aparece en alguna referencia del marco (un hallazgo puede citarlo)
  apoyo            no es directa, pero esta en `apoyo` (lo respaldan salidas de la herramienta)
  no evidenciable  el resto
Es una relacion con evidencia de trafico, no una evaluacion de cumplimiento.
"""
from __future__ import annotations

import json
import re

from .i18n import t
from .standards import DIR_MARCOS, ESTANDARES

DIR_COBERTURA = DIR_MARCOS / "cobertura"
_CAMPOS = {"marco", "fuente", "patron", "categorias", "apoyo", "requisitos", "idioma_textos"}
DIRECTA, APOYO, NO_EVID = "directa", "apoyo", "no evidenciable"
TEXTO_NO_EVID = "No evidenciable con analisis pasivo de trafico"
NOTA = ("La cobertura indica que requisitos pueden relacionarse con evidencia de trafico; "
        "no es una evaluacion de cumplimiento. Texto de los requisitos: fuente oficial en ingles.")
NOTAS_MARCO = {"iec62443": "Identificadores y parafrasis de IEC 62443-3-3:2013; "
                           "falta cotejarlos con el texto de la norma."}


def cargar(clave: str):
    """dict validado, o None si el marco no tiene archivo de cobertura."""
    p = DIR_COBERTURA / f"{clave}.json"
    if not p.is_file():
        return None
    return validar(json.loads(p.read_text(encoding="utf-8")), p.name)


def validar(d, origen: str) -> dict:
    def fallo(msg):
        raise SystemExit(f"[!] cobertura '{origen}': {msg}")

    if not isinstance(d, dict):
        fallo("debe ser un objeto JSON.")
    for k in sorted(_CAMPOS - set(d)):
        fallo(f"falta el campo '{k}'.")
    desconocidas = sorted(set(d) - _CAMPOS)
    if desconocidas:
        fallo(f"campos desconocidos: {', '.join(desconocidas)}.")
    if d["idioma_textos"] not in ("en", "es"):
        fallo("'idioma_textos' debe ser 'en' o 'es' (idioma de los textos de requisitos y categorias).")
    if not isinstance(d["categorias"], dict) or not isinstance(d["apoyo"], dict):
        fallo("'categorias' y 'apoyo' deben ser objetos.")
    if not isinstance(d["requisitos"], list) or not d["requisitos"]:
        fallo("'requisitos' debe ser una lista no vacia.")
    try:
        re.compile(d["patron"])
    except (re.error, TypeError):
        fallo("'patron' debe ser una regex que compile.")
    ids = []
    for r in d["requisitos"]:
        if not (isinstance(r, dict) and {"id", "texto"} <= set(r) <= {"id", "texto", "grupo"}
                and all(isinstance(v, str) for v in r.values())):
            fallo("cada requisito debe ser {id, texto[, grupo]} de texto.")
        if "grupo" in r and r["grupo"] not in d["categorias"]:
            fallo(f"requisito {r['id']}: grupo '{r['grupo']}' no existe en 'categorias'.")
        ids.append(r["id"])
    repetidos = sorted({i for i in ids if ids.count(i) > 1})
    if repetidos:
        fallo(f"ids repetidos: {', '.join(repetidos)}.")
    inexistentes = sorted(set(d["apoyo"]) - set(ids))
    if inexistentes:
        fallo(f"'apoyo' cita ids que no existen en 'requisitos': {', '.join(inexistentes)}.")
    return d


def patron_ids(cob: dict):
    """Regex que extrae ids del marco, segun el campo 'patron' del archivo."""
    return re.compile(r"(?<![A-Za-z0-9])(?:" + cob["patron"] + r")(?!\d)")


def ids_citados(texto: str, cob: dict) -> set:
    return {m.group(0) for m in patron_ids(cob).finditer(texto or "")}


def _texto(cob: dict, txt: str) -> str:
    """Texto de requisito o categoria al idioma del reporte: solo se traduce si el archivo lo trae en espanol."""
    return t(txt) if cob["idioma_textos"] == "es" else txt


def clasificar(cob: dict, estandar) -> list:
    """Una fila por requisito, en el orden del archivo (sin datos de la corrida).

    `texto` y `categoria` salen en el idioma del reporte; `cobertura` y `apoyo` quedan en la
    clave en espanol (el JSON y el resumen la usan) y el reporte los pasa por t()."""
    citas: dict = {}
    for frag, txt in estandar.refs.items():
        for i in sorted(ids_citados(txt, cob)):
            citas.setdefault(i, []).append(frag)
    filas = []
    for r in cob["requisitos"]:
        i = r["id"]
        if i in citas:
            tipo, apoyo = DIRECTA, ""
        elif i in cob["apoyo"]:
            tipo, apoyo = APOYO, cob["apoyo"][i]
        else:
            tipo, apoyo = NO_EVID, TEXTO_NO_EVID
        g = r.get("grupo")
        filas.append({"id": i, "grupo": g or i.split(".")[0],
                      "categoria": _texto(cob, cob["categorias"].get(g or i.split("-")[0], "")),
                      "texto": _texto(cob, r["texto"]), "cobertura": tipo, "apoyo": apoyo,
                      "fragmentos": [t(x) for x in citas.get(i, [])], "hallazgos": 0})
    return filas


def hallazgos_por_id(findings, clave: str, cob: dict) -> dict:
    """{id: hallazgos de la corrida que lo citan}, contando hallazgos agrupados como el reporte."""
    grupos = {(f["titulo"], f["severidad"]): f["referencias"].get(clave, "") for f in findings}
    cuenta: dict = {}
    for txt in grupos.values():
        for i in ids_citados(txt, cob):
            cuenta[i] = cuenta.get(i, 0) + 1
    return cuenta


def resumen(filas: list) -> dict:
    out: dict = {}
    for f in filas:
        s = out.setdefault(f["grupo"], {"total": 0, DIRECTA: 0, APOYO: 0, NO_EVID: 0})
        s["total"] += 1
        s[f["cobertura"]] += 1
    return out


def de_corrida(res) -> list:
    """[(Estandar, filas, resumen)] para los marcos elegidos que tienen archivo de cobertura."""
    findings = [f for c in [*res.caps, *res.extras] for f in c.findings]
    out = []
    for e in res.estandares or [ESTANDARES["iec62443"]]:
        cob = cargar(e.clave)
        if cob is None:
            continue
        filas = clasificar(cob, e)
        cuenta = hallazgos_por_id(findings, e.clave, cob)
        for f in filas:
            f["hallazgos"] = cuenta.get(f["id"], 0)
        out.append((e, filas, resumen(filas)))
    return out
