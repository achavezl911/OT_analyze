"""Marcos de referencia a los que se mapean los hallazgos.

Cada hallazgo lleva una referencia por marco (MITRE ATT&CK for ICS siempre; los demas
segun --estandar). El mapeo es ORIENTATIVO: relaciona el hallazgo con el requisito mas
cercano, no determina cumplimiento ni incumplimiento.

Los marcos son datos: un JSON por marco en `ot_assess/marcos/` (mismo formato que
--estandar-archivo, ver `cargar_archivo`). Para ajustar un mapeo existente se edita su
JSON; para agregar un marco, un archivo nuevo.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import json_entrada
from .i18n import t, unir

DIR_MARCOS = Path(__file__).parent / "marcos"
SIN_DECLARAR = "sin declarar"
_ESTADOS = ("sin revisar", "revisado")
_CAMPOS = {"clave", "nombre", "cruce", "alcance", "fuente", "version_fuente", "validacion", "referencias"}
_CAMPOS_VALIDACION = {"estado", "por", "fecha"}


@dataclass
class Estandar:
    clave: str                   # la que se pasa en --estandar
    nombre: str                  # como se muestra en el reporte
    cruce: str = ""              # complemento de "los conductos que cruzan zonas son ..."
    alcance: str = ""            # aviso de alcance que acompana a las referencias
    refs: dict = field(default_factory=dict)    # fragmento del titulo (minusculas) -> texto
    fuente: str = SIN_DECLARAR           # norma o catalogo de donde salen las referencias
    version_fuente: str = SIN_DECLARAR   # edicion de la fuente en que se basa el mapeo
    validacion: dict = field(default_factory=lambda: {"estado": "sin revisar"})


def _desde_dict(d, origen: str) -> Estandar:
    """Valida un marco (incluido o propio) y lo construye. Error legible con SystemExit."""
    def fallo(msg):
        raise SystemExit(f"[!] '{origen}': {msg}")

    if not isinstance(d, dict):
        fallo("el marco debe ser un objeto JSON.")
    for k in ("clave", "nombre", "referencias"):
        if k not in d:
            fallo(f"falta el campo '{k}'.")
    desconocidas = sorted(set(d) - _CAMPOS)
    if desconocidas:
        fallo(f"campos desconocidos: {', '.join(desconocidas)}.")
    if not isinstance(d["clave"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", d["clave"]):
        fallo("'clave' solo admite minusculas, digitos, '-' y '_'.")
    if not isinstance(d["referencias"], dict):
        fallo("'referencias' debe ser un objeto fragmento -> texto.")
    for k in ("nombre", "cruce", "alcance", "fuente", "version_fuente"):
        if k in d and not isinstance(d[k], str):
            fallo(f"'{k}' debe ser texto.")
    val = d.get("validacion", {"estado": "sin revisar"})
    if not isinstance(val, dict):
        fallo("'validacion' debe ser un objeto.")
    desconocidas = sorted(set(val) - _CAMPOS_VALIDACION)
    if desconocidas:
        fallo(f"campos desconocidos en 'validacion': {', '.join(desconocidas)}.")
    estado = val.get("estado")
    if estado not in _ESTADOS:
        fallo(f"validacion.estado debe ser uno de: {', '.join(_ESTADOS)}.")
    if estado == "revisado":
        if not isinstance(val.get("por"), str) or not val["por"].strip():
            fallo("validacion 'revisado' exige 'por'.")
        fecha = val.get("fecha")
        if not isinstance(fecha, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", fecha):
            fallo("validacion 'revisado' exige 'fecha' con formato AAAA-MM-DD.")
    return Estandar(d["clave"], d["nombre"], d.get("cruce", ""), d.get("alcance", ""),
                    {str(k).lower(): str(v) for k, v in d["referencias"].items()},
                    d.get("fuente", SIN_DECLARAR), d.get("version_fuente", SIN_DECLARAR),
                    {"estado": estado, **{k: val[k] for k in ("por", "fecha") if k in val}})


def _incluido(clave: str) -> Estandar:
    p = DIR_MARCOS / f"{clave}.json"
    return _desde_dict(json.loads(p.read_text(encoding="utf-8")), p.name)


# MITRE aparece siempre y no se elige; los demas se eligen con --estandar (el orden fija
# las columnas del reporte y el catalogo).
MITRE = _incluido("mitre-ics")
ESTANDARES: dict = {c: _incluido(c) for c in ("iec62443", "nerc-cip", "nist-800-82", "nist-csf")}


def linea_fuente(e: Estandar) -> str:
    """Linea ASCII de procedencia y validacion del mapeo, junto al aviso de alcance."""
    return t("Fuente: {fuente}. Version: {version}. Validacion del mapeo: {estado}.",
             fuente=t(e.fuente), version=t(e.version_fuente), estado=_estado(e))


def _estado(e: Estandar) -> str:
    v = e.validacion
    if v["estado"] == "revisado":
        return t("revisado por {por}, {fecha}", por=v["por"], fecha=v["fecha"])
    return t(v["estado"])


def etiqueta_mapeo(e: Estandar) -> str:
    """Complemento de la linea 'Marco <clave>' del perfil."""
    return t("mapeo basado en {version} ({estado})", version=t(e.version_fuente), estado=_estado(e))


def avisos(estandares) -> list:
    """Avisos de alcance de los marcos elegidos, cada uno con su linea de fuente."""
    return [f"{t(e.alcance)} {linea_fuente(e)}" for e in estandares if e.alcance]


def traducir_refs(txt: str) -> str:
    """Referencias de un marco (piezas separadas por '; ') traducidas pieza por pieza."""
    return unir("; ", [t(p) for p in txt.split("; ")]) if txt else txt


def referencias(titulo: str) -> dict:
    """{clave del marco: referencia} para un hallazgo. Solo incluye los marcos con texto."""
    t = titulo.lower()
    out = {}
    for e in (MITRE, *ESTANDARES.values()):
        for frag, txt in e.refs.items():
            if frag in t:
                if txt:
                    out[e.clave] = txt
                break
    return out


def elegir(claves: str) -> list:
    """'iec62443,nerc-cip' -> [Estandar, Estandar]. El primero es el de referencia del reporte."""
    out = []
    for c in (x.strip().lower() for x in claves.split(",") if x.strip()):
        if c not in ESTANDARES:
            raise SystemExit(f"[!] Estandar desconocido: '{c}'. Disponibles: {', '.join(ESTANDARES)}")
        if ESTANDARES[c] not in out:
            out.append(ESTANDARES[c])
    if not out:
        raise SystemExit("[!] --estandar no puede estar vacio.")
    return out


def cargar_archivo(path: str) -> Estandar:
    """Registra un marco propio desde un JSON (el mismo formato de ot_assess/marcos/):

        {"clave": "mi-norma", "nombre": "Norma tecnica X",
         "cruce": "como puntos de control entre zonas segun la norma X",   (opcional)
         "alcance": "Aviso de alcance...",                                 (opcional)
         "fuente": "Norma X, capitulo 4",                                  (opcional)
         "version_fuente": "Norma X:2020",                                 (opcional)
         "validacion": {"estado": "sin revisar"},                          (opcional)
         "referencias": {"texto del titulo": "Art. 12; Art. 14", ...}}

    Sin "fuente" ni "version_fuente" se rotulan "sin declarar"; sin "validacion", "sin revisar".
    "validacion.estado" es "sin revisar" o "revisado"; "revisado" exige "por" y "fecha"
    (AAAA-MM-DD). Cada clave de "referencias" es un fragmento (sin importar mayusculas) del
    titulo del hallazgo; ver los titulos en hallazgos.csv.
    """
    try:
        d = json_entrada.cargar(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as e:
        raise SystemExit(f"[!] No pude leer el estandar '{path}': {e}")
    e = _desde_dict(d, path)
    if e.clave in ESTANDARES or e.clave == MITRE.clave:
        raise SystemExit(f"[!] '{path}': la clave '{e.clave}' ya existe.")
    ESTANDARES[e.clave] = e
    return e
