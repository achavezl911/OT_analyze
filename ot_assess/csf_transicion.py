"""Transicion oficial de NIST CSF 1.1 a 2.0 (D116): catalogo y hoja con los hallazgos de la corrida.

El catalogo (marcos/csf_transicion.json) se genera con scripts/actualizar_csf_transicion.py desde la hoja
oficial de NIST. Los hallazgos solo se cuentan contra el id 2.0 de cada fila; el mapeo hallazgo -> CSF 2.0
sigue sin revisar. No es un perfil ni una evaluacion de CSF. Los textos oficiales y los valores de
reubicacion quedan en ingles en ambos idiomas.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from .i18n import t

RUTA = Path(__file__).parent / "marcos" / "csf_transicion.json"
HOJA = "CSF 1.1 a 2.0"
ARCHIVO = "csf_transicion.csv"
COLUMNAS = ["csf11", "descripcion_csf11", "reubicacion", "modificaciones", "csf20", "descripcion_csf20",
            "nueva_en_csf20", "hallazgos_en_esta_corrida", "titulos"]
# Categoria (GV.OC) o subcategoria (GV.OC-01); una no cuenta como la otra.
ID = re.compile(r"(?<![A-Za-z0-9])(?:GV|ID|PR|DE|RS|RC)\.[A-Z]{2}(?:-\d{2})?(?![A-Za-z0-9]|-\d)")


@lru_cache(maxsize=1)
def cargar() -> dict:
    return json.loads(RUTA.read_text(encoding="utf-8"))


def pasos(id_11: str) -> list:
    """Ids 2.0 a los que paso un elemento 1.1, en el orden del archivo oficial."""
    return [f["id_20"] for f in cargar()["filas"] if f["id_11"] == id_11]


def filas(findings) -> list:
    """Una fila por fila del catalogo; los hallazgos se agrupan por (titulo, severidad) como el reporte."""
    grupos = {(f["titulo"], f["severidad"]): f["referencias"].get("nist-csf", "") for f in findings}
    cuenta: dict = {}
    titulos: dict = {}
    for (titulo, _sev), txt in grupos.items():
        for i in set(ID.findall(txt or "")):
            cuenta[i] = cuenta.get(i, 0) + 1
            titulos.setdefault(i, set()).add(t(titulo))
    return [[f["id_11"], f["descripcion_11"], f["reubicacion"], f["modificaciones"], f["id_20"],
             f["descripcion_20"], f["nueva_en_20"], cuenta.get(f["id_20"], 0),
             "; ".join(sorted(titulos.get(f["id_20"], ())))] for f in cargar()["filas"]]


def tablas(findings, estandares) -> list:
    """Solo si la corrida incluye nist-csf entre sus estandares."""
    if not any(e.clave == "nist-csf" for e in estandares):
        return []
    return [(ARCHIVO, HOJA, COLUMNAS, filas(findings))]
