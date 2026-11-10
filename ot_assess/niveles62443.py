"""Catalogo de requisitos y niveles de seguridad de ISA/IEC 62443 (D75).

Lee `marcos/iec62443_niveles.json`, generado por `scripts/extraer_niveles_62443.py`
a partir de los textos de las normas (que no se versionan). Contiene ids, listas
por nivel SL, secciones y titulos propios en es/en. No afirma cumplimiento.
Base de la linea base as-is/to-be (B7b).
"""
import json
from functools import lru_cache
from pathlib import Path

RUTA = Path(__file__).parent / "marcos" / "iec62443_niveles.json"
NIVELES = ("1", "2", "3", "4")


@lru_cache(maxsize=1)
def cargar() -> dict:
    return json.loads(RUTA.read_text(encoding="utf-8"))


def requisitos_sl(sr: str, nivel: int) -> list:
    """SR y RE que la 3-3 asocia a `sr` en el nivel SL-C `nivel` (1-4); vacia si no aplica."""
    return list(cargar()["sr"][sr]["sl"][str(nivel)])


def titulo(ident: str, idioma: str = "es") -> str:
    """Titulo propio de un SR, RE, CR/xDR, ZCR o ML."""
    d = cargar()
    for seccion in ("sr", "re_sr", "componente", "re_componente", "zcr", "madurez"):
        if ident in d[seccion]:
            return d[seccion][ident]["titulo"][idioma]
    raise KeyError(ident)
