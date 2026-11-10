"""Escritores de reporte. Para agregar un formato: una funcion (Assessment, Path) -> Path
y una fila en ESCRITORES."""
from __future__ import annotations

from pathlib import Path

from ..model import Assessment
from ..resumen_ejecutivo import write_resumen
from .csvout import write_csvs
from .diagrams import write_diagrams
from .html import write_html
from .jsonout import write_json
from .md import write_md
from .word import write_docx
from .xlsxout import write_xlsx

ESCRITORES = [
    ("md", write_md),
    ("html", write_html),
    ("csv", write_csvs),
    ("xlsx", write_xlsx),
    ("docx", write_docx),
    ("json", write_json),
    ("diagramas", write_diagrams),
    ("resumen", write_resumen),
]


def write_all(res: Assessment, outdir: Path, omitir: tuple = ()) -> dict:
    """`omitir`: nombres de ESCRITORES que no se corren (el analisis de exportaciones ya escribio
    sus diagramas aparte)."""
    return {nombre: fn(res, outdir) for nombre, fn in ESCRITORES if nombre not in omitir}
