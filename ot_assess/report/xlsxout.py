"""reporte_ot.xlsx: las mismas tablas que los CSV (sin detalle por captura), una hoja por tabla."""
from __future__ import annotations

from pathlib import Path

from .. import riesgo as _rg
from ..model import Assessment
from .csvout import cabecera_t, nombre_hoja, tablas
from .xlsx import RELLENO, escribir_xlsx


def write_xlsx(res: Assessment, outdir: Path) -> Path:
    hojas = [(nombre_hoja(hoja), cabecera_t(res, cab), filas) for _, hoja, cab, filas in tablas(res) if hoja]
    r = _rg.de(res)
    if _rg.hay(r):       # R1: el mapa de calor va como cuadricula con color por nivel
        cab, filas, niveles = _rg.cuadricula(r)
        hojas.append((nombre_hoja(_rg.HOJA_MAPA), cab, filas,
                      [[RELLENO.get(n, "") if n else "" for n in fila] for fila in niveles]))
    return escribir_xlsx(outdir / "reporte_ot.xlsx", hojas)
