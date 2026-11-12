"""reporte_ot.xlsx: las mismas tablas que los CSV (sin detalle por captura), una hoja por tabla."""
from __future__ import annotations

from pathlib import Path

from .. import riesgo as _rg
from ..model import Assessment
from .csvout import cabecera_t, nombre_hoja, tablas
from .xlsx import RELLENO, escribir_xlsx


def _relleno(m: dict, nivel: str) -> str:
    """Estilo de la celda: el predefinido para los niveles por defecto; el color RRGGBB para los del proyecto."""
    if m["propio_niveles"]:
        return {n: c for n, _, c in m["niveles"]}.get(nivel, "")
    return RELLENO.get(nivel, "")


def write_xlsx(res: Assessment, outdir: Path) -> Path:
    hojas = [(nombre_hoja(hoja), cabecera_t(res, cab), filas) for _, hoja, cab, filas in tablas(res) if hoja]
    r = _rg.de(res)
    if _rg.hay(r):       # R1: el mapa de calor va como cuadricula con color por nivel
        cab, filas, niveles = _rg.cuadricula(r)
        hojas.append((nombre_hoja(_rg.HOJA_MAPA), cab, filas,
                      [[_relleno(r["metodo"], n) if n else "" for n in fila] for fila in niveles]))
    for hoja, cab, filas, niveles in _rg.valoraciones_xlsx(r):      # RM2b (D130)
        if niveles is None:
            hojas.append((nombre_hoja(hoja), cab, filas))
        else:
            hojas.append((nombre_hoja(hoja), cab, filas,
                          [[_relleno(r["metodo"], n) if n else "" for n in fila] for fila in niveles]))
    return escribir_xlsx(outdir / "reporte_ot.xlsx", hojas)
