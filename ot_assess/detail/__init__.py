"""Pase 2: identidad, texto claro, operaciones de control y anomalias L2.

Para agregar un tema nuevo: un modulo con una funcion @COLLECTORS e importarlo abajo.
"""
from __future__ import annotations

from ..model import Capture
from ..tools import Tshark
from .base import COLLECTORS, RowCtx

# El orden de estas importaciones es el orden de ejecucion por paquete.
from . import identity, cleartext, control, l2, dns, protocolos  # noqa: F401,E402,I001


def analyze_detail(ts: Tshark, cap: Capture, fields: list[str], dfilter: str) -> None:
    idx = {f: i for i, f in enumerate(fields)}
    for row in ts.fields_pass(cap.path, fields, dfilter, 0):
        rc = RowCtx(cap, row, idx)
        for collect in COLLECTORS:
            collect(rc)
