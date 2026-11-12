"""CV4E (D120): puntuacion CVSS v4.0 de entorno (CR/IR/AR) desde la criticidad declarada de los activos.

Informativa: no cambia severidad, estado, hallazgos, riesgo ni priorizacion. La tabla nivel -> CR/IR/AR esta
en marcos/cvss4_requisitos.json ("sin revisar"). Sin red.
"""
from __future__ import annotations

import functools
import json
from pathlib import Path

from . import cvss4
from .catalog import CRIT_ORDER
from .i18n import t

RUTA = Path(__file__).parent / "marcos" / "cvss4_requisitos.json"
COLUMNAS = ["cvss_v4_entorno", "vector_cvss_v4_entorno"]
NOTA = ("Puntuacion CVSS v4.0 de entorno (cvss_v4_entorno): sale de la criticidad declarada en el perfil con una "
        "tabla sin revisar (Security Requirements CR/IR/AR); es informativa y no reemplaza a la base.")


@functools.lru_cache(maxsize=1)
def _niveles() -> dict:
    return json.loads(RUTA.read_text(encoding="utf-8"))["niveles"]


def _nivel_fila(ips, crit: dict):
    """Nivel mas critico (segun CRIT_ORDER) declarado para alguna de las IP (texto separado por ';' o lista)."""
    if isinstance(ips, str):
        ips = ips.split(";")
    niveles = [crit[ip] for ip in (str(i).strip() for i in ips or ()) if ip in crit]
    return min(niveles, key=lambda n: CRIT_ORDER[n]) if niveles else None


def entorno(vector, ips, crit) -> tuple:
    """(puntuacion, vector de entorno) o ("", "") sin vector v4 valido o sin criticidad declarada."""
    nivel = _nivel_fila(ips, crit or {})
    if not nivel or not vector:
        return "", ""
    try:
        sel = cvss4.parsear(vector)
    except ValueError:
        return "", ""
    req = _niveles()[nivel]
    sel.update(req)
    vec = cvss4.PREFIJO + "/".join(f"{k}:{v}" for k, v in _en_orden(sel))
    return cvss4.puntuar(vec), vec


def _en_orden(sel: dict):
    """Metricas en el orden de cvss4 (base, luego opcionales), sin las 'X'."""
    for k in cvss4._VALIDOS:
        if k in sel and (sel[k] != "X" or k in cvss4._BASE):
            yield k, sel[k]


def hay(pares) -> bool:
    """True si algun par (puntuacion, vector) obtuvo puntuacion."""
    return any(p != "" for p, _v in pares)


def nota() -> str:
    return t(NOTA)
