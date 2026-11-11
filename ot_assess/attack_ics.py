"""Catalogo compacto de MITRE ATT&CK for ICS (D112): ids, nombres y tacticas vigentes.

Se genera con scripts/actualizar_attack_ics.py desde el STIX oficial de MITRE; no trae descripciones.
Sirve para que ningun mapeo cite un id revocado u obsoleto.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

RUTA = Path(__file__).parent / "marcos" / "attack_ics.json"


@lru_cache(maxsize=1)
def cargar() -> dict:
    return json.loads(RUTA.read_text(encoding="utf-8"))


def version() -> str:
    return cargar()["version"]


def vigente(tid: str) -> bool:
    return tid in cargar()["tecnicas"]


def nombre(tid: str) -> str:
    return cargar()["tecnicas"].get(tid, {}).get("nombre", "")


def tacticas(tid: str) -> list:
    """Nombres de tactica de la tecnica, en el orden de la matriz."""
    cat = cargar()
    cortos = cat["tecnicas"].get(tid, {}).get("tacticas", [])
    return [t["nombre"] for t in cat["tacticas"] if t["id"] in cortos]


def reemplazo(tid: str) -> str:
    """Id que sustituye a una tecnica revocada; cadena vacia si no esta revocada."""
    return cargar()["revocadas"].get(tid, {}).get("por", "")
