"""Playbooks de remediacion (P1a, D55): que hacer, en que orden, por plataforma, como verificar y revertir.

Son datos (un JSON por playbook en este directorio), no logica. Guia generica para OT que no sustituye el
procedimiento de cambios del cliente ni la documentacion del fabricante. Sin tshark: solo lee el plan.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..i18n import Traducido, t

DIR = Path(__file__).parent

PLATAFORMAS = ("Cisco FTD (FMC)", "FortiGate", "Windows / Active Directory", "Switch Cisco IOS/IOS-XE",
               "Claroty xDome", "PLC / RTU (generico)", "Linux")
CLAVES = ("id", "hallazgo", "objetivo", "prioridad_ot", "pasos", "por_plataforma", "verificacion",
          "reversion", "precauciones", "esfuerzo_estimado", "responsable", "referencias")
ESFUERZOS = ("bajo", "medio", "alto")
# (minimo, maximo) de elementos de cada lista
LONGITUDES = {"pasos": (4, 8), "verificacion": (2, 4), "reversion": (2, 4), "precauciones": (2, 6)}
POR_PLATAFORMA = (2, 6)

TITULO = "Playbooks de remediacion"
NOTA = ("Guia generica de remediacion para entornos OT, con las acciones en orden. No sustituye el procedimiento "
        "de cambios del cliente ni la documentacion del fabricante: cada accion se valida con operacion y se "
        "prueba antes de aplicarse. Un cambio reduce el riesgo; no lo anula.")
ETIQUETAS = ("Objetivo", "Que se rompe si se hace mal", "Pasos", "Por plataforma", "Verificacion", "Reversion",
             "Precauciones en OT", "Responsable", "Referencias")

_cache: dict = {}


def validar(pb, origen: str = "playbook", titulos=None) -> None:
    """Falla con ValueError y un mensaje claro si `pb` no cumple el formato. Con `titulos` (lista de titulos
    de hallazgo) exige ademas que `hallazgo` coincida con exactamente uno."""
    def fallo(msg):
        raise ValueError(f"{origen}: {msg}")

    if not isinstance(pb, dict):
        fallo("debe ser un objeto JSON")
    faltan = [c for c in CLAVES if c not in pb]
    sobran = [c for c in pb if c not in CLAVES]
    if faltan or sobran:
        fallo(f"claves invalidas (faltan: {', '.join(faltan) or '-'}; sobran: {', '.join(sobran) or '-'})")
    for c in ("id", "hallazgo", "objetivo", "prioridad_ot", "responsable"):
        if not isinstance(pb[c], str) or not pb[c].strip():
            fallo(f"'{c}' debe ser un texto no vacio")
    if pb["esfuerzo_estimado"] not in ESFUERZOS:
        fallo(f"'esfuerzo_estimado' debe ser uno de: {', '.join(ESFUERZOS)}")
    for c in ("pasos", "verificacion", "reversion", "precauciones", "referencias"):
        if not isinstance(pb[c], list) or not all(isinstance(x, str) and x.strip() for x in pb[c]):
            fallo(f"'{c}' debe ser una lista de textos no vacios")
    for c, (lo, hi) in LONGITUDES.items():
        if not lo <= len(pb[c]) <= hi:
            fallo(f"'{c}' debe tener entre {lo} y {hi} elementos (tiene {len(pb[c])})")
    pp = pb["por_plataforma"]
    if not isinstance(pp, dict) or not pp:
        fallo("'por_plataforma' debe ser un objeto con al menos una plataforma")
    for plat, pasos in pp.items():
        if plat not in PLATAFORMAS:
            fallo(f"plataforma no permitida '{plat}' (use: {', '.join(PLATAFORMAS)})")
        if not isinstance(pasos, list) or not all(isinstance(x, str) and x.strip() for x in pasos):
            fallo(f"'por_plataforma' de '{plat}' debe ser una lista de textos no vacios")
        if not POR_PLATAFORMA[0] <= len(pasos) <= POR_PLATAFORMA[1]:
            fallo(f"'{plat}' debe tener entre {POR_PLATAFORMA[0]} y {POR_PLATAFORMA[1]} pasos (tiene {len(pasos)})")
    if titulos is not None:
        n = sum(1 for x in titulos if pb["hallazgo"] in x)
        if n != 1:
            fallo(f"'hallazgo' ({pb['hallazgo']!r}) debe coincidir con exactamente un titulo de hallazgo "
                  f"(coincide con {n})")


def cargar() -> dict:
    """{id: playbook} de todos los JSON del directorio, validados, en orden de id."""
    if not _cache:
        out: dict = {}
        for p in sorted(DIR.glob("*.json")):
            try:
                pb = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError) as e:
                raise ValueError(f"{p.name}: no pude leerlo: {e}")
            validar(pb, p.name)
            if pb["id"] != p.stem:
                raise ValueError(f"{p.name}: el id '{pb['id']}' debe llamarse como el archivo")
            out[pb["id"]] = pb
        _cache.update(out)
    return _cache


def para_titulo(titulo: str):
    """Id del playbook de un titulo de hallazgo (en espanol, como lo genera el codigo), o ''."""
    for pid, pb in cargar().items():
        if pb["hallazgo"] in titulo:
            return pid
    return ""


def _lista(items) -> list:
    return [t(x) for x in items]


def seccion(filas_plan: list):
    """Playbooks de los hallazgos presentes, en el orden del plan; None si no hay ninguno.

    Cada playbook: {"id", "titulo", "bloques": [(etiqueta, items, ordenada)]}; todo ya traducido.
    """
    pbs = cargar()
    vistos: set = set()
    out = []
    for r in filas_plan:
        pid = r.get("playbook") or ""
        if not pid or pid in vistos:
            continue
        vistos.add(pid)
        pb = pbs[pid]
        bloques = [(t("Objetivo"), [t(pb["objetivo"])], False),
                   (t("Que se rompe si se hace mal"), [t(pb["prioridad_ot"])], False),
                   (t("Pasos"), _lista(pb["pasos"]), True)]
        for plat in PLATAFORMAS:
            if plat in pb["por_plataforma"]:
                bloques.append((t("Por plataforma") + ": " + t(plat), _lista(pb["por_plataforma"][plat]), False))
        bloques += [(t("Verificacion"), _lista(pb["verificacion"]), False),
                    (t("Reversion"), _lista(pb["reversion"]), False),
                    (t("Precauciones en OT"), _lista(pb["precauciones"]), False),
                    (t("Responsable"), [t(pb["responsable"])], False)]
        if pb["referencias"]:       # los hallazgos de calidad de captura no se mapean a ningun marco
            bloques.append((t("Referencias"), [Traducido("; ".join(pb["referencias"]))], False))
        out.append({"id": pid, "titulo": t(r["titulo"]), "bloques": bloques})
    return out or None
