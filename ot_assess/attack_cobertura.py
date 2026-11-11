"""Matriz de cobertura de ATT&CK for ICS (AT2, D115): tacticas por hallazgo y tecnicas citables.

"con_regla = si" significa que algun texto del mapeo propio (marcos/mitre-ics.json, sin revisar)
cita la tecnica: la herramienta puede citarla, no que la detecte siempre ni que el cliente este
protegido. Una fila por par tactica-tecnica vigente del catalogo oficial (attack_ics).
"""
from __future__ import annotations

import re

from . import attack_ics
from .i18n import t
from .standards import MITRE

HOJA = "ATT&CK ICS cobertura"
ARCHIVO = "attack_ics_cobertura.csv"
COLUMNAS = ["tactica", "tactica_id", "tecnica", "nombre", "tipo", "con_regla",
            "referencias_que_la_citan", "hallazgos_en_esta_corrida", "titulos"]
ID = re.compile(r"(?<![A-Za-z0-9])T[01]\d{3}(?:\.\d{3})?(?!\d)")


def ids(texto: str) -> list:
    return ID.findall(texto or "")


def tacticas_de(texto: str) -> str:
    """Tacticas de las tecnicas citadas en `texto`, sin repetir, en el orden de la matriz."""
    cat = attack_ics.cargar()
    cortos = set()
    for i in ids(texto):
        cortos.update(cat["tecnicas"].get(i, {}).get("tacticas", []))
    return "; ".join(x["nombre"] for x in cat["tacticas"] if x["id"] in cortos)


def filas(findings) -> list:
    """Filas (listas) de la matriz; los hallazgos se agrupan por (titulo, severidad) como el reporte."""
    cat = attack_ics.cargar()
    citas: dict = {}
    for txt in MITRE.refs.values():
        for i in set(ids(txt)):
            citas[i] = citas.get(i, 0) + 1
    grupos = {(f["titulo"], f["severidad"]): f["referencias"].get("mitre-ics", "") for f in findings}
    cuenta: dict = {}
    titulos: dict = {}
    for (titulo, _sev), txt in grupos.items():
        for i in set(ids(txt)):
            cuenta[i] = cuenta.get(i, 0) + 1
            titulos.setdefault(i, set()).add(t(titulo))
    out = []
    for tac in cat["tacticas"]:
        for tid in sorted(k for k, v in cat["tecnicas"].items() if tac["id"] in v["tacticas"]):
            out.append([tac["nombre"], tac["id"], tid, cat["tecnicas"][tid]["nombre"],
                        t("subtecnica") if "." in tid else t("tecnica"),
                        t("si") if tid in citas else t("no"), citas.get(tid, 0), cuenta.get(tid, 0),
                        "; ".join(sorted(titulos.get(tid, ())))])
    return out


def tablas(findings) -> list:
    return [(ARCHIVO, HOJA, COLUMNAS, filas(findings))]
