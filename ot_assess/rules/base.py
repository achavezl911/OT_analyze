"""Base de las reglas: registro, constructor de hallazgos y ayudas comunes."""
from __future__ import annotations

from ..model import Capture
from ..registry import Registry
from ..riesgo import id_hallazgo
from ..standards import referencias

# Cada regla es una funcion (cap) -> None decorada con @RULES. El orden de
# registro (ver rules/__init__.py) fija el orden de los hallazgos en los reportes.
RULES = Registry()


def protos_of(cap: Capture) -> dict:
    """Protocolos vistos en minuscula -> tramas."""
    return {p.lower(): c for p, c in cap.ethertypes.items()}


def ips_of(cap: Capture) -> set:
    ips: set = set()
    for h in cap.hosts.values():
        ips |= {i for i in h["ips"] if i}
    return ips


def finding(cap, sev, titulo, evidencia, porque, recomendacion, categoria="Higiene", activos=None):
    """`activos` (opcional): IP de los equipos que involucra; el plan de remediacion las usa para la criticidad."""
    h = {
        "id": id_hallazgo(titulo), "severidad": sev, "titulo": titulo, "categoria": categoria,
        "evidencia": evidencia, "por_que_importa": porque,
        "recomendacion": recomendacion, "captura": cap.name,
        "referencias": referencias(titulo),
    }
    if activos:
        h["activos"] = sorted(set(activos))
    cap.findings.append(h)
