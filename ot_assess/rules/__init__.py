"""Reglas de hallazgos. Para agregar una: funcion con @RULES en el modulo de su categoria."""
from __future__ import annotations

from ..model import Capture
from .base import RULES, finding  # noqa: F401

# El orden de estas importaciones es el orden de los hallazgos.
from . import exposure, segmentation, config, anomaly, control, visibility, dns, protocolos, periodicidad, acceso_remoto, evasion, ataques_l2, salud_red, linea_base_aprobada  # noqa: F401,E402
from .visibility import captura_ilegible  # noqa: E402


def evaluate(cap: Capture) -> None:
    # Sobre una captura ilegible solo se reporta eso: las demas reglas darian hallazgos de ausencia falsos.
    for rule in ([captura_ilegible] if cap.error else RULES):
        rule(cap)
