"""Reglas T5 (D65): periodicidad de las comunicaciones de control (huecos, sondeo irregular, escritor tardio).

Evidencia tecnica de una captura, no un veredicto: un hueco puede ser una maniobra, un reinicio o el corte de
la propia captura. Los calculos viven en periodicidad.py.
"""
from __future__ import annotations

import re

from ..i18n import t, unir
from ..model import Capture
from ..periodicidad import conductos, escritores_tardios, iso
from .base import RULES, finding

MAX_EVIDENCIA = 10
_PURDUE_01 = re.compile(r"Nivel [01]")


def _nivel_01(cap: Capture, ip: str) -> bool:
    return any(ip in h["ips"] and _PURDUE_01.search(h.get("purdue") or "") for h in cap.hosts.values())


def _resto(total: int) -> list:
    return [t(" y {n} mas", n=total - MAX_EVIDENCIA)] if total > MAX_EVIDENCIA else []


@RULES
def perdida_comunicacion_periodica(cap: Capture) -> None:
    afectados = [c for c in conductos(cap) if {"hueco", "termina_antes"} & set(c["marcas"])]
    if not afectados:
        return
    escriben = {(o["src"], o["dst"]) for o in cap.control_ops}
    alta = any((c["src"], c["dst"]) in escriben or _nivel_01(cap, c["src"]) or _nivel_01(cap, c["dst"])
               for c in afectados)
    lineas = []
    for c in afectados[:MAX_EVIDENCIA]:
        base = t("{src} -> {dst} {servicio}: periodo medio {media} s, CV {cv}",
                 src=c["src"], dst=c["dst"], servicio=c["servicio"], media=f"{c['media']:.2f}",
                 cv=f"{c['cv']:.2f}")
        if "hueco" in c["marcas"]:
            base = unir("", [base, t("; hueco maximo {hueco} s desde {cuando}", hueco=f"{c['hueco_max']:.1f}",
                                     cuando=iso(c["hueco_en"]))])
        if "termina_antes" in c["marcas"]:
            base = unir("", [base, t("; ultimo paquete con carga {cuando}, antes del final de la captura",
                                     cuando=iso(c["ultima"]))])
        lineas.append(base)
    finding(
        cap, "Media",
        "Perdida de comunicacion en un conducto de control periodico",
        unir("\n", [t("{n} conductos con hueco o fin temprano", n=len(afectados))] + lineas + _resto(len(afectados))),
        "Un conducto de sondeo que era regular y se interrumpe puede ser una falla del enlace, del controlador "
        "o del cliente, un reinicio o una maniobra; mientras dura el hueco el proceso deja de leerse o de "
        "recibir comandos. Es evidencia de una captura, no un diagnostico: el corte tambien puede ser de la "
        "captura misma.",
        "Correlacionar cada instante con la bitacora de operacion y los registros de los equipos y del "
        "switch; si no hay explicacion, revisar el enlace y la carga del controlador y dejar monitoreo "
        "continuo de la periodicidad del conducto.",
        categoria="Anomalia", activos=[ip for c in afectados for ip in (c["src"], c["dst"])],
    )
    if alta:       # la severidad base es un literal para que las pruebas lean el titulo con una expresion
        cap.findings[-1]["severidad"] = "Alta"


@RULES
def sondeo_irregular(cap: Capture) -> None:
    irr = [c for c in conductos(cap) if c["patron"] == "irregular"]
    if not irr:
        return
    lineas = [t("{src} -> {dst} {servicio}: periodo medio {media} s, CV {cv}, hueco maximo {hueco} s",
                src=c["src"], dst=c["dst"], servicio=c["servicio"], media=f"{c['media']:.2f}",
                cv=f"{c['cv']:.2f}", hueco=f"{c['hueco_max']:.1f}") for c in irr[:MAX_EVIDENCIA]]
    finding(
        cap, "Baja", "Sondeo irregular en conductos de control",
        unir("\n", [t("{n} conductos de sondeo con intervalos irregulares", n=len(irr))] + lineas + _resto(len(irr))),
        "Un sondeo normalmente es regular. La irregularidad puede venir de jitter o saturacion de la red, de "
        "un controlador sobrecargado o de un cliente no habitual (una herramienta manual, un escaneo) que "
        "no es el HMI o SCADA esperado.",
        "Identificar el cliente de cada conducto y confirmar que es el esperado; revisar la carga de la red y "
        "del controlador y comparar con otra captura de la misma ventana.",
        categoria="Anomalia", activos=[ip for c in irr for ip in (c["src"], c["dst"])],
    )


@RULES
def escritor_tardio(cap: Capture) -> None:
    esc = escritores_tardios(cap)
    if not esc:
        return
    lineas = [t("{src} -> {dst}: primera operacion {cuando}; {ops} ({n} operaciones)", src=e["src"],
                dst=e["dst"], cuando=iso(e["t"]), ops="; ".join(e["ops"][:3]), n=e["n"])
              for e in esc[:MAX_EVIDENCIA]]
    finding(
        cap, "Alta", "Escritor de control que aparece a mitad de la captura",
        unir("\n", [t("{n} pares sin trafico previo que escriben o mandan comandos", n=len(esc))]
             + lineas + _resto(len(esc))),
        "Un origen que no hablaba con el controlador y de pronto escribe puede ser una maniobra o una sesion de "
        "ingenieria autorizada, pero tambien un equipo nuevo, comprometido o un movimiento lateral: es "
        "una de las senales que una plataforma OT alertaria como actividad nueva.",
        "Confirmar con operacion si hubo una maniobra o un cambio en esa hora; si no hay registro, tratarlo "
        "como incidente, aislar el origen y revisar la lista de origenes autorizados a escribir.",
        categoria="Control", activos=[ip for e in esc for ip in (e["src"], e["dst"])],
    )
