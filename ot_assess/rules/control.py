"""Reglas sobre operaciones de escritura, comando e ingenieria."""
from __future__ import annotations

import collections

from ..detail.control import op_visible
from ..i18n import t, unir
from ..ingenieria import CLASES, iso, sesiones
from ..model import Capture
from .base import RULES, finding


@RULES
def operaciones_control(cap: Capture) -> None:
    # --- operaciones de control --------------------------------------------#
    if cap.control_ops:
        por_op = collections.Counter(f"{c['proto']}: {op_visible(c)}" for c in cap.control_ops)
        pares = collections.Counter(f"{c['src']} -> {c['dst']}" for c in cap.control_ops)
        finding(
            cap, "Alta",
            "Operaciones de escritura o control observadas en la captura",
            t("Operaciones: {ops}\nPares: {pares}",
              ops="; ".join(f"{k} ({v})" for k, v in por_op.most_common(10)),
              pares="; ".join(f"{k} ({v})" for k, v in pares.most_common(5))),
            "Estas son escrituras y comandos reales sobre el proceso, no lecturas. "
            "Hay que confirmar que cada origen esta autorizado a escribir sobre ese "
            "destino: es el control mas importante del nivel 1.",
            "Validar la lista de origenes autorizados a escribir y restringir la "
            "escritura por firewall OT o por configuracion del controlador.",
            categoria="Control",
        )
    else:
        finding(
            cap, "Informativa",
            "No se observaron escrituras ni comandos de control",
            "Solo trafico de lectura o de I/O ciclico en el periodo capturado.",
            "La captura refleja operacion en estado estable. No permite concluir que "
            "no existan escrituras: solo que no ocurrieron en esta ventana.",
            "Para evaluar control de escritura hace falta capturar durante una "
            "maniobra o una sesion de ingenieria.",
            categoria="Control",
        )


@RULES
def actividad_ingenieria(cap: Capture) -> None:
    # --- programacion / ingenieria (D1, D92): por clase de la operacion, no por palabras clave -------------#
    ses = sesiones(cap)
    if not ses:
        return
    por_clase = collections.Counter()
    for s in ses:
        por_clase[s["clase"]] += s["tramas"]
    clases = unir(", ", (t("{clase} ({n})", clase=t(c), n=por_clase[c]) for c in CLASES if c in por_clase))
    lineas = unir("; ", (t("{inicio} {src} -> {dst}: {proto}, {clase} ({ops})", inicio=iso(s["inicio"]),
                           src=s["src"], dst=s["dst"], proto=s["proto"], clase=t(s["clase"]),
                           ops=", ".join(f"{op_visible({'proto': s['proto'], 'op': op})} ({n})" for op, n in s["ops"])) for s in ses[:10]))
    if len(ses) > 10:
        lineas = unir("", [lineas, t(" y {n} sesiones mas", n=len(ses) - 10)])
    finding(
        cap, "Alta",
        "Actividad de ingenieria sobre controladores (descarga, arranque o paro)",
        t("Clases: {clases}\nSesiones: {sesiones}", clases=clases, sesiones=lineas),
        "Descargar logica, detener o arrancar un controlador son las operaciones "
        "de mayor impacto en una planta. Deben venir solo de estaciones de "
        "ingenieria identificadas y en ventana autorizada.",
        "Correlacionar con la bitacora de cambios del cliente. Si no hay registro "
        "que lo respalde, tratarlo como incidente.",
        categoria="Control",
        activos=[s["dst"] for s in ses],
    )
    if set(por_clase) == {"carga"}:     # severidad base literal: las pruebas leen el titulo con una expresion
        cap.findings[-1]["severidad"] = "Media"
