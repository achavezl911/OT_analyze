"""Reglas L1 (D81): tormenta de difusion y retransmisiones TCP en conductos industriales.

Leen lo que C1 acumula por captura (`cap.cobertura`). Umbrales sin calibrar (D81): evidencia tecnica de una captura,
no un diagnostico. Los calculos viven en salud_red.py.
"""
from __future__ import annotations

import re

from ..i18n import t, unir
from ..model import Capture
from ..salud_red import (
    DIF_P95_PPS,
    DIF_PICO_PPS,
    RETRANS_MIN_SEG,
    RETRANS_PCT,
    stats_difusion,
    tcp_sobre_umbral,
    tormenta,
)
from .base import RULES, finding

MAX_EVIDENCIA = 10
_PURDUE_012 = re.compile(r"Nivel [012]")
TIT_TORMENTA = "Tormenta de difusion o multidifusion"
TIT_RETRANS = "Retransmisiones TCP elevadas en un conducto OT"


def _zona_ot(cap: Capture) -> bool:
    return any(_PURDUE_012.search(h.get("purdue") or "") for h in cap.hosts.values())


@RULES
def tormenta_difusion(cap: Capture) -> None:
    raw = cap.cobertura
    if not raw or not raw.get("paquetes") or not tormenta(raw):
        return
    d = stats_difusion(raw)
    lineas = [t("difusion y multidifusion: p95 de {p} paquetes/s (promedio de cada minuto), maximo de un minuto "
                "{m} paquetes/s, pico de {s} paquetes en un segundo", p=f"{d['pps_p95']:.0f}",
                m=f"{d['pps_max']:.0f}", s=d["pico_s"])]
    if d["arp_total"]:
        lineas.append(t("ARP: {n} paquetes, maximo de {m} en un minuto", n=d["arp_total"], m=d["arp_max"]))
    finding(
        cap, "Media", "Tormenta de difusion o multidifusion",
        unir("\n", [t("Umbrales: p95 mayor que {a} paquetes/s o pico mayor que {b} en un segundo",
                      a=DIF_P95_PPS, b=DIF_PICO_PPS)] + lineas),
        "Una tormenta de difusion o multidifusion llega a todos los equipos del dominio de capa 2, consume la CPU de "
        "los controladores y puede dejar sin respuesta el trafico de control. Suele venir de un bucle de capa 2, "
        "una tarjeta con falla o un equipo mal configurado; tambien puede ser un protocolo industrial legitimo de "
        "multidifusion (GOOSE, PROFINET), que hay que descartar primero.",
        "Identificar el origen del trafico (top de emisores de ARP y de difusion en la captura), revisar bucles y "
        "cambios de topologia en los switches y activar storm control en los puertos de acceso; confirmar con "
        "operacion si hay multidifusion industrial esperada antes de limitarla.",
        categoria="Anomalia")
    if _zona_ot(cap):          # la severidad base es un literal para que las pruebas lean el titulo con una expresion
        cap.findings[-1]["severidad"] = "Alta"


@RULES
def retransmisiones_ot(cap: Capture) -> None:
    raw = cap.cobertura
    if not raw:
        return
    malos = tcp_sobre_umbral(raw)
    if not malos:
        return
    lineas = [t("{cli} -> {srv} puerto {p}: {r} % de retransmisiones y {l} % de perdida en {n} segmentos",
                cli=c, srv=s, p=p, r=f"{rp:.1f}", l=f"{pp:.1f}", n=seg) for c, s, p, seg, rp, pp, _i in
              malos[:MAX_EVIDENCIA]]
    if len(malos) > MAX_EVIDENCIA:
        lineas.append(t(" y {n} mas", n=len(malos) - MAX_EVIDENCIA))
    finding(
        cap, "Media", "Retransmisiones TCP elevadas en un conducto OT",
        unir("\n", [t("{n} conductos de puertos industriales con mas de {u} % de retransmisiones (al menos {m} "
                      "segmentos)", n=len(malos), u=RETRANS_PCT, m=RETRANS_MIN_SEG)] + lineas),
        "Las retransmisiones TCP indican paquetes perdidos o demorados entre los extremos: enlace saturado o con "
        "errores, un equipo lento o un espejo que pierde paquetes (puede ser un artefacto de la captura). En un "
        "conducto de control aumentan la latencia del lazo y pueden cortar la sesion.",
        "Revisar los contadores de errores y descartes de los puertos del camino, la carga del controlador y el "
        "cableado; comparar con la perdida del punto de captura (validacion de la captura) para separar un problema "
        "de la red de uno del espejo, y repetir la medicion.",
        categoria="Anomalia", activos=[ip for c, s, *_r in malos for ip in (c, s)])
