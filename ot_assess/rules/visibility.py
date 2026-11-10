"""Reglas de brecha de visibilidad: por que un sensor pasivo podria no ver lo que si esta."""
from __future__ import annotations

import re

from ..i18n import t
from ..model import Capture
from ..util import is_host_ip, is_unicast_mac
from .base import RULES, finding


@RULES
def captura_ilegible(cap: Capture) -> None:
    if not cap.error:
        return
    finding(
        cap, "Alta",
        "Captura ilegible o sin paquetes",
        t("Wireshark no pudo leerla completa: {error}", error=cap.error),
        "La captura no se analizo: no aporta equipos, flujos ni hallazgos. Ninguna conclusion "
        "del reporte la incluye, y la ausencia de hallazgos sobre ella no significa que la red "
        "este limpia. Un archivo cortado a medias suele ser una copia o una captura interrumpida.",
        "Recapturar o recuperar el archivo, verificarlo con capinfos y repetir el analisis.",
        categoria="Captura",
    )


@RULES
def truncamiento(cap: Capture) -> None:
    info = cap.info
    # 1. Truncamiento
    snap = info.get("Packet size limit") or info.get("Packet size limit (min/max)") or ""
    m = re.search(r"(\d+)", snap)
    if m and int(m.group(1)) and int(m.group(1)) < 1500:
        finding(
            cap, "Alta",
            "Captura truncada (snaplen por debajo del MTU)",
            t("Limite de tamano de paquete: {snap}", snap=snap),
            "Con los paquetes cortados, el disector no alcanza a leer banners, "
            "versiones de firmware ni contenido de protocolo. Un motor de CVE pasivo "
            "se queda sin la evidencia que necesita y no emite hallazgos. Esta es una "
            "causa frecuente de 'la herramienta no ve nada'.",
            "Recapturar con snaplen completo (sin -s) para el analisis de identidad.",
            categoria="Visibilidad",
        )


@RULES
def un_solo_sentido(cap: Capture) -> None:
    # 2. Trafico unidireccional: SPAN configurado solo en una direccion
    # Solo cuentan los pares unicast: el multicast y el broadcast son
    # unidireccionales por diseno y dirian que el SPAN esta mal sin estarlo.
    pairs: dict[tuple, set] = {}
    for (src, dst, dport, l4), f in cap.flows.items():
        if not is_host_ip(src) or not is_host_ip(dst):
            continue
        key = tuple(sorted((src, dst)))
        pairs.setdefault(key, set()).add((src, dst))
    oneway = [k for k, v in pairs.items() if len(v) == 1]
    if pairs and len(oneway) / len(pairs) > 0.6 and len(pairs) >= 5:
        finding(
            cap, "Alta",
            "La mayoria de las conversaciones aparece en un solo sentido",
            t("{n} de {total} pares de IPs sin trafico de vuelta", n=len(oneway), total=len(pairs)),
            "Un SPAN configurado solo en RX (o solo en TX), o un TAP de una sola fibra, "
            "entrega media conversacion. El sensor no puede correlacionar peticion y "
            "respuesta, y pierde justo las respuestas, que son las que traen banners, "
            "identidad y version de firmware. Explica directamente que una herramienta "
            "con otro punto de captura si encuentre hallazgos.",
            "Reconfigurar el SPAN como 'both' o instalar un TAP que agregue ambas "
            "direcciones, y validar con un conteo de paquetes por sentido.",
            categoria="Visibilidad",
        )


@RULES
def sin_unicast(cap: Capture) -> None:
    # 2b. Casi nada de unicast: el sensor solo ve lo que se inunda
    l2_total = sum(cap.l2_flows.values())
    l2_uni = sum(n for (s, d), n in cap.l2_flows.items() if is_unicast_mac(d))
    if l2_total > 2000 and l2_uni / l2_total < 0.15:
        finding(
            cap, "Alta",
            "El punto de captura casi no ve trafico unicast",
            t("Solo {n} de {total} paquetes ({pct}) van a una MAC unicast; el resto es "
              "difusion o multicast.", n=l2_uni, total=l2_total, pct=f"{l2_uni / l2_total:.1%}"),
            "Un puerto que solo recibe lo que el switch inunda (difusion, "
            "multicast y trafico desconocido) no ve las conversaciones "
            "cliente-servidor. Ahi es justo donde viven la mensajeria explicita, "
            "los banners y las negociaciones que permiten identificar modelo y "
            "firmware. Un sensor conectado en este punto construye un inventario "
            "parcial y no puede enumerar vulnerabilidades, mientras que otro "
            "conectado donde si pasa el unicast si lo logra. Es de las "
            "explicaciones mas frecuentes de que dos herramientas no coincidan.",
            "Verificar que el SPAN tenga como fuente los puertos o la VLAN "
            "completa de los equipos de interes, no solo un puerto de acceso, "
            "y que este configurado en ambos sentidos.",
            categoria="Visibilidad",
        )


@RULES
def paquetes_identidad(cap: Capture) -> None:
    # 3. Paquetes de identidad: cuantos hay realmente
    ident_frames = len(cap.identity)
    total = cap.flow_packets or 1
    if ident_frames == 0:
        finding(
            cap, "Alta",
            "La captura no contiene ningun paquete que revele identidad de equipos",
            "Sin CDP, LLDP, banners, respuestas de descubrimiento ni objetos de identidad.",
            "Un sensor pasivo deriva fabricante, modelo y firmware de estos paquetes. "
            "Sin ellos no puede hacer match contra su base de CVEs, y por eso reporta "
            "cero vulnerabilidades aunque los equipos si sean vulnerables. La ausencia "
            "de hallazgos aqui es ausencia de evidencia, no evidencia de ausencia.",
            "Capturar durante un arranque de equipo o una sesion de ingenieria, o "
            "habilitar sondeo activo (Smart Polling o equivalente) en el sensor.",
            categoria="Visibilidad",
        )
    elif ident_frames < 50:
        finding(
            cap, "Media",
            "Muy pocos paquetes de identidad en la captura",
            t("{n} paquetes con informacion de identidad sobre {total} analizados ({pct})",
              n=ident_frames, total=total, pct=f"{ident_frames / total:.4%}"),
            "Los paquetes que permiten identificar un equipo son escasos y "
            "esporadicos (anuncios cada 30-60 s, respuestas de descubrimiento, "
            "negociaciones iniciales). Una ventana de captura corta, o un sensor que "
            "arranco despues de que los equipos ya habian negociado, se los pierde.",
            "Extender la ventana de captura a varias horas y cubrir un arranque de "
            "sistema, o complementar con sondeo activo controlado.",
            categoria="Visibilidad",
        )


@RULES
def io_ciclico(cap: Capture) -> None:
    total = cap.flow_packets or 1
    # 4. I/O ciclico dominante: trafico que no fingerprintea
    # Nombres tal como los escribe la columna "Protocol" de Wireshark.
    # Solo el I/O ciclico: la mensajeria explicita (CIP sobre TCP, MMS) si
    # puede revelar identidad y no debe contarse aqui.
    cyclic_markers = ("cip i/o", "cipio", "profinet", "pn-io", "pnio",
                      "goose", "sampled value", "iec61850 sv")
    cyclic = sum(c for p, c in cap.ethertypes.items()
                 if any(m in p.lower() for m in cyclic_markers))
    if cyclic and cyclic / total > 0.7:
        finding(
            cap, "Informativa",
            "El trafico es casi todo I/O ciclico, que no revela identidad",
            t("{n} de {total} paquetes ({pct}) son I/O ciclico (CIP Class 1 / PROFINET RT / GOOSE / SV)",
              n=cyclic, total=total, pct=f"{cyclic / total:.0%}"),
            "El I/O ciclico lleva solo valores de proceso: ni modelo, ni version, ni "
            "comandos. Un sensor pasivo lo usa para construir el mapa de "
            "comunicaciones y la linea base, pero no para enumerar vulnerabilidades. "
            "Es la razon tecnica mas probable de que la plataforma OT muestre los "
            "activos pero sin CVEs asociados.",
            "Para enumerar vulnerabilidades hace falta mensajeria explicita "
            "(ENIP/CIP sobre TCP 44818, MMS, lecturas de objeto Identity) o sondeo activo.",
            categoria="Visibilidad",
        )


@RULES
def duplicados(cap: Capture) -> None:
    info = cap.info
    # 5. Duplicados por SPAN mal armado
    dups = str(info.get("Number of duplicate packets") or "")
    if re.fullmatch(r"[1-9]\d*", dups):
        finding(
            cap, "Baja",
            "Paquetes duplicados en la captura",
            t("Duplicados detectados con editcap -d (ventana de 5 paquetes): {n}", n=dups),
            "Un SPAN que copia el mismo paquete desde varios puertos infla los "
            "conteos y puede disparar falsos positivos de retransmision en el sensor.",
            "Ajustar la fuente del SPAN para no duplicar.",
            categoria="Visibilidad",
        )


@RULES
def ventana_corta(cap: Capture) -> None:
    info = cap.info
    # 6. Ventana de captura corta
    dur = info.get("Capture duration") or ""
    md = re.search(r"([\d.]+)\s*seconds", dur)
    if md and float(md.group(1)) < 900:
        finding(
            cap, "Media",
            "Ventana de captura corta",
            t("Duracion: {dur}", dur=dur),
            "Menos de 15 minutos no alcanza a cubrir ciclos lentos: anuncios LLDP/CDP, "
            "polling de historiador, respaldos, sincronizaciones y sesiones de "
            "ingenieria. Dos herramientas comparadas sobre ventanas distintas no son "
            "comparables.",
            "Para el assessment, capturar al menos 24 h en cada punto, o acordar la "
            "misma ventana para ambas herramientas.",
            categoria="Visibilidad",
        )
