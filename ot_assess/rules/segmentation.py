"""Reglas de direccionamiento y segmentacion."""
from __future__ import annotations

import collections

from ..i18n import t, unir
from ..model import Capture
from ..util import is_apipa, is_private
from .base import RULES, finding, ips_of


@RULES
def apipa(cap: Capture) -> None:
    all_ips = ips_of(cap)
    # --- direccionamiento ---------------------------------------------------#
    apipa = sorted({i for i in all_ips if is_apipa(i)})
    if apipa:
        finding(
            cap, "Media",
            "Equipos con direccion APIPA (169.254.x.x)",
            t("{lista}", lista=", ".join(apipa[:10])),
            "Una direccion APIPA significa que el equipo no obtuvo IP por DHCP. En "
            "planta suele indicar un dispositivo mal configurado, un servidor DHCP "
            "caido o un equipo conectado donde no debia estar.",
            "Identificar fisicamente cada equipo y corregir su direccionamiento; "
            "si no debe estar en la red, retirarlo.",
            categoria="Configuracion",
        )


@RULES
def ip_publicas(cap: Capture) -> None:
    all_ips = ips_of(cap)
    publics = sorted({i for i in all_ips if i and ":" not in i and not is_private(i)})
    if publics:
        finding(
            cap, "Alta",
            "Trafico con direcciones IP publicas desde la red OT",
            t("{lista}", lista=", ".join(publics[:15])),
            "Comunicacion hacia Internet desde un segmento de control rompe la "
            "segmentacion esperada y es via de exfiltracion y de mando y control.",
            "Verificar si son equipos de planta o trafico de transito mal segmentado; "
            "bloquear la salida directa a Internet desde niveles 0-2.",
            categoria="Segmentacion",
        )


@RULES
def multiples_subredes(cap: Capture) -> None:
    all_ips = ips_of(cap)
    # subredes: muchas /24 distintas en un mismo dominio de difusion
    subnets = collections.Counter()
    for i in sorted(all_ips):  # orden fijo: los empates de most_common no cambian entre corridas
        if i and ":" not in i and not is_apipa(i):
            subnets[".".join(i.split(".")[:3])] += 1
    if len(subnets) > 3:
        finding(
            cap, "Media",
            "Multiples subredes conviviendo en el mismo dominio de difusion",
            unir(", ", (t("{k}.0/24 ({v} hosts)", k=k, v=v) for k, v in subnets.most_common(10))),
            "Varias subredes en el mismo segmento L2 indican segmentacion incompleta: "
            "el aislamiento logico no esta respaldado por aislamiento de red.",
            "Revisar el diseno de VLANs y el plan de direccionamiento contra el "
            "modelo de zonas y perimetros de seguridad definido para la planta.",
            categoria="Segmentacion",
        )


@RULES
def sin_vlan(cap: Capture) -> None:
    if len(cap.vlans) <= 1 and cap.flow_packets > 1000:
        finding(
            cap, "Informativa",
            "Sin segmentacion por VLAN visible en el punto de captura",
            t("VLANs observadas: {vlans}",
              vlans=", ".join(cap.vlans) or t("ninguna (tramas sin etiqueta 802.1Q)")),
            "Puede ser que no haya VLANs, o que el puerto SPAN entregue las tramas "
            "sin etiqueta. Lo segundo le quita contexto a cualquier sensor pasivo.",
            "Confirmar con el equipo de redes si el SPAN preserva el tag 802.1Q.",
            categoria="Visibilidad",
        )
