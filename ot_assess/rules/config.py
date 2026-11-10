"""Reglas de configuracion de servicios de red."""
from __future__ import annotations

from ..i18n import t
from ..model import Capture
from .base import RULES, finding, protos_of


@RULES
def rip(cap: Capture) -> None:
    # --- RIP / protocolos de ruteo sin autenticacion ------------------------ #
    # Wireshark nombra la columna RIPv1, RIPv2 o RIPng, nunca "RIP" a secas (COR-05).
    tramas = sum(n for p, n in protos_of(cap).items() if p.startswith("rip"))
    if tramas:
        finding(
            cap, "Media",
            "RIP activo en la red de control",
            t("{n} tramas RIP", n=tramas),
            "RIP sin autenticacion permite inyectar rutas falsas y desviar trafico. "
            "Ademas es un protocolo que no suele tener razon de existir en un "
            "segmento de control moderno.",
            "Eliminar RIP o, si se requiere ruteo dinamico, migrar a OSPF con "
            "autenticacion y filtrado de vecinos.",
            categoria="Configuracion",
        )


@RULES
def dhcp(cap: Capture) -> None:
    protos = protos_of(cap)
    # --- DHCP en red de control --------------------------------------------#
    if "dhcp" in protos and protos["dhcp"] > 5:
        finding(
            cap, "Baja",
            "DHCP activo en el segmento de control",
            t("{n} tramas DHCP", n=protos["dhcp"]),
            "El direccionamiento dinamico en nivel 1-2 complica el inventario, "
            "rompe reglas de firewall basadas en IP y dificulta la trazabilidad.",
            "Usar direccionamiento estatico o reservas por MAC para dispositivos de control.",
            categoria="Configuracion",
        )
