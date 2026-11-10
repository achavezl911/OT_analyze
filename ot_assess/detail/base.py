"""Base de los colectores del pase de detalle."""
from __future__ import annotations

from ..model import Capture
from ..registry import Registry
from ..util import _int_or_none, g

# Cada colector es una funcion (RowCtx) -> None decorada con @COLLECTORS.
COLLECTORS = Registry()


class RowCtx:
    """Una fila de tshark con los campos de uso comun ya resueltos."""

    def __init__(self, cap: Capture, row: list[str], idx: dict[str, int]):
        self.cap, self.row, self.idx = cap, row, idx
        self.sip = g(row, idx, "ip.src")
        self.smac = g(row, idx, "eth.src")
        self.frame = g(row, idx, "frame.number")
        try:
            self.t = float(g(row, idx, "frame.time_epoch") or 0)
        except ValueError:
            self.t = 0.0

    def get(self, name: str) -> str:
        return g(self.row, self.idx, name)

    def toward_server(self, port: int) -> bool:
        """Una operacion se cuenta una sola vez: en la peticion. En Modbus,
        DNP3, IEC-104 y S7 la respuesta repite el mismo codigo de funcion,
        asi que nos quedamos con el sentido que va hacia el servidor."""
        return port in (
            _int_or_none(self.get("tcp.dstport")),
            _int_or_none(self.get("udp.dstport")),
        )

    def add_ident(self, src_ip, src_mac, kind, value, extra=None):
        if not value:
            return
        self.cap.identity.append({
            "ip": src_ip, "mac": src_mac, "tipo": kind,
            "valor": value, "detalle": extra or "",
        })
        if src_mac in self.cap.hosts:
            self.cap.hosts[src_mac]["fingerprints"].add(f"{kind}: {value}")
