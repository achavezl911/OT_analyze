"""Indicios de bucle en el pase 1 (T10a, D72): tormenta de difusion, mismo paquete con TTL que baja y rafagas
de ICMP time exceeded. Memoria acotada: contadores por segundo en linea (sin guardar cada segundo) y una tabla
de paquetes recientes con tope. El resultado queda en cap.l2x["bucle"]; la regla esta en rules/ataques_l2.py.
"""
from __future__ import annotations

import collections

from .util import g, is_unicast_mac

# Tormenta: al menos BROADCAST_PPS paquetes por segundo de difusion o multicast durante BROADCAST_SEG_MIN
# segundos seguidos. No cuentan los protocolos cuyo multicast ciclico es normal en OT (valores muestreados
# 61850-9-2, GOOSE y sincronia PTP).
BROADCAST_PPS = 1000
BROADCAST_SEG_MIN = 3
BROADCAST_EXCLUIDOS = frozenset({"sv", "goose", "ptp", "ptpv2"})
# Bucle de enrutamiento: el mismo paquete (origen, destino, protocolo, ip.id, longitud IP) visto con TTL
# estrictamente decreciente al menos LAZO_TTL_VISTAS veces; hacen falta LAZO_TTL_PAQUETES paquetes asi.
LAZO_TTL_VISTAS = 4
LAZO_TTL_PAQUETES = 5
TTL_TABLA_MAX = 20000
# Rafaga de ICMP time exceeded (tipo 11): al menos ICMP11_RAFAGA en un mismo segundo.
ICMP11_RAFAGA = 50
MAX_EJEMPLOS = 10


class Vigia:
    """Se alimenta con cada fila del pase 1 (fila) y se cierra con cerrar(cap)."""

    def __init__(self) -> None:
        self.sec = None
        self.bm = 0
        self.i11 = 0
        self.racha = None            # [inicio, fin, maximo pps, total]
        self.rachas: list = []
        self.n_rachas = 0
        self.i11_total = 0
        self.i11_max = 0
        self.i11_en = 0
        self.tabla: collections.OrderedDict = collections.OrderedDict()
        self.ttl_n = 0
        self.ttl_ej: list = []
        self.ttl_primero = 0.0

    # -- segundos ------------------------------------------------------- #
    def _cerrar_racha(self) -> None:
        r = self.racha
        self.racha = None
        if r and r[1] - r[0] + 1 >= BROADCAST_SEG_MIN:
            self.n_rachas += 1
            if len(self.rachas) < MAX_EJEMPLOS:
                self.rachas.append(r)

    def _cerrar_segundo(self) -> None:
        if self.sec is None:
            return
        if self.bm >= BROADCAST_PPS:
            r = self.racha
            if r and r[1] == self.sec - 1:
                r[1] = self.sec
                r[2] = max(r[2], self.bm)
                r[3] += self.bm
            else:
                self._cerrar_racha()
                self.racha = [self.sec, self.sec, self.bm, self.bm]
        else:
            self._cerrar_racha()
        if self.i11 > self.i11_max:
            self.i11_max, self.i11_en = self.i11, self.sec
        self.bm = self.i11 = 0

    # -- paquetes ------------------------------------------------------- #
    def fila(self, row: list, idx: dict, t: float) -> None:
        if t:
            sec = int(t)
            if self.sec is None:
                self.sec = sec
            elif sec > self.sec:             # un paquete fuera de orden cuenta en el segundo actual
                self._cerrar_segundo()
                self.sec = sec
            edst = g(row, idx, "eth.dst")
            if edst and not is_unicast_mac(edst):
                proto = g(row, idx, "_ws.col.protocol").lower()
                if proto not in BROADCAST_EXCLUIDOS:
                    self.bm += 1
            if g(row, idx, "icmp.type").split("|")[0] == "11":
                self.i11 += 1
                self.i11_total += 1
        self._ttl(row, idx, t)

    def _ttl(self, row: list, idx: dict, t: float) -> None:
        ip_id = g(row, idx, "ip.id").split("|")[0]
        ttl = g(row, idx, "ip.ttl").split("|")[0]
        src = g(row, idx, "ip.src").split("|")[0]
        dst = g(row, idx, "ip.dst").split("|")[0]
        if not (ip_id and ttl and src and dst) or ip_id in ("0", "0x0000"):
            return
        try:
            ttl_n = int(ttl)
        except ValueError:
            return
        clave = (src, dst, g(row, idx, "ip.proto").split("|")[0], ip_id, g(row, idx, "ip.len").split("|")[0])
        e = self.tabla.get(clave)
        if e is None:
            self.tabla[clave] = [ttl_n, 1, False, ttl_n]        # ttl actual, vistas seguidas, contado, ttl inicial
            if len(self.tabla) > TTL_TABLA_MAX:
                self.tabla.popitem(last=False)
        elif e[2]:
            return
        elif ttl_n < e[0]:
            e[0] = ttl_n
            e[1] += 1
            if e[1] >= LAZO_TTL_VISTAS:
                e[2] = True
                self.ttl_n += 1
                if not self.ttl_primero:
                    self.ttl_primero = t
                if len(self.ttl_ej) < MAX_EJEMPLOS:
                    self.ttl_ej.append([src, dst, e[3], ttl_n, t])
        elif ttl_n > e[0]:
            e[0], e[1], e[3] = ttl_n, 1, ttl_n

    def cerrar(self, cap) -> None:
        self._cerrar_segundo()
        self._cerrar_racha()
        cap.l2x["bucle"] = {
            "rachas": self.rachas, "n_rachas": self.n_rachas,
            "ttl_n": self.ttl_n, "ttl_ejemplos": self.ttl_ej, "ttl_primero": self.ttl_primero,
            "i11_total": self.i11_total, "i11_max": self.i11_max, "i11_en": self.i11_en,
        }
