"""Pase 1: activos, flujos y VLANs a partir de campos de capa 2-4."""
from __future__ import annotations

from .bucles import Vigia
from .catalog import OT_PORTS
from .cobertura_captura import Acumulador
from .model import Capture
from .tools import Tshark
from .util import g, is_host_ip, is_unicast_mac

# T5 (D65): un intervalo mayor que max(HUECO_FACTOR x media, HUECO_MIN_S) es un hueco; con al menos
# BASE_MIN intervalos previos se registra aparte y no entra en la media ni en la varianza.
HUECO_FACTOR = 10
HUECO_MIN_S = 5.0
BASE_MIN = 5


# L1 (D81): serie por minuto de cada flujo (bytes << 32 | paquetes). Memoria acotada: tope de celdas por captura;
# los flujos de puerto efimero (>= 32768, no industrial) solo ocupan celdas mientras quede mas de la mitad.
SERIES_CUPO = 500_000
EFIMERO = 32768


def _serie_elegible(dport: str, l4: str, cupo: list) -> bool:
    if not l4:
        return False
    try:
        p = int(dport)
    except ValueError:
        return False
    return (p, l4) in OT_PORTS or p < EFIMERO or cupo[0] > SERIES_CUPO // 2


def registrar_carga(f: dict, t: float) -> None:
    """Estadistica en linea (Welford) de los intervalos entre paquetes con carga util de un flujo.

    pl_n/pl_mean/pl_m2: intervalos normales; pl_huecos: los excluidos por ser huecos; pl_min/pl_max y
    pl_max_en (inicio del intervalo maximo): todos los intervalos; pl_first/pl_last: primera y ultima carga.
    """
    prev = f.get("pl_last")
    if prev is None:
        f["pl_first"] = f["pl_last"] = t
        f.update(pl_n=0, pl_mean=0.0, pl_m2=0.0, pl_huecos=0, pl_min=None, pl_max=0.0, pl_max_en=0.0)
        return
    dt = t - prev
    if dt < 0:                     # paquete fuera de orden: no hay intervalo que medir
        return
    f["pl_last"] = t
    if f["pl_min"] is None or dt < f["pl_min"]:
        f["pl_min"] = dt
    if dt > f["pl_max"]:
        f["pl_max"], f["pl_max_en"] = dt, prev
    if f["pl_n"] >= BASE_MIN and dt > max(HUECO_FACTOR * f["pl_mean"], HUECO_MIN_S):
        f["pl_huecos"] += 1
        return
    f["pl_n"] += 1
    d = dt - f["pl_mean"]
    f["pl_mean"] += d / f["pl_n"]
    f["pl_m2"] += d * (dt - f["pl_mean"])


def _con_carga(row, idx, l4: str) -> bool:
    """UDP siempre lleva datagrama; en TCP solo cuenta el segmento con datos (los ACK y el saludo no)."""
    if l4 != "tcp":
        return True
    try:
        return int((g(row, idx, "tcp.len") or "0").split("|")[0]) > 0
    except ValueError:
        return False


def analyze_flows(ts: Tshark, cap: Capture, fields: list[str], limit: int) -> None:
    idx = {f: i for i, f in enumerate(fields)}
    n = 0
    vigia = Vigia()
    acum = Acumulador(idx)                            # C1 (D80): cobertura de la captura
    cupo = [SERIES_CUPO]
    for row in ts.fields_pass(cap.path, fields, None, limit):
        n += 1
        acum.fila(row)
        esrc = g(row, idx, "eth.src")
        if not esrc:
            continue
        edst = g(row, idx, "eth.dst")
        try:
            blen = int(g(row, idx, "frame.len") or 0)
        except ValueError:
            blen = 0
        try:
            t = float(g(row, idx, "frame.time_epoch") or 0)
        except ValueError:
            t = 0.0
        if t:
            if not cap.ventana:
                cap.ventana = [t, t]
            else:
                cap.ventana[0] = min(cap.ventana[0], t)
                cap.ventana[1] = max(cap.ventana[1], t)
        vigia.fila(row, idx, t)                       # T10a: indicios de bucle (bucles.py)

        # Solo las MAC unicast son equipos. ff:ff:... y 01:00:5e:... son grupos
        # de destino y no deben aparecer en el inventario de activos.
        if not is_unicast_mac(esrc):
            continue
        hs = cap.host(esrc, g(row, idx, "eth.src_resolved"))
        hd = (cap.host(edst, g(row, idx, "eth.dst_resolved"))
              if edst and is_unicast_mac(edst) else None)

        hs["tx_pkts"] += 1
        hs["tx_bytes"] += blen
        if hd:
            hd["rx_pkts"] += 1
            hd["rx_bytes"] += blen
        for h in (hs, hd):
            if h is None:
                continue
            if h["first"] is None or (t and t < h["first"]):
                h["first"] = t
            if h["last"] is None or t > h["last"]:
                h["last"] = t

        vlan = g(row, idx, "vlan.id")
        if vlan:
            for v in vlan.split("|"):
                cap.vlans[v] += 1
                hs["vlans"].add(v)
                if hd:
                    hd["vlans"].add(v)

        colproto = g(row, idx, "_ws.col.protocol")
        if colproto:
            hs["proto_seen"][colproto] += 1
            cap.ethertypes[colproto] += 1

        sip = (g(row, idx, "ip.src") or g(row, idx, "ipv6.src")).split("|")[0]
        dip = (g(row, idx, "ip.dst") or g(row, idx, "ipv6.dst")).split("|")[0]
        if is_host_ip(sip):
            hs["ips"].add(sip)
        if hd and is_host_ip(dip):
            hd["ips"].add(dip)

        tsp, tdp = g(row, idx, "tcp.srcport"), g(row, idx, "tcp.dstport")
        usp, udp_ = g(row, idx, "udp.srcport"), g(row, idx, "udp.dstport")
        if tdp:
            l4, sport, dport = "tcp", tsp, tdp
        elif udp_:
            l4, sport, dport = "udp", usp, udp_
        else:
            l4, sport, dport = "", "", ""

        if sip and dip:
            hs["peers"].add(dip)
            if hd:
                hd["peers"].add(sip)
            key = (sip, dip, dport, l4)
            f = cap.flows.get(key)
            if f is None:
                f = {
                    "src": sip, "dst": dip, "dport": dport, "l4": l4,
                    "pkts": 0, "bytes": 0, "proto": colproto,
                    "first": t, "last": t, "sports": set(),
                    "min": {} if _serie_elegible(dport, l4, cupo) else None,
                }
                cap.flows[key] = f
            f["pkts"] += 1
            f["bytes"] += blen
            f["last"] = t
            mins = f["min"]
            if mins is not None and t:                # L1 (D81): bytes y paquetes por minuto del flujo
                m = int(t // 60)
                v = mins.get(m)
                if v is not None:
                    mins[m] = v + (blen << 32) + 1
                elif cupo[0] > 0:
                    cupo[0] -= 1
                    mins[m] = (blen << 32) | 1
                else:
                    f["min"] = None                  # cupo agotado: este flujo se queda sin serie
            if t and l4 and _con_carga(row, idx, l4):
                registrar_carga(f, t)
            if sport:
                f["sports"].add(sport)
            if not f["proto"] and colproto:
                f["proto"] = colproto

        # Puertos: el bajo suele ser el que "sirve".
        if l4 and sport and dport:
            try:
                sp, dp = int(sport), int(dport)
            except ValueError:
                sp = dp = 0
            if dp and (dp < sp or dp < 1024 or (dp, l4) in OT_PORTS):
                if hd:
                    hd["ports_served"][(dp, l4)] += 1
                hs["ports_used"][(dp, l4)] += 1
            elif sp:
                hs["ports_served"][(sp, l4)] += 1

        cap.l2_flows[(esrc, edst)] += 1

    vigia.cerrar(cap)
    cap.cobertura = acum.cerrar()
    cap.flow_packets = n
    cap.sampled = bool(limit) and n >= limit
