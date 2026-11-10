"""Colector: ARP, STP, ICMP y DNS; ademas, evidencia de ataques de capa 2 (T10a, D72).

Campos de tshark (validados con tshark 4.4.19; los que falten se descartan y ese indicio no se genera):
  DHCP    dhcp.option.dhcp (tipo de mensaje), dhcp.option.dhcp_server_id, dhcp.hw.mac_addr
  STP     stp.root.hw, stp.root.prio, vlan.id (PVST+ lleva una raiz por VLAN)
  DTP     dtp.version
  HSRP    hsrp.priority/group/auth_data; hsrp2.priority/group/auth_data/md5_auth_data
  VRRP    vrrp.prio, vrrp.virt_rtr_id, vrrp.version, vrrp.auth_type
  IPv6    icmpv6.type (134 = Router Advertisement), ipv6.src
Todo queda en cap.l2x con topes (LIM_*): nunca una entrada por paquete.
"""
from __future__ import annotations

import collections

from ..util import g
from .base import COLLECTORS, RowCtx

LIM_ENTIDADES = 20       # servidores DHCP, VLAN con raiz, grupos HSRP/VRRP, origenes de RA, pares de etiquetas
LIM_ELEMENTOS = 50       # clientes y equipos dentro de cada entidad
LIM_CAMBIOS = 10         # cambios de raiz guardados por VLAN


@COLLECTORS
def capa2(rc: RowCtx) -> None:
    cap, row, idx = rc.cap, rc.row, rc.idx
    sip, frame, t = rc.sip, rc.frame, rc.t
    # ---- L2 / anomalias ----------------------------------------------- #
    op = g(row, idx, "arp.opcode")
    if op:
        cap.arp_events.append({
            "frame": frame, "t": t, "opcode": op,
            "hw": g(row, idx, "arp.src.hw_mac"),
            "sip": g(row, idx, "arp.src.proto_ipv4"),
            "dip": g(row, idx, "arp.dst.proto_ipv4"),
            "dup": g(row, idx, "arp.duplicate-address-detected"),
        })
    if g(row, idx, "stp.flags.tc") in ("1", "True"):
        cap.stp_tc += 1
    ic = g(row, idx, "icmp.type")
    if ic == "3":
        cap.icmp_unreach[f"{sip} -> {g(row, idx, 'ip.dst')}"] += 1
    qn = g(row, idx, "dns.qry.name")
    if qn:
        for name in qn.split("|"):
            cap.dns_names[name] += 1


def _primero(rc: RowCtx, campo: str) -> str:
    return rc.get(campo).split("|")[0]


def _dhcp(rc: RowCtx, x: dict) -> None:
    tipo = _primero(rc, "dhcp.option.dhcp")
    if tipo not in ("2", "5"):                 # 2 = OFFER, 5 = ACK
        return
    servidor = _primero(rc, "dhcp.option.dhcp_server_id") or rc.sip
    if not servidor:
        return
    d = x.setdefault("dhcp", {})
    e = d.get(servidor)
    if e is None:
        if len(d) >= LIM_ENTIDADES:
            return
        e = d[servidor] = {"ip": rc.sip, "macs": set(), "ofertas": 0, "acks": 0, "clientes": set(),
                           "t": rc.t, "frame": rc.frame}
    e["ofertas" if tipo == "2" else "acks"] += 1
    if rc.smac and len(e["macs"]) < LIM_ELEMENTOS:
        e["macs"].add(rc.smac)
    cliente = _primero(rc, "dhcp.hw.mac_addr")
    if cliente and len(e["clientes"]) < LIM_ELEMENTOS:
        e["clientes"].add(cliente)


def _stp(rc: RowCtx, x: dict) -> None:
    raiz = _primero(rc, "stp.root.hw")
    if not raiz:
        return
    prio = _primero(rc, "stp.root.prio")
    ident = f"{prio}/{raiz}" if prio else raiz
    vlan = _primero(rc, "vlan.id")
    r = x.setdefault("stp_raiz", {})
    e = r.get(vlan)
    if e is None:
        if len(r) < LIM_ENTIDADES:
            r[vlan] = {"primera": ident, "ultima": ident, "t": rc.t, "cambios": [], "n_cambios": 0}
    elif ident != e["ultima"]:
        e["n_cambios"] += 1
        if len(e["cambios"]) < LIM_CAMBIOS:
            e["cambios"].append([ident, rc.t, rc.frame])
        e["ultima"] = ident
    if rc.smac:
        src = x.setdefault("stp_origen", collections.Counter())
        if rc.smac in src or len(src) < LIM_ELEMENTOS:
            src[rc.smac] += 1


def _ha(rc: RowCtx, x: dict) -> None:
    """HSRP y VRRP: protocolo, grupo, autenticacion y prioridad por equipo (se identifica por IP de origen)."""
    if _primero(rc, "hsrp.priority"):
        proto, grupo, prio = "HSRP", _primero(rc, "hsrp.group"), _primero(rc, "hsrp.priority")
        auth = "texto" if _primero(rc, "hsrp.auth_data") else "ninguna"          # HSRPv1 siempre lleva texto
    elif _primero(rc, "hsrp2.priority"):
        proto, grupo, prio = "HSRP", _primero(rc, "hsrp2.group"), _primero(rc, "hsrp2.priority")
        auth = ("md5" if _primero(rc, "hsrp2.md5_auth_data")
                else "texto" if _primero(rc, "hsrp2.auth_data") else "ninguna")
    elif _primero(rc, "vrrp.prio"):
        proto, grupo, prio = "VRRP", _primero(rc, "vrrp.virt_rtr_id"), _primero(rc, "vrrp.prio")
        tipo = _primero(rc, "vrrp.auth_type")
        auth = "texto" if tipo == "1" else "ah" if tipo == "2" else "ninguna"     # VRRPv3 no define autenticacion
    else:
        return
    if not rc.sip:
        return
    try:
        prio_n = int(prio)
    except ValueError:
        return
    h = x.setdefault("ha", {})
    clave = f"{proto}/{grupo}"
    e = h.get(clave)
    if e is None:
        if len(h) >= LIM_ENTIDADES:
            return
        e = h[clave] = {"proto": proto, "grupo": grupo, "auth": set(), "equipos": {}, "primero": rc.sip,
                        "t": rc.t, "frame": rc.frame}
    e["auth"].add(auth)
    if rc.sip in e["equipos"] or len(e["equipos"]) < LIM_ELEMENTOS:
        e["equipos"][rc.sip] = max(prio_n, e["equipos"].get(rc.sip, 0))


@COLLECTORS
def ataques_capa2(rc: RowCtx) -> None:
    """T10a (D72): DHCP, STP, DTP, doble etiqueta, HSRP/VRRP y Router Advertisement."""
    x = rc.cap.l2x
    _dhcp(rc, x)
    _stp(rc, x)
    _ha(rc, x)
    if rc.get("dtp.version") and rc.smac:
        d = x.setdefault("dtp", {})
        if rc.smac in d or len(d) < LIM_ENTIDADES:
            d[rc.smac] = d.get(rc.smac, 0) + 1
    vlans = [v for v in rc.get("vlan.id").split("|") if v]
    if len(vlans) >= 2:
        d = x.setdefault("doble_vlan", {})
        par = "/".join(vlans[:2])
        if par in d or len(d) < LIM_ENTIDADES:
            e = d.setdefault(par, {"n": 0, "macs": set(), "t": rc.t})
            e["n"] += 1
            if rc.smac and len(e["macs"]) < LIM_ELEMENTOS:
                e["macs"].add(rc.smac)
    if _primero(rc, "icmpv6.type") == "134" and rc.smac:
        d = x.setdefault("ra", {})
        if rc.smac in d or len(d) < LIM_ENTIDADES:
            e = d.setdefault(rc.smac, {"ip": _primero(rc, "ipv6.src"), "n": 0, "t": rc.t})
            e["n"] += 1
