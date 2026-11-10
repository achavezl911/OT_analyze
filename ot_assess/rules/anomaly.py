"""Reglas de anomalias de capa 2 y de comportamiento."""
from __future__ import annotations

import collections

from ..i18n import t, unir
from ..model import Capture
from ..util import is_host_ip, is_unicast_mac
from .base import RULES, finding


@RULES
def conflicto_arp(cap: Capture) -> None:
    # --- ARP ----------------------------------------------------------------#
    ip2mac = collections.defaultdict(set)
    mac2ip = collections.defaultdict(set)
    for e in cap.arp_events:
        # Un ARP probe anuncia 0.0.0.0 como origen: no es un duplicado de IP.
        if is_host_ip(e["sip"]) and is_unicast_mac(e["hw"]):
            ip2mac[e["sip"]].add(e["hw"])
            mac2ip[e["hw"]].add(e["sip"])
    conflicts = {ip: macs for ip, macs in ip2mac.items() if len(macs) > 1}
    if conflicts:
        finding(
            cap, "Alta",
            "Conflicto de direcciones: una misma IP anunciada por varias MAC",
            unir("\n", (t("- {ip}: {macs}", ip=ip, macs=", ".join(sorted(m)))
                        for ip, m in list(conflicts.items())[:10])),
            "Puede ser un duplicado de IP por error de configuracion o un intento de "
            "ARP spoofing. En una red de control, un ARP spoofing exitoso permite "
            "interceptar o alterar comandos entre HMI y controlador.",
            "Identificar los equipos por puerto de switch, corregir duplicados y "
            "habilitar Dynamic ARP Inspection y DHCP snooping donde el switch lo soporte.",
            categoria="Anomalia",
        )


@RULES
def arp_duplicado(cap: Capture) -> None:
    dup_flag = [e for e in cap.arp_events if e["dup"]]
    if dup_flag:
        finding(
            cap, "Alta",
            "Wireshark marco deteccion de direccion duplicada en ARP",
            t("{n} eventos; primero en la trama {frame}", n=len(dup_flag), frame=dup_flag[0]["frame"]),
            "Confirma el punto anterior con la propia deteccion del disector.",
            "Resolver el duplicado antes de cualquier otra accion: provoca perdida "
            "intermitente de comunicacion con el equipo afectado.",
            categoria="Anomalia",
        )


@RULES
def barrido_arp(cap: Capture) -> None:
    # escaneo ARP: un host preguntando por muchas IPs
    asker = collections.Counter()
    for e in cap.arp_events:
        if e["opcode"] == "1" and e["dip"]:
            asker[e["hw"]] += 1
    targets = collections.defaultdict(set)
    for e in cap.arp_events:
        if e["opcode"] == "1" and e["dip"] and e["hw"]:
            targets[e["hw"]].add(e["dip"])
    sweepers = {m: dips for m, dips in targets.items() if len(dips) >= 25}
    if sweepers:
        finding(
            cap, "Media",
            "Barrido ARP: un equipo pregunta por muchas direcciones",
            unir("\n", (t("- {mac} ({vendor}): {n} IPs distintas", mac=m,
                          vendor=cap.hosts.get(m, {}).get("vendor", "?"), n=len(dips))
                        for m, dips in list(sweepers.items())[:8])),
            "Puede ser una herramienta de descubrimiento legitima (inventario, el "
            "propio escaner del cliente) o reconocimiento no autorizado. Conviene "
            "atribuirlo antes de descartarlo.",
            "Confirmar con el cliente si corresponde a una herramienta autorizada y "
            "en que ventana se ejecuto.",
            categoria="Anomalia",
        )


@RULES
def escaneo_red(cap: Capture) -> None:
    # --- escaneo de puertos / hosts ----------------------------------------#
    scan_ports = collections.defaultdict(set)
    scan_hosts = collections.defaultdict(set)
    for f in cap.flows.values():
        if f["dport"] and is_host_ip(f["src"]) and is_host_ip(f["dst"]):
            scan_ports[f["src"]].add((f["dst"], f["dport"]))
            scan_hosts[f["src"]].add(f["dst"])
    port_scanners = {s: v for s, v in scan_ports.items() if len(v) >= 50}
    host_scanners = {s: v for s, v in scan_hosts.items() if len(v) >= 25}
    if port_scanners or host_scanners:
        lines = []
        for s, v in list(port_scanners.items())[:5]:
            lines.append(t("- {src}: {n} pares destino/puerto distintos", src=s, n=len(v)))
        for s, v in list(host_scanners.items())[:5]:
            lines.append(t("- {src}: contacto con {n} destinos distintos", src=s, n=len(v)))
        finding(
            cap, "Media",
            "Patron compatible con escaneo de red",
            unir("\n", lines),
            "El escaneo activo en redes OT puede tumbar dispositivos de campo que no "
            "toleran trafico inesperado. Si es el escaner del cliente, explica tambien "
            "por que esa herramienta genera hallazgos que un sensor pasivo no produce.",
            "Atribuir el origen. Si es una herramienta autorizada, documentar la "
            "ventana y evaluar el riesgo de escaneo activo sobre nivel 1.",
            categoria="Anomalia",
        )


@RULES
def difusion(cap: Capture) -> None:
    # --- storms -------------------------------------------------------------#
    bcast = sum(c for (s, d), c in cap.l2_flows.items() if d == "ff:ff:ff:ff:ff:ff")
    if cap.flow_packets and bcast / cap.flow_packets > 0.20:
        finding(
            cap, "Media",
            "Proporcion alta de trafico de difusion",
            t("{n} de {total} paquetes ({pct}) son broadcast", n=bcast, total=cap.flow_packets,
              pct=f"{bcast / cap.flow_packets:.0%}"),
            "Un exceso de difusion degrada el desempeno de los dispositivos de campo, "
            "que tienen pilas de red limitadas, y puede causar perdida de comunicacion.",
            "Revisar storm control en los switches y reducir el tamano del dominio de difusion.",
            categoria="Desempeno",
        )


@RULES
def stp(cap: Capture) -> None:
    if cap.stp_tc > 20:
        finding(
            cap, "Media",
            "Cambios de topologia STP frecuentes",
            t("{n} notificaciones de cambio de topologia (TCN)", n=cap.stp_tc),
            "Un STP inestable provoca microcortes. En control, un microcorte puede "
            "derivar en perdida de comunicacion con un controlador y en un disparo.",
            "Identificar el puerto que genera los TCN y habilitar PortFast/Edge Port "
            "y BPDU Guard en los puertos de dispositivos finales.",
            categoria="Desempeno",
        )
