"""Reglas de exposicion, obsolescencia e identidad expuesta."""
from __future__ import annotations

import collections
import re

from ..catalog import OBSOLETE_PATTERNS
from ..i18n import t, unir
from ..model import Capture
from ..util import port_info
from .base import RULES, finding, protos_of


@RULES
def descubrimiento_windows(cap: Capture) -> None:
    protos = protos_of(cap)
    # --- protocolos de descubrimiento IT en red de control ----------------- #
    noisy = {}
    for name, key in (("LLMNR", "llmnr"), ("NBT-NS", "nbns"), ("mDNS", "mdns"),
                      ("SSDP/UPnP", "ssdp"), ("SMB Browser", "browser")):
        if key in protos:
            noisy[name] = protos[key]
    if noisy:
        finding(
            cap, "Media",
            "Protocolos de descubrimiento de Windows activos en la red de control",
            unir(", ", (t("{k}: {v} tramas", k=k, v=v) for k, v in noisy.items())),
            "LLMNR, NBT-NS y mDNS permiten envenenamiento de resolucion de nombres "
            "(Responder y similares) para capturar hashes NTLM y suplantar servicios. "
            "Un escaner pasivo de corte IT suele reportar esto como vulnerabilidad; "
            "una plataforma OT lo clasifica como higiene y puede no levantar alerta.",
            "Deshabilitar LLMNR y NetBIOS sobre TCP/IP por GPO en los hosts Windows "
            "de la red OT, y bloquear SSDP/mDNS entre VLANs.",
            categoria="Exposicion",
        )


@RULES
def sentinel_hasp(cap: Capture) -> None:
    # --- Sentinel / licenciamiento ----------------------------------------- #
    lic = [f for f in cap.flows.values() if f["dport"] == "1947"]
    if lic:
        srcs = sorted({f["src"] for f in lic})
        finding(
            cap, "Media",
            "Servicio de licenciamiento Sentinel HASP (puerto 1947) en difusion",
            t("{n} flujos hacia udp/1947 desde {srcs}", n=len(lic), srcs=", ".join(srcs[:5])),
            "El Sentinel LDK/HASP Run-time expone un servicio administrativo web local "
            "y ha acumulado vulnerabilidades criticas (ejecucion remota y denegacion de "
            "servicio). En plantas suele venir embebido con el software de ingenieria y "
            "queda sin parchear. Es un hallazgo tipico de escaneres que miran puertos IT.",
            "Inventariar los hosts con Sentinel, actualizar el runtime al ultimo "
            "release del fabricante y restringir el 1947 a loopback si la licencia es local.",
            categoria="Exposicion",
        )


@RULES
def texto_claro(cap: Capture) -> None:
    # --- texto claro --------------------------------------------------------#
    if cap.cleartext:
        por_tipo = collections.Counter(c["tipo"] for c in cap.cleartext)
        finding(
            cap, "Alta",
            "Credenciales o administracion en texto claro",
            t("{lista}", lista="; ".join(f"{k}: {v}" for k, v in por_tipo.most_common())),
            "Cualquiera con acceso al segmento puede leer credenciales y comandos de "
            "administracion. En OT esto suele ser el camino mas corto de una red de "
            "planta a un controlador.",
            "Migrar a SSH/HTTPS/SNMPv3 donde el equipo lo soporte; donde no, aislar "
            "la administracion en una VLAN dedicada con acceso por jump server.",
            categoria="Exposicion",
            activos=[c["ip"] for c in cap.cleartext if c.get("ip")],
        )


@RULES
def gestion_sin_cifrar(cap: Capture) -> None:
    cleartext_ports = collections.Counter()
    for f in cap.flows.values():
        name, cat = port_info(f["dport"], f["l4"])
        if cat == "claro":
            cleartext_ports[name] += f["pkts"]
    if cleartext_ports:
        finding(
            cap, "Media",
            "Protocolos de gestion sin cifrar en uso",
            unir(", ", (t("{k}: {v} paquetes", k=k, v=v) for k, v in cleartext_ports.most_common())),
            "Telnet, FTP, TFTP, HTTP y SNMPv1/v2c transportan credenciales y "
            "configuracion sin proteccion. TFTP ademas se usa para cargar firmware.",
            "Deshabilitar los servicios que no se usen y sustituir los necesarios por "
            "su equivalente cifrado.",
            categoria="Exposicion",
        )


@RULES
def software_obsoleto(cap: Capture) -> None:
    # --- software obsoleto --------------------------------------------------#
    obsolete = []
    for ident in cap.identity:
        blob = f"{ident['valor']} {ident['detalle']}"
        for pat, label, nota in OBSOLETE_PATTERNS:
            if re.search(pat, blob, re.I):
                obsolete.append((ident.get("ip") or ident.get("mac"), label, nota, blob[:160]))
    if obsolete:
        seen, lines = set(), []
        for ip, label, nota, blob in obsolete:
            k = (ip, label)
            if k in seen:
                continue
            seen.add(k)
            lines.append(t("- {ip}: {label} — {nota} | evidencia: {blob}",
                           ip=ip, label=label, nota=t(nota), blob=blob))
        finding(
            cap, "Alta",
            "Software o sistema operativo fuera de soporte",
            unir("\n", lines),
            "Un sistema sin soporte no recibe parches. Es exactamente el tipo de "
            "hallazgo que un motor de CVE pasivo emite en cuanto logra leer la version.",
            "Levantar plan de reemplazo o compensar con aislamiento de red y control "
            "de acceso estricto mientras se reemplaza.",
            categoria="Obsolescencia",
        )


@RULES
def firmware_expuesto(cap: Capture) -> None:
    # --- firmware visible = material para CVE ------------------------------- #
    fw = [i for i in cap.identity if i["tipo"] in ("CDP", "LLDP") and i["detalle"]]
    if fw:
        finding(
            cap, "Informativa",
            "Version de firmware expuesta en protocolos de descubrimiento",
            unir("\n", (t("- {valor}: {detalle}", valor=i["valor"], detalle=i["detalle"][:180])
                        for i in fw[:15])),
            "CDP y LLDP anuncian modelo y version de firmware en texto claro. Es la "
            "fuente principal de la que un motor pasivo deriva CVEs. Tambien le sirve "
            "a un atacante con acceso al segmento para elegir exploit sin escanear.",
            "Deshabilitar CDP/LLDP en puertos de acceso que no lo necesiten y "
            "contrastar cada version contra el aviso de seguridad del fabricante "
            "(Cisco PSIRT, Siemens SSA, Rockwell SD).",
            categoria="Identidad",
        )
