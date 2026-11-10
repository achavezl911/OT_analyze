"""Modelos de datos: una captura analizada y el resultado consolidado."""
from __future__ import annotations

import collections
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .util import vendor_of


class Capture:
    def __init__(self, path: Path):
        self.path = path
        self.name = path.name
        self.info: dict = {}
        self.error = ""          # causa si la captura no se pudo leer; vacia = legible
        self.protos: dict[str, int] = {}
        self.sampled = False
        self.flow_packets = 0

        # Activos: clave = MAC
        self.hosts: dict[str, dict] = {}
        # Flujos: (src, dst, dport, proto) -> dict
        self.flows: dict[tuple, dict] = {}
        self.ventana: list = []   # [primer, ultimo] instante (epoch) leido; lo fija flows.py (T5)
        self.cobertura: dict = {}   # C1 (D80): Acumulador.cerrar() de cobertura_captura.py; lo fija flows.py
        self.l2_flows: collections.Counter = collections.Counter()
        self.vlans: collections.Counter = collections.Counter()
        self.ethertypes: collections.Counter = collections.Counter()

        # Evidencia del pase de detalle
        self.identity: list[dict] = []
        self.cleartext: list[dict] = []
        self.control_ops: list[dict] = []
        self.protocolo_eventos: list[dict] = []   # T4: ver detail/protocolos.py
        self.arp_events: list[dict] = []
        self.dns_names: collections.Counter = collections.Counter()
        self.dns_eventos: list[dict] = []        # ver detail/dns.py
        self.nombres_servidor: list[dict] = []   # {"fuente": "TLS SNI"|"HTTP Host", "ip", "nombre", "src", "t"}
        self.dominios_internos: tuple = ()   # del perfil; lo fija cli antes de las reglas
        self.tor_relays = None               # lista de relays Tor (evasion.cargar_relays); la fija cli antes de las reglas
        self.stp_tc = 0
        self.icmp_unreach: collections.Counter = collections.Counter()
        # T10a (D72): evidencia acotada de ataques de capa 2 y bucles; claves en detail/l2.py y bucles.py
        self.l2x: dict = {}

        self.findings: list[dict] = []

    # -- helpers de inventario -------------------------------------------- #

    def host(self, mac: str, resolved: str = "") -> dict:
        h = self.hosts.get(mac)
        if h is None:
            h = {
                "mac": mac,
                "vendor": vendor_of(resolved, mac),
                "ips": set(),
                "vlans": set(),
                "tx_pkts": 0,
                "rx_pkts": 0,
                "tx_bytes": 0,
                "rx_bytes": 0,
                "proto_seen": collections.Counter(),
                "ports_served": collections.Counter(),
                "ports_used": collections.Counter(),
                "peers": set(),
                "hostnames": set(),
                "fingerprints": set(),
                "first": None,
                "last": None,
            }
            self.hosts[mac] = h
        if not h["vendor"] and resolved:
            h["vendor"] = vendor_of(resolved, mac)
        return h


@dataclass
class Assessment:
    """Todo lo que los escritores de reporte necesitan, en un solo objeto."""
    caps: list
    assets: dict
    conduits: list
    args: Any
    diagrams: list = field(default_factory=list)
    estandares: list = field(default_factory=list)   # el primero es el de referencia
    entorno: dict = field(default_factory=dict)      # ver entorno.py
    perfil: dict = field(default_factory=dict)       # ver perfil.py; vacio sin --perfil
    firewall: dict = field(default_factory=dict)     # ver firewall.contrastar; vacio sin --reglas-firewall
    rutas: dict = field(default_factory=dict)        # ver rutas_firewall.aplicar; vacio sin --rutas-firewall
    fuentes: dict = field(default_factory=dict)      # fuentes.calcular; vacio sin --fuente NOMBRE=RUTA
    switches: dict = field(default_factory=dict)    # switches.integracion.integrar (SW1a); vacio sin --switch
    zonas: dict = field(default_factory=dict)       # zonas.asignar; zonas de cada activo (Z1a)
    zcr: dict = field(default_factory=dict)         # conductos_zcr.construir; conductos entre zonas (Z1b)
    linea_base: dict = field(default_factory=dict)  # linea_base.construir (B7b); vacio sin zonas
    matriz_controles: dict = field(default_factory=dict)   # matriz_controles.construir (B7c): parte NIST
    rutas_ataque: dict = field(default_factory=dict)   # rutas_ataque.construir (A1)
    inventario_normalizado: dict = field(default_factory=dict)   # inventario_normalizado.construir (I1a, D78)
    obsolescencia: dict = field(default_factory=dict)   # obsolescencia.construir (I1b, D79)
    cobertura_captura: dict = field(default_factory=dict)   # cobertura_captura.construir (C1, D80)
    salud_red: dict = field(default_factory=dict)           # salud_red.construir (L1, D81)
    sensores: dict = field(default_factory=dict)            # sensores.construir (S1, D96); vacio sin capturas
    linea_base_aprobada: dict = field(default_factory=dict)   # linea_base_aprobada.evaluar (LB1, D82)
    riesgos: dict = field(default_factory=dict)         # riesgo.de (R1, D83): registro, mapa de calor y quick wins
    madurez: dict = field(default_factory=dict)         # madurez.construir (M7, D84): madurez por dominio
    tobe: dict = field(default_factory=dict)            # tobe.construir (T1a, D85): allowlist zona x zona propuesta
    hardening: dict = field(default_factory=dict)       # hardening.construir (T1b, D86): hardening por tipo de equipo
    direccionamiento: dict = field(default_factory=dict)   # direccionamiento.construir (G1b, D88): redes observadas
    vuln_firmware: dict = field(default_factory=dict)   # vuln_firmware.construir (V1a, D89): candidatas por firmware
    fuentes_log: dict = field(default_factory=dict)     # fuentes_log.construir (G1a, D87): fuentes y colectores de log
    diagrama_zcr: Any = None                  # diagram.diagrama_zcr; se escribe aparte de `diagrams`
    diagrama_tobe: Any = None                 # diagram.diagrama_tobe; tambien aparte de `diagrams`
    extras: list =field(default_factory=list)       # Capture que solo aportan hallazgos (no son capturas)
    vulnerabilidades: dict = field(default_factory=dict)   # vulnerabilidades.resumen; vacio sin la opcion
    vulns_cruces: list = field(default_factory=list)       # vulnerabilidades.cruzar; para la tabla
    tor_relays: Any = None                                 # evasion.cargar_relays (T9); None sin --tor-relays
    evasion: list = field(default_factory=list)            # evasion.de_exportacion (T9, camino diagrama)
    alertas: dict = field(default_factory=dict)          # alertas.resumen_completo; vacio sin la opcion
    alertas_asoc: list = field(default_factory=list)       # alertas.asociar; para la tabla
