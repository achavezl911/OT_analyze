"""Modelo de un switch (SW1a): lo que produce el lector de la CLI de Cisco IOS/IOS-XE.

Es solo dato. Nunca guarda contrasenas, usuarios, comunidades SNMP, llaves AAA ni certificados:
de las credenciales solo se conserva un conteo por tipo (`credenciales`).
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Puerto:
    nombre: str
    descripcion: str = ""
    modo: str = ""                     # access | trunk | routed | "" (sin configurar)
    vlan_acceso: int | None = None
    vlans_trunk: list = field(default_factory=list)   # permitidas explicitas; con trunk_todas, vacio
    trunk_todas: bool = False          # trunk sin lista (todas las VLAN)
    vlan_nativa: int | None = None
    canal: int | None = None           # channel-group al que pertenece
    apagado: bool = False              # shutdown en la configuracion
    estado: str = ""                   # up | down | admin down (show interfaces description / ip int brief)
    protocolo: str = ""                # up | down
    en_config: bool = False            # aparece en la running-config
    modo_explicito: bool = False       # la configuracion trae `switchport mode access|trunk`
    portfast: bool = False             # spanning-tree portfast [edge]
    portfast_off: bool = False         # spanning-tree portfast disable
    bpduguard: bool = False            # spanning-tree bpduguard enable
    bpduguard_off: bool = False        # spanning-tree bpduguard disable
    root_guard: bool = False           # spanning-tree guard root
    storm_broadcast: bool = False      # storm-control broadcast level ...
    port_security: bool = False        # switchport port-security
    nonegotiate: bool = False          # switchport nonegotiate
    dtp: str = ""                      # auto | desirable (switchport mode dynamic ...)


@dataclass
class Svi:
    vlan: int
    ip: str
    mascara: str


@dataclass
class SesionSpan:
    id: int
    vlans_origen: list = field(default_factory=list)
    interfaces_origen: list = field(default_factory=list)
    destino: str = ""


@dataclass
class Vecino:
    id_equipo: str
    ip: str = ""
    plataforma: str = ""
    interfaz: str = ""
    puerto_remoto: str = ""


@dataclass
class CambioStp:
    """Una instancia de spanning-tree en `show spanning-tree detail`."""
    instancia: str                     # VLAN10 | MST0
    cambios: int = 0
    hace_s: int | None = None          # segundos desde el ultimo cambio de topologia
    puerto: str = ""                   # puerto desde el que llego el ultimo cambio
    raiz: str = ""                     # "local" o la MAC del puente raiz
    prioridad: int | None = None       # prioridad base del puente de este switch (Bridge Identifier)
    puente: str = ""                   # MAC del puente de este switch en la instancia
    puertos: list = field(default_factory=list)       # [PuertoStp]


@dataclass
class PuertoStp:
    """Un puerto de una instancia de `show spanning-tree detail`."""
    nombre: str
    numero: int
    estado: str = ""                   # "root forwarding", "backup blocking", ...
    puente_designado: str = ""         # MAC del puente designado del segmento
    puerto_designado: int | None = None   # numero del puerto designado ("Designated port id is 128.N")
    bpdu_recibidas: int | None = None
    portfast: bool = False             # "The port is in the portfast mode"


@dataclass
class Contador:
    """Contadores acumulados de un puerto (show interfaces / counters errors)."""
    puerto: str
    paquetes: int | None = None
    broadcast: int | None = None
    errores: int = 0
    crc: int = 0
    descartes: int = 0                 # OutDiscards / Total output drops (acumulados)
    paquetes_salida: int | None = None
    limpieza: str = ""                 # "Last clearing of show interface counters ..."
    bw_kbit: int | None = None         # "BW 100000 Kbit/sec" (L1, D81)
    tasa_entrada_bps: int | None = None    # "5 minute input rate N bits/sec"
    tasa_salida_bps: int | None = None     # "5 minute output rate N bits/sec"


@dataclass
class Switch:
    hostname: str = ""
    modelo: str = ""
    version: str = ""
    vlans: dict = field(default_factory=dict)         # {id: nombre}
    puertos: list = field(default_factory=list)       # [Puerto]
    svis: list = field(default_factory=list)          # [Svi]
    span: list = field(default_factory=list)          # [SesionSpan]
    mac: list = field(default_factory=list)           # [(vlan, mac "aa:bb:cc:dd:ee:ff", puerto)]
    cdp: list = field(default_factory=list)           # [Vecino]
    credenciales: dict = field(default_factory=dict)  # {tipo: conteo}; jamas valores ni usuarios
    http: str = ""                                    # "" | http | https | http,https
    vty_transport: list = field(default_factory=list)
    config: bool = False                              # la sesion trae running-config
    aaa_modelo: bool = False                          # aaa new-model
    servidores_aaa: int = 0                           # servidores TACACS+/RADIUS (solo el conteo)
    stp_modo: str = ""                                # pvst | rapid-pvst | mst
    stp_loopguard: bool = False                       # spanning-tree loopguard default
    stp_portfast_defecto: bool = False                # spanning-tree portfast [edge] default
    stp_bpduguard_defecto: bool = False               # spanning-tree portfast [edge] bpduguard default
    udld: bool = False                                # udld enable | aggressive (global)
    dhcp_snooping: bool = False                       # ip dhcp snooping (global)
    dhcp_snooping_vlans: list = field(default_factory=list)
    dai_vlans: list = field(default_factory=list)     # ip arp inspection vlan
    stp: list = field(default_factory=list)           # [CambioStp]
    macflap: list = field(default_factory=list)       # [(mac, vlan, "puertoA puertoB", veces)]
    log_fechadas: int = 0                             # lineas del log con fecha (solo el conteo)
    log_sin_sincronizar: int = 0                      # ... de ellas con "*" delante (hora no autoritativa)
    log_sincronia_perdida: int = 0                    # ... con "." delante (sincronizada pero se perdio)
    ntp_servidores: int = 0                           # lineas `ntp server|peer` de la configuracion (conteo)
    macflap_total: int = 0                           # mensajes de MAC flapping en el log
    errdisable: list = field(default_factory=list)    # [(puerto, motivo, veces)]
    contadores: list = field(default_factory=list)    # [Contador]
    leyo: list = field(default_factory=list)          # salidas de estado leidas: stp | logging | interfaces | espejo (AOS-CX)
    avisos: list = field(default_factory=list)
    archivo: str = ""
    origen: str = "cli"                               # cli (Cisco IOS) | snmp (recorrido SNMP, sin SPAN ni config) | aoscx (CLI de Aruba AOS-CX, solo estado)

    def puerto(self, nombre: str):
        from .cisco_ios import clave_if
        k = clave_if(nombre)
        return next((p for p in self.puertos if clave_if(p.nombre) == k), None)
