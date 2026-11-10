"""Modelo comun de firewall (F1a): lo que producen los adaptadores por fabricante.

Es solo dato: ningun adaptador ni formato de salida vive aqui. Convenciones:
- Redes como ipaddress.IPv4Network; "any" = 0.0.0.0/0. IPv6 no se modela todavia.
- Una lista de redes vacia en una regla significa "no se pudo resolver" (ver Regla.no_resuelto),
  no "cualquiera".
- puertos vacio = todos los puertos (o el protocolo no usa puertos); protocolos vacio = todos.
- Las uniones de varias lineas de una misma regla pierden la relacion origen-puerto exacta
  (producto cartesiano): el modelo es una aproximacion para analisis pasivo, no un motor de decision.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

TIPOS_RUTA = ("conectada", "local", "estatica", "dinamica", "defecto")
ACCIONES = ("permitir", "bloquear", "confiar")


@dataclass
class Interfaz:
    fisica: str                      # p. ej. GigabitEthernet0/0
    nombre: str = ""                 # nameif
    ip: str = ""
    mascara: str = ""
    seguridad: int | None = None
    zona: str = ""


@dataclass
class Ruta:
    red: ipaddress.IPv4Network
    interfaz: str                    # nameif tal como lo imprime show route
    salto: str = ""                  # vacio en rutas conectadas/locales
    tipo: str = "estatica"           # TIPOS_RUTA
    codigo: str = ""                 # codigo original (C, L, S*, O E2...)
    distancia: int | None = None
    metrica: int | None = None


@dataclass
class Arp:
    interfaz: str                    # nameif
    ip: str
    mac: str
    edad: int | None = None          # segundos; None con `-` o `alias`


@dataclass
class Objeto:
    nombre: str
    tipo: str                        # red | servicio | protocolo
    # red: IPv4Network; servicio: (proto, inicio, fin) con inicio None = sin restriccion de puerto;
    # protocolo: str. Los grupos ya vienen aplanados.
    valores: list = field(default_factory=list)
    sin_resolver: list[str] = field(default_factory=list)   # fqdn, referencias sin definir, puertos


@dataclass
class Subregla:
    """Una linea ACL tal como la evalua el firewall (el contraste usa esto, no la union de Regla).
    Listas vacias = todos (protocolos, puertos) o sin interfaz fija (zonas); redes vacias = sin resolver."""
    protocolos: list[str] = field(default_factory=list)
    origen: list[ipaddress.IPv4Network] = field(default_factory=list)
    destino: list[ipaddress.IPv4Network] = field(default_factory=list)
    puertos_origen: list[tuple[int, int]] = field(default_factory=list)
    puertos_destino: list[tuple[int, int]] = field(default_factory=list)
    zonas_origen: list[str] = field(default_factory=list)
    zonas_destino: list[str] = field(default_factory=list)
    linea: str = ""


@dataclass
class Regla:
    id: str
    nombre: str = ""
    politica: str = ""
    seccion: str = ""
    accion: str = "permitir"         # ACCIONES
    protocolos: list[str] = field(default_factory=list)
    origen: list[ipaddress.IPv4Network] = field(default_factory=list)
    destino: list[ipaddress.IPv4Network] = field(default_factory=list)
    puertos: list[tuple[int, int]] = field(default_factory=list)
    zonas_origen: list[str] = field(default_factory=list)     # palabra ifc (nameif)
    zonas_destino: list[str] = field(default_factory=list)
    registro: bool = False
    activa: bool = True
    aciertos: int = 0
    primer_acierto: str = ""         # UTC, "AAAA-MM-DD HH:MM:SS"
    ultimo_acierto: str = ""
    lineas: list[str] = field(default_factory=list)           # lineas ACL de origen
    acl: str = ""
    no_resuelto: list[str] = field(default_factory=list)
    subreglas: list[Subregla] = field(default_factory=list)   # una por linea ACL, en orden


@dataclass
class Nat:
    interfaces: list[str] = field(default_factory=list)       # [interna, externa]
    tipo: str = ""                   # static | dynamic
    objetos: list[str] = field(default_factory=list)
    descripcion: str = ""
    texto: str = ""                  # linea nat original, para evaluarla despues
    # D70: campos explicitos. Los nombres son el texto de la configuracion; las redes son el objeto ya
    # resuelto (None = cualquiera, [] = sin resolver).
    linea: int = 0                   # orden de la linea nat en la configuracion (1 = primera)
    seccion: int = 1                 # 1 twice NAT, 2 object NAT, 3 twice NAT `after-auto`
    clase: str = "twice"             # twice | objeto
    modo: str = "static"             # static | dynamic | pat
    origen_real: str = ""
    origen_mapeado: str = ""
    destino_mapeado: str = ""
    destino_real: str = ""
    red_origen_real: list | None = None
    red_origen_mapeado: list | None = None
    red_destino_mapeado: list | None = None
    red_destino_real: list | None = None
    destino: bool = False            # la regla trae `destination static`
    inactiva: bool = False
    unidireccional: bool = False
    con_servicio: bool = False       # `service`: traduccion de puertos, no modelada
    modelable: bool = True
    motivo: str = ""                 # por que no es modelable
    # F6b: de `show nat detail` (None = la sesion no lo trae o la regla no se emparejo)
    hits_traducidos: int | None = None       # translate_hits desde el ultimo clear
    hits_inversos: int | None = None         # untranslate_hits
    redes_detalle: dict = field(default_factory=dict)   # origen_real|origen_mapeado|destino_mapeado|destino_real
    desde_detalle: bool = False      # se modelo con las redes de show nat detail (faltaba un objeto)


@dataclass
class Firewall:
    fabricante: str = ""
    hostname: str = ""
    interfaces: list[Interfaz] = field(default_factory=list)
    rutas: list[Ruta] = field(default_factory=list)
    objetos: list[Objeto] = field(default_factory=list)
    reglas: list[Regla] = field(default_factory=list)
    nat: list[Nat] = field(default_factory=list)
    avisos: list[str] = field(default_factory=list)
    arp: list[Arp] = field(default_factory=list)
    nat_detalle: dict = field(default_factory=dict)   # F6b: {} sin show nat detail; si no, conteos

    def ruta_de(self, ip) -> Ruta | None:
        """Ruta mas especifica que contiene la IP; None si ninguna. Empate de prefijo: la primera del archivo."""
        try:
            a = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            return None
        mejor = None
        for r in self.rutas:
            if a in r.red and (mejor is None or r.red.prefixlen > mejor.red.prefixlen):
                mejor = r
        return mejor

    def interfaz_de(self, ip) -> str | None:
        """Interfaz (nameif) de la ruta mas especifica que contiene la IP; None si ninguna."""
        r = self.ruta_de(ip)
        return r.interfaz if r else None

    def zona_de(self, interfaz: str) -> str:
        """Zona de una interfaz dada por nameif o por nombre fisico ('' si no existe)."""
        k = str(interfaz).lower()
        for i in self.interfaces:
            if k in (i.nombre.lower(), i.fisica.lower()):
                return i.zona
        return ""
