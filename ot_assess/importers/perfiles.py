"""Reconocimiento de columnas y valores de exportaciones de plataformas OT.

IMPORTANTE: los alias de columna de abajo son los nombres habituales de cada campo, tomados de
la documentacion publica de las APIs y de la practica. NO estan validados contra una exportacion
real de cada plataforma: los fabricantes no publican el formato de sus exportaciones y cambia
entre versiones. Por eso:
  - el mapeo detectado se imprime y se guarda junto al diagrama, para revisarlo;
  - `--mapeo` permite fijar a mano cualquier columna sin tocar el codigo.
Si una columna no se reconoce, agregar su nombre normalizado al alias del campo.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field


def normalizar(s: str) -> str:
    """'Direccion IP (v4)' -> 'direccion_ip_v4' (sin acentos, minusculas, solo [a-z0-9_])."""
    s = unicodedata.normalize("NFKD", str(s)).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")


# Campo -> alias (normalizados). Un encabezado coincide si es igual al alias (mejor), termina en
# "_alias" ('addresses_address' de un JSON anidado es una IP) o empieza con "alias_"
# ('asset_type_name' es un tipo). Una columna alimenta un solo campo.
ACTIVOS = {
    "id": ["id", "asset_id", "node_id", "device_id", "uid", "guid", "key"],
    # Nozomi (D74): vlan_id es atributo, nunca identificador; sin este campo 'vlan_id' casaba con 'id'.
    "vlan": ["vlan_id", "vlan", "vlans"],
    # Nozomi Nodes: 'address' es IPv4, IPv6, MAC o MAC@IP; el perfil lo fuerza aqui, no al campo 'ip'.
    "address": [],
    "roles": ["roles"],
    "protocolos": ["protocols"],
    "so": ["os", "operating_system"],
    "firmware_alt": ["os_or_firmware"],
    "vendor_alt": ["mac_vendor"],
    "ip": ["ip", "ip_address", "ip_addresses", "ipv4", "ipv4_address", "ipv4_addresses", "ips",
           "address", "addresses", "direccion_ip", "ip_v4"],
    "mac": ["mac", "mac_address", "mac_addresses", "macs", "mac_addr", "direccion_mac"],
    "nombre": ["name", "label", "asset_name", "device_name", "display_name", "hostname", "host_name",
               "hostnames", "insight_name", "computer_name", "dns_name", "nombre"],
    "vendor": ["vendor", "manufacturer", "vendor_name", "make", "fabricante"],
    "modelo": ["model", "product_name", "product", "model_name", "product_model", "device_model",
               "modelo"],
    "firmware": ["firmware", "firmware_version", "fw_version", "fw", "software_version", "sw_version",
                 "version"],
    "tipo": ["type", "asset_type", "device_type", "category", "device_category", "asset_category",
             "subtype", "role", "roles", "class", "device_class", "tipo", "rol"],
    "nivel": ["level", "purdue_level", "purdue", "pera_level", "purdue_model_level", "purdue_layer",
              "nivel", "nivel_purdue"],
    "zona": ["zone", "zone_name", "zones", "virtual_zone", "security_zone", "network_zone", "zona"],
    # I1a (D78): solo los lee el inventario normalizado; el resto del analisis no los usa
    "criticidad": ["criticality", "criticidad", "criticality_level", "asset_criticality"],
    "ultima": ["last_seen", "last_activity", "last_activity_time", "last_seen_time", "ultima_actividad",
               "ultima_observacion"],
    "puerto_switch": ["switch_port", "puerto_switch", "puerto_de_switch"],
    "servicios": ["services", "servicios", "open_ports", "puertos"],
}

ENLACES = {
    "origen": ["source", "src", "from", "source_ip", "src_ip", "source_address", "source_asset",
               "source_node", "source_name", "client", "client_ip", "from_node", "from_ip", "origin",
               "sender", "origen", "side_a_ip_comm"],
    "destino": ["destination", "dst", "to", "dest", "destination_ip", "dst_ip", "dest_ip",
                "destination_address", "destination_asset", "destination_node", "server", "server_ip",
                "to_node", "to_ip", "target", "receiver", "destino", "side_b_ip_comm"],
    "protocolo": ["protocol", "protocols", "service", "application", "proto", "protocol_name",
                  "app_protocol", "protocol_type", "protocolo"],
    "puerto": ["port", "dst_port", "destination_port", "dport", "server_port", "dest_port",
               "port_number", "puerto", "to_port"],
    # el puerto del cliente (efimero) nunca es el del conducto; este campo lo aparta de 'puerto'
    "puerto_origen": ["from_port", "src_port", "source_port", "sport"],
    "t_ini": ["first_activity_time"],
    "t_fin": ["last_activity_time"],
    "l4": ["transport", "transport_protocol", "ip_protocol", "l4", "l4_protocol"],
    "paquetes": ["packets", "pkts", "total_packets", "packet_count", "num_packets", "paquetes"],
    "bytes": ["bytes", "total_bytes", "byte_count", "traffic", "data_volume", "volume", "size"],
    # xDome (D37): el lado A es el de la consulta, no el iniciador; "direccion" dice quien inicio.
    "direccion": ["direction", "direccion", "flow_direction"],
    "fecha": ["date", "fecha", "day"],
    "tipo_origen": ["side_a_device_type"],
    "tipo_destino": ["side_b_device_type"],
    "nombre_destino": ["side_b_domains"],
    "ambito": ["comm_type", "communication_type"],
}

# Columna de tipo que manda sobre los alias generales en el inventario de cada plataforma:
# en xDome CATEGORY es IT/OT/IoT y el tipo real de equipo esta en TYPE.
TIPO_PREFERIDO = {"xdome": "type", "nozomi": "type"}

# Campos sin los que el diagrama no tiene sentido.
OBLIGATORIOS = {"activos": [], "enlaces": ["origen", "destino"]}


@dataclass
class Perfil:
    clave: str
    nombre: str
    firma: set = field(default_factory=set)    # encabezados normalizados que la delatan


PERFILES = {
    "nozomi": Perfil("nozomi", "Nozomi Networks", {
        "product_name", "firmware_version", "level", "zone", "mac_address", "label", "node_id", "protocols",
        # exportaciones reales de una Guardian (D74): Assets, Nodes, Sessions, Links y CVE por nodo
        "mac_vendor", "os_or_firmware", "is_ai_enriched", "transport_protocol", "from_port", "to_port",
        "is_learned", "links_count", "cve_is_kev", "cve_epss_score", "tcp_retransmission_percent",
        "transferred_bytes", "throughput_speed", "sent_bytes", "received_bytes"}),
    "claroty": Perfil("claroty", "Claroty", {"virtual_zone", "insight_name", "asset_name", "site",
                                             "network", "purdue_level", "asset_type"}),
    "xdome": Perfil("xdome", "Claroty xDome", {"side_a_ip_comm", "side_b_ip_comm", "comm_type", "direction",
                                               "side_b_domains", "sub_category", "mac_oui", "risk_score"}),
    "dragos": Perfil("dragos", "Dragos", {"pera_level", "zone_name", "zone_id", "hostnames",
                                          "ip_addresses", "asset_type", "criticality"}),
    "generico": Perfil("generico", "Exportacion generica", set()),
}


def detectar_perfil(encabezados: list) -> str:
    """Perfil cuya firma mas encabezados comparte; 'generico' si ninguno destaca."""
    norm = {normalizar(h) for h in encabezados}
    puntos = {k: len(p.firma & norm) for k, p in PERFILES.items() if p.firma}
    mejor = max(puntos, key=puntos.get, default="generico")
    unico = sorted(puntos.values(), reverse=True)[:2]
    if puntos.get(mejor, 0) < 2 or (len(unico) > 1 and unico[0] == unico[1]):
        return "generico"
    return mejor


def mapear(encabezados: list, alias: dict, forzado: dict | None = None) -> dict:
    """{campo: encabezado original}. `forzado` (campo -> encabezado) manda sobre los alias."""
    forzado = forzado or {}
    por_norm = {normalizar(h): h for h in encabezados}
    res: dict = {}
    for campo, nombre in forzado.items():
        if campo not in alias:
            raise SystemExit(f"[!] Campo desconocido en --mapeo: '{campo}'. Validos: {', '.join(alias)}")
        h = por_norm.get(normalizar(nombre))
        if h is None:
            raise SystemExit(f"[!] --mapeo: no existe la columna '{nombre}'. Columnas: {', '.join(encabezados)}")
        res[campo] = h

    candidatos = []                  # (puntaje, indice de columna, campo, encabezado)
    for i, h in enumerate(encabezados):
        n = normalizar(h)
        for campo, nombres in alias.items():
            for a in nombres:
                if n == a:
                    candidatos.append((1000 + len(a), -i, campo, h))
                elif n.endswith("_" + a):
                    candidatos.append((len(a), -i, campo, h))
                elif n.startswith(a + "_") and len(a) > 3:
                    # 'asset_type_name' de un JSON anidado; prioridad baja para que un campo con
                    # nombre exacto no pierda frente a uno de nombre parecido.
                    candidatos.append((len(a) / 2, -i, campo, h))
    usadas = set(res.values())
    for _, _, campo, h in sorted(candidatos, reverse=True):
        if campo not in res and h not in usadas:
            res[campo] = h
            usadas.add(h)
    return res


# ---------------------------------------------------------------------------
# Valores
# ---------------------------------------------------------------------------

def parse_nivel(texto: str) -> str | None:
    """'Level 1', 'L2', 'Purdue 3.5', '0' -> 'Nivel N'. None si no hay un nivel reconocible.
    El nivel 0 es un nivel valido (proceso fisico), no ausencia de dato."""
    t = normalizar(texto)
    if not t:
        return None
    if "dmz" in t:
        return "Nivel 3.5"
    m = re.search(r"(?<!\d)([0-5])(?:_([0-9]))?(?!\d)", t)
    if not m:
        return None
    if m.group(2):
        return "Nivel 3.5" if (m.group(1), m.group(2)) == ("3", "5") else None
    return f"Nivel {m.group(1)}"


_TIPOS = [   # (expresion sobre el texto normalizado con espacios, tipo interno, banda sugerida)
    (r"firewall|\bids\b|\bips\b|\butm\b|security appliance", "firewall", "Infraestructura"),
    (r"ot gateway", "controlador", "Nivel 1"),          # xDome: pasarela de campo, no equipo de red
    (r"switch|router|\bhub\b|access point|wireless|\bap\b|network device|network equipment|gateway|networking|^network$",
     "red", "Infraestructura"),
    (r"engineering|\beng\b|ingenieria", "ingenieria", "Nivel 2"),
    ((r"domain controller|domain server|historian|server|servidor|database|hypervisor|\bnas\b|storage|"
      r"virtual machine|\bvm\b|building management"), "servidor", "Nivel 3"),
    ((r"\bplc\b|\brtu\b|\bied\b|controller|controlador|relay|\bdrive\b|\bvfd\b|servo|protection|"
      r"remote i o|io module|\bi o\b|meter|analyzer|sensor|actuator|transmitter|field device|"
      r"safety|\bsis\b|\bdcs\b|robot"), "controlador", "Nivel 1"),
    (r"\bhmi\b|scada|operator|panel|human machine|supervis", "supervision", "Nivel 2"),
    (r"workstation|laptop|\bpc\b|desktop|computer|endpoint|windows|linux|estacion", "host", "Nivel 2-3"),
]


def clasificar_tipo(texto: str) -> tuple:
    """Texto de tipo/rol de una plataforma -> (tipo interno, banda sugerida o None)."""
    t = normalizar(texto).replace("_", " ")
    for patron, tipo, banda in _TIPOS:
        if re.search(patron, t):
            return tipo, banda
    return "otro", None


_OT = ("modbus", "dnp3", "iec", "61850", "mms", "goose", "sampled", "s7", "siemens", "ethernet_ip", "enip",
       "cip", "opc", "bacnet", "profinet", "profibus", "fins", "melsec", "srtp", "codesys", "pcworx",
       "niagara", "fox", "crimson", "proconos", "omron", "mitsubishi", "ptp", "lonworks", "hart", "ff_hse")
_CLARO = ("telnet", "ftp", "tftp", "http", "snmp", "rsh", "rlogin", "rexec", "pop3", "imap", "smtp")


def categoria_protocolo(protocolo: str) -> str | None:
    """'ot', 'claro' o None si el nombre no permite decidir."""
    t = normalizar(protocolo)
    if not t:
        return None
    if any(re.search(rf"(^|_){k}", t) for k in _OT):
        return "ot"
    if any(re.search(rf"(^|_){k}($|_)", t) for k in _CLARO) and "https" not in t and "sftp" not in t:
        return "claro"
    return None
