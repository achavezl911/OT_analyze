#!/usr/bin/env python3
"""Genera capturas sinteticas para probar el analizador sin datos de cliente.

Requiere scapy (solo para desarrollo): pip install scapy
Uso: python tests/gen_pcaps.py <carpeta_salida>

Escenario (dos puntos de captura de una planta ficticia):
  - HMI 10.10.1.10 -> PLC 10.10.1.20: Modbus con lecturas y escrituras.
  - Estacion de ingenieria 10.10.1.30 -> PLC S7 10.10.1.40: PLC Stop.
  - Master 10.10.2.5 -> RTU 10.10.2.6: IEC-104 comando simple.
  - Dos MAC reclamando la IP 10.10.1.20 (conflicto ARP).
  - Telnet, FTP y SNMP community en texto claro.
  - Una IP publica destino y una consulta DNS.

punto_c y punto_d no los escribe main(): solo los usa DeteccionesTest (tests/test_pipeline.py),
una captura por grupo de detecciones, para que cada regla tenga un escenario que la dispare.
  - punto_c: ruido IT y conducta anomala, sin ningun comando de control OT.
  - punto_d: 2100 tramas GOOSE por multicast y snaplen de 96 bytes.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

from scapy.all import (
    ARP,
    BOOTP,
    DHCP,
    DNS,
    DNSQR,
    ICMP,
    IP,
    LLC,
    SNAP,
    TCP,
    UDP,
    Dot3,
    Ether,
    Raw,
    conf,
    wrpcap,
)
from scapy.asn1.asn1 import ASN1_OID
from scapy.contrib.cdp import (
    CDPMsgDeviceID,
    CDPMsgPlatform,
    CDPMsgSoftwareVersion,
    CDPv2_HDR,
)
from scapy.layers.l2 import STP
from scapy.layers.llmnr import LLMNRQuery
from scapy.layers.netbios import NBNSQueryRequest
from scapy.layers.rip import RIP, RIPEntry
from scapy.layers.snmp import SNMP, SNMPget, SNMPvarbind

conf.verb = 0

MAC = {
    "hmi": "00:1b:1b:00:00:10",   # prefijo Siemens
    "plc": "00:00:bc:00:00:20",   # prefijo Rockwell
    "plc2": "00:00:bc:00:00:99",  # segunda MAC con la misma IP
    "eng": "00:1b:1b:00:00:30",
    "s7": "00:1b:1b:00:00:40",
    "master": "00:00:54:00:00:05",
    "rtu": "00:00:54:00:00:06",
    "gw": "00:50:c2:00:00:01",
    "sw": "00:0d:65:00:00:01",    # prefijo Cisco
    "dnp": "00:0e:8c:00:00:77",
    "dnpm": "00:0e:8c:00:00:78",
    "tls0": "02:00:00:00:30:00",
    "tls1": "02:00:00:00:30:01",
    "tls2": "02:00:00:00:30:02",
    "tls3": "02:00:00:00:30:03",
    "tls4": "02:00:00:00:30:04",
}


def dnp_crc(data: bytes) -> bytes:
    """CRC-16/DNP: polinomio reflejado 0xA6BC, resultado invertido, little-endian."""
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return ((~crc) & 0xFFFF).to_bytes(2, "little")


def mbap(tid: int, func: int, data: bytes, unit: int = 1) -> bytes:
    return tid.to_bytes(2, "big") + b"\x00\x00" + (len(data) + 2).to_bytes(2, "big") \
        + bytes([unit, func]) + data


_SEQ: dict = {}


def tcp(src, dst, ip_s, ip_d, sport, dport, payload=b"", flags="PA"):
    # Secuencia TCP por flujo: si no avanza, Wireshark lo toma por retransmision
    # y no disecciona el payload.
    key = (ip_s, ip_d, sport, dport)
    seq = _SEQ.get(key, 1000)
    _SEQ[key] = seq + len(payload)
    return (Ether(src=MAC[src], dst=MAC[dst]) /
            IP(src=ip_s, dst=ip_d) /
            TCP(sport=sport, dport=dport, flags=flags, seq=seq) /
            Raw(payload))


def punto_a() -> list:
    p = []
    # Modbus: lecturas FC3 y una escritura FC6 y FC16
    for i in range(6):
        p.append(tcp("hmi", "plc", "10.10.1.10", "10.10.1.20", 40000, 502,
                     mbap(i, 3, b"\x00\x00\x00\x0a")))
        p.append(tcp("plc", "hmi", "10.10.1.20", "10.10.1.10", 502, 40000,
                     mbap(i, 3, b"\x14" + b"\x00" * 20)))
    p.append(tcp("hmi", "plc", "10.10.1.10", "10.10.1.20", 40000, 502,
                 mbap(100, 6, b"\x00\x01\x00\xff")))
    p.append(tcp("plc", "hmi", "10.10.1.20", "10.10.1.10", 502, 40000,
                 mbap(100, 6, b"\x00\x01\x00\xff")))
    p.append(tcp("hmi", "plc", "10.10.1.10", "10.10.1.20", 40000, 502,
                 mbap(101, 16, b"\x00\x02\x00\x01\x02\x00\x07")))

    # S7comm: PLC Stop (PI service) desde la estacion de ingenieria
    tpkt_cotp = lambda s7: (b"\x03\x00" + (len(s7) + 7).to_bytes(2, "big")
                            + b"\x02\xf0\x80" + s7)
    param = b"\x29\x00\x00\x00\x00\x00\x09P_PROGRAM"
    s7 = (b"\x32\x01\x00\x00\x00\x01" + len(param).to_bytes(2, "big")
          + b"\x00\x00" + param)
    p.append(tcp("eng", "s7", "10.10.1.30", "10.10.1.40", 41000, 102, tpkt_cotp(s7)))

    # IEC-104: C_SC_NA_1 comando simple
    asdu = b"\x2d\x01\x06\x00\x01\x00\x01\x00\x00\x01"
    apdu = b"\x68" + bytes([4 + len(asdu)]) + b"\x00\x00\x00\x00" + asdu
    p.append(tcp("master", "rtu", "10.10.2.5", "10.10.2.6", 42000, 2404, apdu))
    p.append(tcp("rtu", "master", "10.10.2.6", "10.10.2.5", 2404, 42000,
                 b"\x68\x04\x01\x00\x00\x00"))

    # Texto claro
    p.append(tcp("eng", "gw", "10.10.1.30", "10.10.1.1", 43000, 23,
                 b"admin\r\n"))
    p.append(tcp("eng", "gw", "10.10.1.30", "10.10.1.1", 43001, 21,
                 b"USER operador\r\n"))
    p.append(tcp("eng", "gw", "10.10.1.30", "10.10.1.1", 43001, 21,
                 b"PASS Secreto1\r\n"))
    p.append(Ether(src=MAC["eng"], dst=MAC["gw"]) / IP(src="10.10.1.30", dst="10.10.1.1")
             / UDP(sport=50000, dport=161)
             / SNMP(community="public", PDU=SNMPget(varbindlist=[
                 SNMPvarbind(oid=ASN1_OID("1.3.6.1.2.1.1.1.0"))])))

    # Salida a Internet y DNS
    p.append(Ether(src=MAC["eng"], dst=MAC["gw"]) / IP(src="10.10.1.30", dst="8.8.8.8")
             / UDP(sport=51000, dport=53) / DNS(rd=1, qd=DNSQR(qname="update.vendor.example")))
    p.append(tcp("eng", "gw", "10.10.1.30", "93.184.216.34", 44000, 80,
                 b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))

    # DNP3: Direct Operate (FC5) hacia la outstation; el CRC no se valida
    cab = b"\x05\x64\x08\xc4\x01\x00\x02\x00"
    usr = b"\xc0\xc1\x05"
    dnp = cab + dnp_crc(cab) + usr + dnp_crc(usr)
    p.append(tcp("dnpm", "dnp", "10.10.3.5", "10.10.3.6", 45000, 20000, dnp))

    # EtherNet/IP SendRRData con CIP Write Tag (0x4D)
    cip = b"\x4d\x03\x91\x03Tag\x00\xc3\x00\x01\x00\x01\x00"
    cpf = (b"\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\xb2\x00"
           + len(cip).to_bytes(2, "little") + cip)
    enip = (b"\x6f\x00" + len(cpf).to_bytes(2, "little") + b"\x01\x00\x00\x00"
            + b"\x00" * 4 + b"\x00" * 8 + b"\x00" * 4 + cpf)
    p.append(tcp("hmi", "plc", "10.10.1.10", "10.10.1.20", 46000, 44818, enip))

    # Banner HTTP de firmware viejo y CDP del switch (identidad)
    p.append(tcp("plc", "hmi", "10.10.1.20", "10.10.1.10", 80, 47000,
                 b"HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.28\r\nContent-Length: 0\r\n\r\n"))
    p.append(Dot3(src=MAC["sw"], dst="01:00:0c:cc:cc:cc") / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
             / SNAP(OUI=0x00000C, code=0x2000)
             / CDPv2_HDR(msg=[CDPMsgDeviceID(val="SW-CAMPO-01"),
                              CDPMsgSoftwareVersion(val="Cisco IOS Software, Version 12.2(55)SE"),
                              CDPMsgPlatform(val="cisco WS-C2960-24TT-L")]))

    # DHCP con hostname (6 tramas para superar el umbral de la regla)
    for i in range(6):
        p.append(Ether(src=MAC["hmi"], dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255")
                 / UDP(sport=68, dport=67)
                 / BOOTP(chaddr=bytes.fromhex(MAC["hmi"].replace(":", "")), xid=i)
                 / DHCP(options=[("message-type", "request"), ("hostname", "HMI-01"), "end"]))

    # ARP: la misma IP 10.10.1.20 anunciada por dos MAC
    for mac in ("plc", "plc2"):
        p.append(Ether(src=MAC[mac], dst="ff:ff:ff:ff:ff:ff") /
                 ARP(op=2, hwsrc=MAC[mac], psrc="10.10.1.20",
                     hwdst="00:00:00:00:00:00", pdst="10.10.1.20"))
    return p


def punto_b() -> list:
    """Segundo punto de captura: solo ve el lazo master-RTU y difusion."""
    p = []
    asdu = b"\x2d\x01\x06\x00\x01\x00\x02\x00\x00\x01"
    apdu = b"\x68" + bytes([4 + len(asdu)]) + b"\x00\x00\x00\x00" + asdu
    for _ in range(3):
        p.append(tcp("master", "rtu", "10.10.2.5", "10.10.2.6", 42000, 2404, apdu))
    p.append(Ether(src=MAC["master"], dst="ff:ff:ff:ff:ff:ff") /
             ARP(op=1, hwsrc=MAC["master"], psrc="10.10.2.5",
                 hwdst="00:00:00:00:00:00", pdst="10.10.2.6"))
    return p


def punto_c() -> list:
    """Red con protocolos IT de descubrimiento, RIP, APIPA, barrido, escaneo y STP; sin control OT."""
    p = []
    hmi, eng = "10.10.5.10", "10.10.5.30"
    mc = lambda ip: "01:00:5e:" + ":".join(f"{int(o):02x}" for o in ip.split(".")[1:])
    qn = DNS(rd=1, qd=DNSQR(qname="wpad"))

    # Descubrimiento de Windows y de servicios: LLMNR, NBT-NS, mDNS y SSDP
    p.append(Ether(src=MAC["hmi"], dst=mc("224.0.0.252")) / IP(src=hmi, dst="224.0.0.252")
             / UDP(sport=51000, dport=5355) / LLMNRQuery(qd=DNSQR(qname="wpad")))
    p.append(Ether(src=MAC["hmi"], dst="ff:ff:ff:ff:ff:ff") / IP(src=hmi, dst="10.10.5.255")
             / UDP(sport=137, dport=137) / NBNSQueryRequest(QUESTION_NAME="WPAD"))
    p.append(Ether(src=MAC["hmi"], dst=mc("224.0.0.251")) / IP(src=hmi, dst="224.0.0.251")
             / UDP(sport=5353, dport=5353) / qn)
    p.append(Ether(src=MAC["hmi"], dst=mc("239.255.255.250")) / IP(src=hmi, dst="239.255.255.250")
             / UDP(sport=52000, dport=1900)
             / Raw(b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
                   b"MX: 1\r\nST: ssdp:all\r\n\r\n"))

    # Sentinel HASP (udp/1947) en difusion
    p.append(Ether(src=MAC["eng"], dst="ff:ff:ff:ff:ff:ff") / IP(src=eng, dst="10.10.5.255")
             / UDP(sport=1947, dport=1947) / Raw(b"\x00" * 8))

    # Equipo con direccion APIPA
    p.append(Ether(src=MAC["dnp"], dst="ff:ff:ff:ff:ff:ff") / IP(src="169.254.10.20", dst="169.254.255.255")
             / UDP(sport=50100, dport=50100) / Raw(b"hola"))

    # RIPv2
    p.append(Ether(src=MAC["sw"], dst=mc("224.0.0.9")) / IP(src="10.10.5.1", dst="224.0.0.9")
             / UDP(sport=520, dport=520) / RIP(cmd=2, version=2)
             / RIPEntry(AF=2, addr="10.10.6.0", mask="255.255.255.0", metric=1))

    # Barrido ARP: 30 direcciones distintas desde una MAC
    for i in range(1, 31):
        p.append(Ether(src=MAC["dnpm"], dst="ff:ff:ff:ff:ff:ff") /
                 ARP(op=1, hwsrc=MAC["dnpm"], psrc="10.10.5.99",
                     hwdst="00:00:00:00:00:00", pdst=f"10.10.5.{i}"))

    # Escaneo: SYN de una IP hacia 30 destinos distintos
    for i in range(1, 31):
        p.append(tcp("eng", "gw", eng, f"10.10.5.{100 + i}", 40000 + i, 445, flags="S"))

    # STP: 25 BPDU de configuracion con el bit de cambio de topologia
    for _ in range(25):
        p.append(Dot3(src=MAC["sw"], dst="01:80:c2:00:00:00") / LLC(dsap=0x42, ssap=0x42, ctrl=3)
                 / STP(bpdutype=0, bpduflags=1, rootmac=MAC["sw"], bridgemac=MAC["sw"]))
    return p


def punto_d() -> list:
    """Punto de captura que solo ve difusion/multicast y casi todo es I/O ciclico GOOSE (2100 tramas)."""
    return [Ether(src=MAC["s7"], dst="01:0c:cd:01:00:01", type=0x88B8)
            / Raw(b"\x00\x01\x00\x20\x00\x00\x00\x00" + b"\x00" * 24) for _ in range(2100)]


def client_hello(sni: str) -> bytes:
    """TLS ClientHello minimo con la extension server_name."""
    n = sni.encode()
    ext_sni = b"\x00\x00" + struct.pack(">HHBH", len(n) + 5, len(n) + 3, 0, len(n)) + n
    cuerpo = (b"\x03\x03" + b"\x11" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
              + struct.pack(">H", len(ext_sni)) + ext_sni)
    hs = b"\x01" + len(cuerpo).to_bytes(3, "big") + cuerpo
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def _ua_cadena(s: str) -> bytes:
    b = s.encode()
    return struct.pack("<i", len(b)) + b


def opc_opn(politica: str, modo: int, respuesta: bool = False) -> bytes:
    """OpenSecureChannelRequest (o Response) de OPC UA binario, sin firma ni cifrado."""
    cab_ext = b"\x00\x00\x00"
    if respuesta:
        cuerpo = (b"\x01\x00\xc1\x01" + b"\x00" * 8 + struct.pack("<II", 1, 0) + b"\x00"
                  + struct.pack("<i", 0) + cab_ext + struct.pack("<I", 0)
                  + struct.pack("<II", 1, 1) + b"\x00" * 8 + struct.pack("<I", 3600000)
                  + struct.pack("<i", -1))
    else:
        cuerpo = (b"\x01\x00\xbe\x01" + b"\x00\x00" + b"\x00" * 8 + struct.pack("<I", 1) + struct.pack("<I", 0)
                  + struct.pack("<i", -1) + struct.pack("<I", 10000) + cab_ext
                  + struct.pack("<III", 0, 0, modo) + struct.pack("<i", -1) + struct.pack("<I", 3600000))
    asim = _ua_cadena(politica) + struct.pack("<ii", -1, -1)
    seq = struct.pack("<II", 1, 1)
    tam = 12 + len(asim) + len(seq) + len(cuerpo)
    return b"OPNF" + struct.pack("<II", tam, 0) + asim + seq + cuerpo


def opc_msg(nodo: int, canal: int = 1) -> bytes:
    """Mensaje MSG con solo el tipo de servicio (cuerpo en ceros): basta para ver el servicio."""
    cuerpo = b"\x01\x00" + struct.pack("<H", nodo) + b"\x00" * 40
    return b"MSGF" + struct.pack("<III", 24 + len(cuerpo), canal, 1) + struct.pack("<II", 2, 2) + cuerpo


POLITICA_NONE = "http://opcfoundation.org/UA/SecurityPolicy#None"
POLITICA_B256 = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"


def punto_opcua(con_escritura: bool = False) -> list:
    """OPC UA: 10.20.1.10 -> 10.20.1.20 con politica None; 10.20.1.11 -> 10.20.1.21 con Basic256Sha256."""
    p = [tcp("hmi", "plc", "10.20.1.10", "10.20.1.20", 50100, 4840, opc_opn(POLITICA_NONE, 1)),
         tcp("plc", "hmi", "10.20.1.20", "10.20.1.10", 4840, 50100, opc_opn(POLITICA_NONE, 1, True)),
         tcp("eng", "gw", "10.20.1.11", "10.20.1.21", 50101, 4840, opc_opn(POLITICA_B256, 3))]
    if con_escritura:
        p.append(tcp("hmi", "plc", "10.20.1.10", "10.20.1.20", 50100, 4840, opc_msg(673)))
    return p


def punto_opcua_seguro() -> list:
    """Solo el canal Basic256Sha256 con Sign&Encrypt."""
    return [tcp("eng", "gw", "10.20.1.11", "10.20.1.21", 50101, 4840, opc_opn(POLITICA_B256, 3))]


def server_hello(version: int, suite: int, record: int = 0x0301) -> bytes:
    """TLS ServerHello minimo (sin extensiones)."""
    cuerpo = struct.pack(">H", version) + b"\x22" * 32 + b"\x00" + struct.pack(">H", suite) + b"\x00"
    hs = b"\x02" + len(cuerpo).to_bytes(3, "big") + cuerpo
    return b"\x16" + struct.pack(">HH", record, len(hs)) + hs


def client_hello_versiones(sni: str, version: int, suites: list) -> bytes:
    """ClientHello que ofrece `version` y las suites dadas."""
    n = sni.encode()
    ext_sni = b"\x00\x00" + struct.pack(">HHBH", len(n) + 5, len(n) + 3, 0, len(n)) + n
    lista = b"".join(struct.pack(">H", x) for x in suites)
    cuerpo = (struct.pack(">H", version) + b"\x11" * 32 + b"\x00" + struct.pack(">H", len(lista)) + lista
              + b"\x01\x00" + struct.pack(">H", len(ext_sni)) + ext_sni)
    hs = b"\x01" + len(cuerpo).to_bytes(3, "big") + cuerpo
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


TLS_CASOS = [("10.30.1.20", 0x0301, 0x002F, "vieja.example"),    # TLS 1.0, RSA_AES128_SHA
             ("10.30.1.21", 0x0303, 0xC02F, "buena.example"),    # TLS 1.2, ECDHE_AES128_GCM
             ("10.30.1.22", 0x0303, 0x0005, "rc4.example"),      # TLS 1.2, RSA_RC4_128_SHA
             ("10.30.1.23", 0x0303, 0x1301, "tls13.example")]    # TLS 1.3 (version heredada 1.2)


def punto_tls() -> list:
    """Cuatro servidores; todos reciben un ClientHello que ofrece TLS 1.0 y suites debiles.
    El de RC4 (10.30.1.22) ademas atiende Modbus: es un equipo OT."""
    p = []
    for i, (srv, ver, suite, sni) in enumerate(TLS_CASOS, 1):
        p.append(tcp("tls0", f"tls{i}", "10.30.1.10", srv, 51000 + i, 8443,
                     client_hello_versiones(sni, 0x0301, [0x002F, 0xC02F, 0x0005])))
        p.append(tcp(f"tls{i}", "tls0", srv, "10.30.1.10", 8443, 51000 + i, server_hello(ver, suite)))
    p.append(tcp("tls0", "tls3", "10.30.1.10", "10.30.1.22", 51100, 502, mbap(1, 3, b"\x00\x00\x00\x0a")))
    p.append(tcp("tls3", "tls0", "10.30.1.22", "10.30.1.10", 502, 51100, mbap(1, 3, b"\x14" + b"\x00" * 20)))
    return p


def punto_modbus_diag(subfuncion: int = 1, solo_respuestas: bool = False) -> list:
    """Modbus FC8 con la subfuncion dada, dos veces (unidad 7), cada una con su respuesta."""
    datos = struct.pack(">HH", subfuncion, 0)
    p = []
    for i in range(2):
        if not solo_respuestas:
            p.append(tcp("hmi", "plc", "10.40.1.10", "10.40.1.20", 52000, 502, mbap(i, 8, datos, unit=7)))
        p.append(tcp("plc", "hmi", "10.40.1.20", "10.40.1.10", 502, 52000, mbap(i, 8, datos, unit=7)))
    return p


def punto_dnp3_reinicio(solo_respuestas: bool = False) -> list:
    """DNP3: maestro 1 -> outstation 2, Cold Restart (FC13) dos veces, cada una con su respuesta."""
    def trama(cab: bytes, usr: bytes) -> bytes:
        return cab + dnp_crc(cab) + usr + dnp_crc(usr)
    pet = trama(b"\x05\x64\x08\xc4\x02\x00\x01\x00", b"\xc0\xc1\x0d")
    res = trama(b"\x05\x64\x0a\x44\x01\x00\x02\x00", b"\xc0\xc1\x81\x00\x00")
    p = []
    for _ in range(2):
        if not solo_respuestas:
            p.append(tcp("dnpm", "dnp", "10.50.1.10", "10.50.1.20", 53000, 20000, pet))
        p.append(tcp("dnp", "dnpm", "10.50.1.20", "10.50.1.10", 20000, 53000, res))
    return p


def punto_dns() -> list:
    """Consultas y respuestas DNS: A con CNAME (y autoridad y adicional), AAAA, PTR, NXDOMAIN
    con SOA, REFUSED, una consulta sin respuesta y un ClientHello con SNI."""
    from scapy.layers.dns import DNSRR, DNSRRSOA
    cli, srv, ext = "10.10.1.10", "10.10.1.53", "8.8.8.8"

    def eth_ip(a, b):
        return Ether(src=MAC["hmi"] if a == cli else MAC["gw"],
                     dst=MAC["gw"] if a == cli else MAC["hmi"]) / IP(src=a, dst=b)

    def consulta(i, nombre, qtype, servidor=srv):
        return (eth_ip(cli, servidor) / UDP(sport=40000 + i, dport=53)
                / DNS(id=i, rd=1, qd=DNSQR(qname=nombre, qtype=qtype)))

    def respuesta(i, nombre, qtype, servidor=srv, **kw):
        return (eth_ip(servidor, cli) / UDP(sport=53, dport=40000 + i)
                / DNS(id=i, qr=1, rd=1, ra=1, qd=DNSQR(qname=nombre, qtype=qtype), **kw))

    p = [consulta(1, "www.example.com", "A"),
         respuesta(1, "www.example.com", "A",
                   an=DNSRR(rrname="www.example.com", type="CNAME", ttl=300,
                            rdata="cdn.example.net")
                   / DNSRR(rrname="cdn.example.net", type="A", ttl=60, rdata="93.184.216.34"),
                   ancount=2, nscount=1, arcount=1,   # scapy cuenta la cadena an como 1
                   ns=DNSRR(rrname="example.net", type="NS", ttl=900, rdata="ns1.example.net"),
                   ar=DNSRR(rrname="ns1.example.net", type="A", ttl=900, rdata="192.0.2.53")),
         consulta(2, "v6.example.com", "AAAA"),
         respuesta(2, "v6.example.com", "AAAA",
                   an=DNSRR(rrname="v6.example.com", type="AAAA", ttl=120, rdata="2001:db8::1")),
         consulta(3, "20.1.10.10.in-addr.arpa", "PTR"),
         respuesta(3, "20.1.10.10.in-addr.arpa", "PTR",
                   an=DNSRR(rrname="20.1.10.10.in-addr.arpa", type="PTR", ttl=3600,
                            rdata="plc.planta.local")),
         consulta(4, "nada.example.com", "A"),
         respuesta(4, "nada.example.com", "A", rcode=3,
                   ns=DNSRRSOA(rrname="example.com", ttl=30, mname="ns.example.com",
                               rname="admin.example.com", serial=1, refresh=2, retry=3,
                               expire=4, minimum=5)),
         consulta(5, "refused.example.org", "A", ext),
         respuesta(5, "refused.example.org", "A", ext, rcode=5),
         consulta(6, "perdida.example.com", "A"),
         tcp("hmi", "gw", cli, "93.184.216.34", 41000, 443, client_hello("www.example.com"))]
    return p


def punto_dns_hallazgos() -> list:
    """Para las reglas DNS-b: WPAD, AXFR, un nombre externo, TXT, un flujo DoT y un mDNS
    (multicast; no debe contarse como servidor DNS)."""
    cli, srv, ext = "10.10.1.10", "10.10.1.53", "8.8.8.8"

    def consulta(i, nombre, qtype, destino):
        return (Ether(src=MAC["hmi"], dst=MAC["gw"]) / IP(src=cli, dst=destino)
                / UDP(sport=41000 + i, dport=53)
                / DNS(id=i, rd=1, qd=DNSQR(qname=nombre, qtype=qtype)))

    return [consulta(1, "wpad", "A", srv),
            consulta(2, "wpad.planta.local", "A", srv),
            consulta(3, "planta.local", "AXFR", srv),
            consulta(4, "www.example.com", "A", ext),
            consulta(5, "datos.tunel.example.net", "TXT", ext),
            tcp("hmi", "gw", cli, "1.1.1.1", 42000, 853, b"\x16\x03\x01\x00\x00"),
            (Ether(src=MAC["hmi"], dst="01:00:5e:00:00:fb") / IP(src=cli, dst="224.0.0.251")
             / UDP(sport=5353, dport=5353) / DNS(id=0, rd=0, qd=DNSQR(qname="impresora.local")))]


T5_T0 = 1_700_000_000          # inicio de las capturas de periodicidad (T5)
T5_DURACION = 700               # s: mas de 10 minutos, para que cuente "aparece tarde"


def _sondeo(cli, srv, ip_c, ip_s, sport, instantes, func=3):
    """Una lectura Modbus (o la funcion dada) por instante: peticion, respuesta y ACK sin carga."""
    p = []
    for i, t in enumerate(instantes):
        datos = b"\x00\x01\x00\xff" if func == 6 else b"\x00\x00\x00\x0a"
        pk = [tcp(cli, srv, ip_c, ip_s, sport, 502, mbap(i, func, datos)),
              tcp(srv, cli, ip_s, ip_c, 502, sport, mbap(i, func, datos if func == 6 else b"\x14" + b"\x00" * 20)),
              tcp(cli, srv, ip_c, ip_s, sport, 502, b"", flags="A")]
        for k, x in enumerate(pk):
            x.time = T5_T0 + t + k * 0.001
        p += pk
    return p


def _instantes(desde, hasta, periodo=1.0, jitter=0.05, hueco=None, semilla=1):
    """Instantes (s desde T5_T0) de un sondeo regular con jitter; `hueco`=(inicio, fin) los omite."""
    import random
    rng = random.Random(semilla)
    out, t = [], float(desde)
    while t < hasta:
        if not (hueco and hueco[0] <= t < hueco[1]):
            out.append(t + rng.uniform(-jitter, jitter))
        t += periodo
    return [max(0.0, x) for x in out]


def punto_t5_periodico() -> list:
    """Sondeo Modbus cada 1 s con jitter bajo durante toda la ventana (con ACK sin carga)."""
    return _sondeo("hmi", "plc", "10.60.1.10", "10.60.1.20", 41000, _instantes(0, T5_DURACION))


def punto_t5_hueco() -> list:
    """El mismo sondeo con un hueco de 60 s (de 300 a 360 s)."""
    return _sondeo("hmi", "plc", "10.60.1.10", "10.60.1.20", 41000,
                   _instantes(0, T5_DURACION, hueco=(300, 360)))


def punto_t5_irregular() -> list:
    """Sondeo con intervalos exponenciales de media 1 s (CV cercano a 1)."""
    import random
    rng = random.Random(7)
    t, ins = 0.0, []
    while t < T5_DURACION:
        ins.append(t)
        t += max(0.01, rng.expovariate(1.0))
    return _sondeo("hmi", "plc", "10.60.1.10", "10.60.1.20", 41000, ins)


def punto_t5_termina_antes() -> list:
    """Dos sondeos: el de 10.60.1.20 termina a los 200 s; el de 10.60.1.30 sigue hasta el final."""
    return (_sondeo("hmi", "plc", "10.60.1.10", "10.60.1.20", 41000, _instantes(0, 200))
            + _sondeo("hmi", "plc2", "10.60.1.10", "10.60.1.30", 41001, _instantes(0, T5_DURACION, semilla=2)))


def punto_t5_escritor_tardio() -> list:
    """El HMI lee todo el tiempo y escribe al inicio y al final (no es tardio); la estacion de ingenieria
    10.60.1.50 aparece a los 400 s y escribe tres veces."""
    return (_sondeo("hmi", "plc", "10.60.1.10", "10.60.1.20", 41000, _instantes(0, T5_DURACION))
            + _sondeo("hmi", "plc", "10.60.1.10", "10.60.1.20", 41002, [10, 500], func=6)
            + _sondeo("eng", "plc", "10.60.1.50", "10.60.1.20", 41003, [400, 401, 402], func=6))


def punto_t5_dnp3_eventos() -> list:
    """DNP3: el maestro consulta al outstation con intervalos exponenciales de media 10 s (eventos)."""
    import random
    rng = random.Random(11)
    cab = b"\x05\x64\x08\xc4\x02\x00\x01\x00"
    pet = cab + dnp_crc(cab) + b"\xc0\xc1\x01" + dnp_crc(b"\xc0\xc1\x01")
    t, p = 0.0, []
    while t < T5_DURACION:
        pk = tcp("dnpm", "dnp", "10.50.1.10", "10.50.1.20", 53000, 20000, pet)
        pk.time = T5_T0 + t
        p.append(pk)
        t += max(0.5, rng.expovariate(0.1))
    return p


T8_CLI, T8_DNS, T8_PLC = "10.80.1.10", "10.80.1.53", "10.80.1.20"
MAC.update({"t8c": "02:00:00:00:80:01", "t8g": "02:00:00:00:80:02", "t8p": "02:00:00:00:80:03"})


def _t8_dns(i: int, nombre: str, respuesta_ip: str = "") -> list:
    from scapy.layers.dns import DNSRR
    p = [Ether(src=MAC["t8c"], dst=MAC["t8g"]) / IP(src=T8_CLI, dst=T8_DNS) / UDP(sport=43000 + i, dport=53)
         / DNS(id=i, rd=1, qd=DNSQR(qname=nombre, qtype="A"))]
    if respuesta_ip:
        p.append(Ether(src=MAC["t8g"], dst=MAC["t8c"]) / IP(src=T8_DNS, dst=T8_CLI) / UDP(sport=53, dport=43000 + i)
                 / DNS(id=i, qr=1, rd=1, ra=1, qd=DNSQR(qname=nombre, qtype="A"),
                       an=DNSRR(rrname=nombre, type="A", ttl=60, rdata=respuesta_ip)))
    return p


def punto_t8(con_ot: bool = False) -> list:
    """T8: un cliente usa TeamViewer (consulta DNS y TCP/5938), AnyDesk (SNI en 443) y RustDesk (TCP/21116).
    Con con_ot=True el mismo equipo ademas lee un PLC por Modbus: es un cliente de control (Nivel 2)."""
    p = _t8_dns(1, "master3.teamviewer.com", "203.0.113.50")
    p.append(tcp("t8c", "t8g", T8_CLI, "203.0.113.60", 51001, 443, client_hello("net.anydesk.com")))
    p.append(tcp("t8c", "t8g", T8_CLI, "203.0.113.70", 51002, 5938, b"\x17\x03\x03\x00\x05hello"))
    p.append(tcp("t8c", "t8g", T8_CLI, "203.0.113.80", 51003, 21116, b"\x17\x03\x03\x00\x05hello"))
    if con_ot:
        p.append(tcp("t8c", "t8p", T8_CLI, T8_PLC, 51100, 502, mbap(1, 3, b"\x00\x00\x00\x0a")))
        p.append(tcp("t8p", "t8c", T8_PLC, T8_CLI, 502, 51100, mbap(1, 3, b"\x14" + b"\x00" * 20)))
    return p


def punto_t8_trampa() -> list:
    """T8: nada de esto es una herramienta del catalogo: dominios que solo se le parecen y TCP/443 solo."""
    p = _t8_dns(1, "teamviewer.com.example.net", "198.51.100.10")
    p += _t8_dns(2, "noteamviewer.com", "198.51.100.11")
    p.append(tcp("t8c", "t8g", T8_CLI, "198.51.100.12", 51001, 443, client_hello("anydesk.com.example.net")))
    p.append(tcp("t8c", "t8g", T8_CLI, "198.51.100.13", 51002, 443, b"\x17\x03\x03\x00\x05hello"))
    return p


T9_TOR = "203.0.113.105"       # IP ficticia que las pruebas ponen en la lista de relays Tor (nunca la lista real)


def _t9_udp(ip_d: str, sport: int, dport: int, payload: bytes = b"\x01\x02\x03\x04hello") -> object:
    return (Ether(src=MAC["t8c"], dst=MAC["t8g"]) / IP(src=T8_CLI, dst=ip_d) / UDP(sport=sport, dport=dport)
            / Raw(payload))


def _t9_ip(ip_d: str, proto_cls) -> object:
    return Ether(src=MAC["t8c"], dst=MAC["t8g"]) / IP(src=T8_CLI, dst=ip_d) / proto_cls / Raw(b"\x00" * 12)


def punto_t9(con_ot: bool = False) -> list:
    """T9: un cliente usa DoH (SNI dns.google y TCP/443 a 1.1.1.1), DoQ (UDP/853), DoT (TCP/853, no es de T9),
    consulta el canario de Firefox, Tor (TCP/9001 y TCP/443 hacia T9_TOR), VPN (OpenVPN, NAT-T, PPTP, WireGuard,
    nordvpn.com), tuneles (GRE, ESP) y proxies (SOCKS 1080, Squid 3128), todo hacia IP publicas.
    Con con_ot=True el mismo equipo ademas lee un PLC por Modbus: es un cliente de control (Nivel 2)."""
    from scapy.layers.inet import GRE
    from scapy.layers.ipsec import ESP
    basura = b"\x17\x03\x03\x00\x05hello"
    p = _t8_dns(1, "use-application-dns.net", "203.0.113.90")
    p += _t8_dns(2, "nordvpn.com", "203.0.113.91")
    p.append(tcp("t8c", "t8g", T8_CLI, "203.0.113.101", 52001, 443, client_hello("dns.google")))
    p.append(tcp("t8c", "t8g", T8_CLI, "1.1.1.1", 52002, 443, basura))
    p.append(_t9_udp("203.0.113.102", 52003, 853))
    p.append(tcp("t8c", "t8g", T8_CLI, "203.0.113.103", 52004, 853, basura))
    p.append(tcp("t8c", "t8g", T8_CLI, "203.0.113.104", 52005, 9001, basura))
    p.append(tcp("t8c", "t8g", T8_CLI, T9_TOR, 52006, 443, basura))
    p.append(_t9_udp("203.0.113.106", 52007, 1194))
    p.append(_t9_udp("203.0.113.107", 52008, 4500))
    p.append(tcp("t8c", "t8g", T8_CLI, "203.0.113.108", 52009, 1723, basura))
    p.append(_t9_udp("203.0.113.112", 52010, 51820))
    p.append(_t9_ip("203.0.113.109", GRE()))
    p.append(_t9_ip("203.0.113.111", ESP(spi=0x1000, seq=1)))
    p.append(tcp("t8c", "t8g", T8_CLI, "203.0.113.110", 52011, 1080, basura))
    p.append(tcp("t8c", "t8g", T8_CLI, "203.0.113.114", 52012, 3128, basura))
    if con_ot:
        p.append(tcp("t8c", "t8p", T8_CLI, T8_PLC, 51100, 502, mbap(1, 3, b"\x00\x00\x00\x0a")))
        p.append(tcp("t8p", "t8c", T8_PLC, T8_CLI, 502, 51100, mbap(1, 3, b"\x14" + b"\x00" * 20)))
    return p


def punto_t9_trampa() -> list:
    """T9: nada de esto es un canal del catalogo: los mismos puertos y protocolos hacia IP privadas, dominios
    que solo se le parecen, 443 hacia una IP que no es un resolvedor y 9001 sin que el destino sea publico."""
    from scapy.layers.inet import GRE
    from scapy.layers.ipsec import ESP
    basura = b"\x17\x03\x03\x00\x05hello"
    p = _t8_dns(1, "nordvpn.com.example.net", "198.51.100.10")
    p += _t8_dns(2, "nonordvpn.com", "198.51.100.11")
    p.append(tcp("t8c", "t8g", T8_CLI, "198.51.100.12", 52001, 443, client_hello("dns.google.example.net")))
    p.append(tcp("t8c", "t8g", T8_CLI, "198.51.100.13", 52002, 443, basura))
    p.append(_t9_udp("10.80.9.1", 52003, 1194))
    p.append(_t9_udp("10.80.9.2", 52004, 4500))
    p.append(tcp("t8c", "t8g", T8_CLI, "10.80.9.3", 52005, 1723, basura))
    p.append(tcp("t8c", "t8g", T8_CLI, "10.80.9.4", 52006, 9001, basura))
    p.append(tcp("t8c", "t8g", T8_CLI, "192.168.9.5", 52007, 1080, basura))
    p.append(_t9_udp("10.80.9.6", 52008, 853))
    p.append(_t9_ip("10.80.9.7", GRE()))
    p.append(_t9_ip("10.80.9.8", ESP(spi=0x1000, seq=1)))
    return p


T10_T0 = 1_700_000_000.0
T10_SW = "00:0d:65:10:00:01"        # prefijo Cisco: el analizador lo reconoce como equipo de red
T10_SW2 = "00:0d:65:10:00:02"
T10_HOST = "02:00:00:10:00:01"      # equipo final sin fabricante
T10_HOST2 = "02:00:00:10:00:02"


def _en(t: float, pk):
    """Fija el instante del paquete (segundos desde T10_T0) y lo devuelve."""
    pk.time = T10_T0 + t
    return pk


def _t10_udp(src: str, dst: str, ip_s: str, ip_d: str, t: float, sport: int = 40000, dport: int = 5000, **kw):
    return _en(t, Ether(src=src, dst=dst) / IP(src=ip_s, dst=ip_d, **kw) / UDP(sport=sport, dport=dport) / Raw(b"x" * 8))


def punto_t10_dhcp(dos: bool = True) -> list:
    """T10a: ofertas y ACK DHCP; con dos=True, de dos servidores distintos (10.10.1.2 y 10.10.1.99)."""
    from scapy.utils import mac2str
    p = []
    servidores = [("00:0d:65:10:00:11", "10.10.1.2")] + ([("02:00:00:10:00:99", "10.10.1.99")] if dos else [])
    for k, (mac, ip) in enumerate(servidores):
        for c in range(3):
            cli = f"02:00:00:10:01:{c:02x}"
            for n, tipo in enumerate(("offer", "ack")):
                p.append(_en(k * 3 + c * 5 + n, Ether(src=mac, dst=cli) / IP(src=ip, dst="255.255.255.255")
                             / UDP(sport=67, dport=68)
                             / BOOTP(op=2, yiaddr=f"10.10.1.{100 + c}", siaddr=ip, chaddr=mac2str(cli), xid=c + 1)
                             / DHCP(options=[("message-type", tipo), ("server_id", ip), ("lease_time", 3600),
                                             "end"])))
    return p


def _bpdu(src: str, rootid: int, rootmac: str, t: float):
    return _en(t, Dot3(src=src, dst="01:80:c2:00:00:00") / LLC()
               / STP(rootid=rootid, rootmac=rootmac, bridgeid=rootid, bridgemac=rootmac, portid=0x8001))


def punto_t10_stp(cambio_raiz: bool = False, equipo_final: bool = False) -> list:
    """T10a: BPDU de un switch con raiz estable; con cambio_raiz=True la raiz pasa a otra MAC con mejor prioridad;
    con equipo_final=True un equipo sin fabricante, que tambien origina trafico IP, repite BPDU de la misma raiz."""
    p = [_bpdu(T10_SW, 32768, T10_SW, 2.0 * i) for i in range(5)]
    if cambio_raiz:
        p += [_bpdu(T10_SW2, 4096, T10_SW2, 20 + 2.0 * i) for i in range(3)]
    if equipo_final:
        p += [_bpdu(T10_HOST, 32768, T10_SW, 30 + 2.0 * i) for i in range(3)]
        p += [_t10_udp(T10_HOST, "02:00:00:10:00:aa", "10.10.1.50", "10.10.1.51", 30 + i) for i in range(3)]
    return p


def punto_t10_vlan(doble: bool = True, dtp: bool = True) -> list:
    """T10a: tramas con doble etiqueta 802.1Q (100 y 200) y/o tramas DTP de un puerto que negocia troncal."""
    from scapy.contrib.dtp import DTP
    from scapy.layers.l2 import Dot1Q
    p = []
    if doble:
        for i in range(4):
            p.append(_en(i, Ether(src=T10_HOST, dst="02:00:00:10:00:aa") / Dot1Q(vlan=100) / Dot1Q(vlan=200)
                         / IP(src="10.10.1.50", dst="10.10.2.51") / UDP(sport=40000, dport=5000) / Raw(b"x" * 8)))
    if dtp:
        for i in range(3):
            p.append(_en(10 + i, Dot3(src=T10_SW, dst="01:00:0c:cc:cc:cc") / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
                         / SNAP(OUI=0x00000C, code=0x2004) / DTP()))
    return p


def punto_t10_ha(nuevo_255: bool = True) -> list:
    """T10a: HSRP grupo 1 (texto claro, el equipo 10.10.1.2 con prioridad 100) y VRRP grupo 5 sin autenticacion;
    con nuevo_255=True un equipo nuevo (10.10.1.77) anuncia prioridad 255 en el grupo HSRP."""
    from scapy.layers.hsrp import HSRP
    from scapy.layers.vrrp import VRRP
    p = []
    for i in range(3):
        p.append(_en(3 * i, Ether(src="00:00:0c:07:ac:01", dst="01:00:5e:00:00:02")
                     / IP(src="10.10.1.2", dst="224.0.0.2", ttl=1) / UDP(sport=1985, dport=1985)
                     / HSRP(group=1, priority=100, virtualIP="10.10.1.1")))
        p.append(_en(3 * i + 1, Ether(src="00:00:5e:00:01:05", dst="01:00:5e:00:00:12")
                     / IP(src="10.10.1.3", dst="224.0.0.18", ttl=255)
                     / VRRP(vrid=5, priority=100, ipcount=1, addrlist=["10.10.1.4"])))
    if nuevo_255:
        p.append(_en(20, Ether(src="02:00:00:10:00:77", dst="01:00:5e:00:00:02")
                     / IP(src="10.10.1.77", dst="224.0.0.2", ttl=1) / UDP(sport=1985, dport=1985)
                     / HSRP(group=1, priority=255, virtualIP="10.10.1.1")))
    return p


def punto_t10_ra(origen: str = "host", ipv6_en_uso: bool = False) -> list:
    """T10a: Router Advertisement (ICMPv6 134) de un equipo final ("host") o de un router ("router"); con
    ipv6_en_uso=True ademas hay trafico TCP sobre IPv6 entre dos equipos."""
    from scapy.layers.inet6 import ICMPv6ND_RA, IPv6
    mac = T10_HOST if origen == "host" else T10_SW
    p = [_en(i * 5, Ether(src=mac, dst="33:33:00:00:00:01") / IPv6(src="fe80::1", dst="ff02::1", hlim=255)
             / ICMPv6ND_RA()) for i in range(3)]
    if ipv6_en_uso:
        for i in range(4):
            p.append(_en(i, Ether(src="02:00:00:10:00:b1", dst="02:00:00:10:00:b2")
                         / IPv6(src="2001:db8::10", dst="2001:db8::20") / TCP(sport=50000 + i, dport=443, flags="PA")
                         / Raw(b"hello")))
    return p


def punto_t10_macflood(n: int = 250, arranque: bool = False) -> list:
    """T10a: unos equipos legitimos desde el segundo 0 y n MAC de origen nuevas (un paquete cada una) repartidas
    en 10 s a partir del segundo 60. Con arranque=True las n MAC aparecen en los primeros 5 s (no es inundacion)."""
    p = [_t10_udp(T10_HOST, T10_HOST2, "10.10.1.50", "10.10.1.51", i * 10.0) for i in range(8)]
    t0, paso = (1.0, 5.0 / max(n, 1)) if arranque else (60.0, 10.0 / max(n, 1))
    for i in range(n):
        mac = "02:ee:%02x:%02x:%02x:01" % (i >> 16 & 255, i >> 8 & 255, i & 255)
        p.append(_en(t0 + i * paso, Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src="10.20.0.1", dst="10.20.0.2")
                     / UDP(sport=1, dport=2) / Raw(b"x")))
    return p


def punto_t10_bucle(ttl: bool = True, icmp11: bool = True, tormenta: bool = True, ttl_vistas: int = 7) -> list:
    """T10a: indicios de bucle. ttl: 8 paquetes IP, cada uno visto ttl_vistas veces con TTL 64, 63, 62...;
    icmp11: 60 ICMP time exceeded en un segundo; tormenta: 1500 paquetes/s de difusion durante 5 s."""
    p = [_t10_udp(T10_HOST, T10_HOST2, "10.10.1.50", "10.10.1.51", i * 10.0) for i in range(3)]
    if ttl:
        for k in range(8):
            for v in range(ttl_vistas):
                p.append(_t10_udp(T10_HOST, T10_HOST2, "10.10.1.60", "10.10.2.61", 2 + k + v * 0.05,
                                  id=1000 + k, ttl=64 - v))
    if icmp11:
        for i in range(60):
            p.append(_en(20 + i * 0.01, Ether(src=T10_SW, dst=T10_HOST) / IP(src="10.10.1.1", dst="10.10.1.50")
                         / ICMP(type=11, code=0) / IP(src="10.10.1.50", dst="10.10.9.9", id=5 + i)
                         / UDP(sport=1, dport=2)))
    if tormenta:
        for i in range(5 * 1500):
            p.append(_en(40 + i / 1500.0, Ether(src=T10_HOST, dst="ff:ff:ff:ff:ff:ff")
                         / IP(src="10.10.1.50", dst="255.255.255.255") / UDP(sport=137, dport=137) / Raw(b"x")))
    return p


# --- V1b (D90): identidad que el equipo reporta en su protocolo OT. IP de documentacion, productos inventados ---
MAC.update({
    "id_ctl": "02:00:00:00:41:10",   # el que pregunta (192.0.2.10)
    "id_cip": "02:00:00:00:41:01",   # 192.0.2.50
    "id_mb": "00:1b:1b:00:41:02",    # OUI Siemens, pero el protocolo dice otro fabricante (192.0.2.51)
    "id_dcp": "02:00:00:00:41:03",   # 192.0.2.60
    "id_s7": "02:00:00:00:41:04",    # 192.0.2.70
    "id_rt": "02:00:00:00:41:05",    # MAC de enrutamiento: 6 IP (192.0.2.101-106)
    "id_cdp": "02:00:00:00:41:06",   # CDP y CIP con fabricante desconocido (192.0.2.80)
})


def _enip(comando: int, datos: bytes = b"") -> bytes:
    return struct.pack("<HHII", comando, len(datos), 0, 0) + bytes(8) + bytes(4) + datos


def enip_list_identity(ip: str, vendor: int, nombre: str, mayor: int, menor: int, prodcode: int = 55) -> bytes:
    """Respuesta ListIdentity (comando 0x0063) con un item de identidad."""
    sock = struct.pack(">HH", 2, 44818) + bytes(map(int, ip.split("."))) + bytes(8)
    cuerpo = (struct.pack("<H", 1) + sock
              + struct.pack("<HHHBBHIB", vendor, 14, prodcode, mayor, menor, 0x30, 123456, len(nombre))
              + nombre.encode() + b"\x03")
    return _enip(0x63, struct.pack("<H", 1) + struct.pack("<HH", 0x0C, len(cuerpo)) + cuerpo)


def modbus_mei(objetos: dict, respuesta: bool = True) -> bytes:
    """Cuerpo (despues del codigo de funcion 43) de Read Device Identification: peticion o respuesta."""
    if not respuesta:
        return b"\x0e\x01\x00"
    cuerpo = b"".join(bytes([i, len(v)]) + v.encode() for i, v in objetos.items())
    return b"\x0e\x01\x01\x00\x00" + bytes([len(objetos)]) + cuerpo


def s7_szl(szl_id: int, indice: int, registros: bytes, largo_registro: int, cuantos: int) -> bytes:
    """Respuesta userdata de lectura de SZL (TPKT / COTP / S7comm)."""
    datos = (b"\xff\x09" + struct.pack(">H", 8 + len(registros))
             + struct.pack(">HHHH", szl_id, indice, largo_registro, cuantos) + registros)
    param = b"\x00\x01\x12\x08\x12\x84\x01\x01\x00\x00\x00\x00"
    s7 = b"\x32\x07\x00\x00" + struct.pack(">HHH", 1, len(param), len(datos)) + param + datos
    cotp = b"\x02\xf0\x80"
    return b"\x03\x00" + struct.pack(">H", 4 + len(cotp) + len(s7)) + cotp + s7


def dcp_identify(mac_o: str, mac_d: str, bloques: list, respuesta: bool = True):
    """Trama PROFINET DCP Identify: (opcion, subopcion, datos) por bloque; respuesta o peticion."""
    cuerpo = b""
    for opcion, sub, datos in bloques:
        cuerpo += bytes([opcion, sub]) + struct.pack(">H", len(datos)) + datos + (b"\x00" if len(datos) % 2 else b"")
    cab = struct.pack(">HBBIHH", 0xFEFD if respuesta else 0xFEFF, 5, 1 if respuesta else 0, 4, 0, len(cuerpo))
    return Ether(src=mac_o, dst=mac_d, type=0x8892) / Raw(cab + cuerpo)


def dcp_set(mac_o: str, mac_d: str, bloques: list, t: float, respuesta: bool = False):
    """PN1 (D102): trama PROFINET DCP Set (service_id 4) con (opcion, subopcion, datos) por bloque; peticion o respuesta."""
    cuerpo = b""
    for opcion, sub, datos in bloques:
        cuerpo += bytes([opcion, sub]) + struct.pack(">H", len(datos)) + datos + (b"\x00" if len(datos) % 2 else b"")
    cab = struct.pack(">HBBIHH", 0xFEFD, 4, 1 if respuesta else 0, 7, 0, len(cuerpo))
    pk = Ether(src=mac_o, dst=mac_d, type=0x8892) / Raw(cab + cuerpo)
    pk.time = t
    return pk


def dcp_bloque_ip(ip: str, mascara: str, permanente: bool = True):
    return (1, 2, struct.pack(">H", 1 if permanente else 0) + bytes(map(int, ip.split(".")))
            + bytes(map(int, mascara.split("."))) + bytes(4))


def dcp_bloque_nombre(nombre: str):
    return (2, 2, struct.pack(">H", 1) + nombre.encode("ascii"))


def dcp_bloque_control(sub: int):
    return (5, sub, struct.pack(">H", 0) + (b"\x01\x00" if sub == 3 else b""))


def punto_identidad_ot(solo_peticiones: bool = False) -> list:
    """Respuestas de identidad de cinco protocolos y casos de MAC (enrutada, CDP + CIP, fabricante desconocido)."""
    ctl, p = "192.0.2.10", []
    udp = lambda o, d, ip_o, ip_d, sp, dp, datos: (
        Ether(src=MAC[o], dst=MAC[d]) / IP(src=ip_o, dst=ip_d) / UDP(sport=sp, dport=dp) / Raw(datos))
    # peticiones: no crean identidad
    p.append(udp("id_ctl", "id_cip", ctl, "192.0.2.50", 49000, 44818, _enip(0x63)))
    p.append(tcp("id_ctl", "id_mb", ctl, "192.0.2.51", 50000, 502, mbap(1, 43, modbus_mei({}, False))))
    p.append(dcp_identify(MAC["id_ctl"], "01:0e:cf:00:00:00", [(0xFF, 0xFF, b"")], respuesta=False))
    if solo_peticiones:
        return p
    # 1. CIP ListIdentity (Rockwell, ID 1)
    p.append(udp("id_cip", "id_ctl", "192.0.2.50", ctl, 44818, 49000,
                 enip_list_identity("192.0.2.50", 1, "1756-L71/B LOGIX5571", 20, 11)))
    # 2. Modbus 43/14: VendorName, ProductCode, MajorMinorRevision
    p.append(tcp("id_mb", "id_ctl", "192.0.2.51", ctl, 502, 50000, mbap(1, 43, modbus_mei(
        {0: "Acme Automation", 1: "PLC-5000", 2: "V2.3.0"}))))
    # 3. PROFINET DCP: vendor 42, dispositivo, nombre de estacion y su IP; mas un paquete IP de la misma MAC
    p.append(dcp_identify(MAC["id_dcp"], MAC["id_ctl"], [
        (1, 2, b"\x00\x01" + bytes([192, 0, 2, 60]) + bytes([255, 255, 255, 0]) + bytes(4)),
        (2, 1, b"\x00\x00" + b"PX-1500"),
        (2, 2, b"\x00\x00" + b"estacion-px1"),
        (2, 3, b"\x00\x00" + struct.pack(">HH", 42, 0x0101))]))
    p.append(udp("id_dcp", "id_ctl", "192.0.2.60", ctl, 49152, 49152, b"x"))
    # 4. S7comm SZL 0x0011 indice 1 (MLFB inventado) y SZL 0x001C (nombre del PLC)
    mlfb = b"6XX7 123-4AB56-0XY7".ljust(20, b" ")
    # registro de indice 7 (firmware basico): Ausbg = 'V' y la primera cifra, Ausbe = las otras dos -> V2.9.5
    p.append(tcp("id_s7", "id_ctl", "192.0.2.70", ctl, 102, 50100, s7_szl(
        0x0011, 0, struct.pack(">H", 1) + mlfb + struct.pack(">HHH", 0xC0, 0x0100, 0x0200)
        + struct.pack(">H", 7) + b" " * 20 + struct.pack(">HHH", 0, 0x5602, 0x0905), 28, 2)))
    p.append(tcp("id_s7", "id_ctl", "192.0.2.70", ctl, 102, 50100, s7_szl(
        0x001C, 0, struct.pack(">H", 1) + b"PLC-SINTETICO".ljust(32, b"\x00"), 34, 1)))
    # 5. MAC enrutada: 6 IP y la respuesta CIP solo desde una
    for i in range(1, 7):
        p.append(udp("id_rt", "id_ctl", f"192.0.2.10{i}", ctl, 40000 + i, 5000, b"x"))
    p.append(udp("id_rt", "id_ctl", "192.0.2.103", ctl, 44818, 49000,
                 enip_list_identity("192.0.2.103", 1, "1756-L83E", 33, 15)))
    # 6. misma MAC con CDP y CIP (fabricante desconocido)
    p.append(Dot3(src=MAC["id_cdp"], dst="01:00:0c:cc:cc:cc") / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
             / SNAP(OUI=0x00000C, code=0x2000)
             / CDPv2_HDR(msg=[CDPMsgDeviceID(val="SW-SINTETICO"),
                              CDPMsgPlatform(val="cisco WS-C9999-24T")]))
    p.append(udp("id_cdp", "id_ctl", "192.0.2.80", ctl, 44818, 49000,
                 enip_list_identity("192.0.2.80", 9999, "Producto-X", 1, 2)))
    return p


MAC.update({"ing_eng": "02:00:00:00:51:01", "ing_srv": "02:00:00:00:51:02"})   # D1: 192.0.2.201 -> 192.0.2.202
ING_ORIGEN, ING_DESTINO = "192.0.2.201", "192.0.2.202"


def _ing_ip(cls, t: float, desde_servidor: bool = False):
    o, d = ("ing_srv", "ing_eng") if desde_servidor else ("ing_eng", "ing_srv")
    ip_o, ip_d = (ING_DESTINO, ING_ORIGEN) if desde_servidor else (ING_ORIGEN, ING_DESTINO)
    return o, d, ip_o, ip_d


def _ing_t(pk, t: float):
    pk.time = t
    return pk


def srtp(codigo: int, t: float, extendido: bool = False, tipo: int = 2, desde_servidor: bool = False,
         largo: int = 56):
    """GE SRTP (TCP 18245): cabecera de 56 bytes; byte 31 = 0xC0 (corto, codigo en el 42) o 0x80 (extendido, en el 50)."""
    cab = bytearray(largo)
    cab[0:2] = struct.pack("<H", tipo)
    cab[31] = 0x80 if extendido else 0xC0
    if largo > 50:
        cab[50 if extendido else 42] = codigo
    o, d, ip_o, ip_d = _ing_ip(None, t, desde_servidor)
    sp, dp = (18245, 49500) if desde_servidor else (49500, 18245)
    return _ing_t(tcp(o, d, ip_o, ip_d, sp, dp, bytes(cab)), t)


def umas(codigo: int, t: float, respuesta: bool = False):
    """UMAS = Modbus FC 90: datos = clave de sesion + codigo (la respuesta de exito trae 0xFE)."""
    datos = bytes([0x01, 0xFE if respuesta else codigo, 0x00])
    o, d, ip_o, ip_d = _ing_ip(None, t, respuesta)
    sp, dp = (502, 49600) if respuesta else (49600, 502)
    return _ing_t(tcp(o, d, ip_o, ip_d, sp, dp, mbap(7, 90, datos)), t)


def fins(comando: int, t: float, icf: int = 0x80):
    """FINS/UDP 9600: cabecera de 10 bytes (ICF, RSV, GCT, DNA, DA1, DA2, SNA, SA1, SA2, SID) + comando."""
    cab = bytes([icf, 0, 2, 0, 20, 0, 0, 10, 0, 1])
    desde_servidor = bool(icf & 0x40)
    o, d, ip_o, ip_d = _ing_ip(None, t, desde_servidor)
    sp, dp = (9600, 49700) if desde_servidor else (49700, 9600)
    pk = (Ether(src=MAC[o], dst=MAC[d]) / IP(src=ip_o, dst=ip_d) / UDP(sport=sp, dport=dp)
          / Raw(cab + struct.pack(">H", comando) + (b"\x00\x00" if desde_servidor else b"")))
    return _ing_t(pk, t)


def cip_servicio(servicio: int, clase: int, t: float, respuesta: bool = False):
    """EtherNet/IP SendRRData con una peticion CIP al objeto `clase` (instancia 1); la respuesta lleva el bit 0x80."""
    cip = bytes([servicio | (0x80 if respuesta else 0)]) + (b"\x00\x00\x00\x00" if respuesta else
                                                              bytes([2, 0x20, clase, 0x24, 1]))
    items = struct.pack("<HHHH", 0, 0, 0xB2, len(cip)) + cip
    o, d, ip_o, ip_d = _ing_ip(None, t, respuesta)
    sp, dp = (44818, 49800) if respuesta else (49800, 44818)
    datos = _enip(0x6F, struct.pack("<IH", 0, 10) + struct.pack("<H", 2) + items)
    return _ing_t(tcp(o, d, ip_o, ip_d, sp, dp, datos), t)


def s7_pi(servicio: str, t: float, funcion: int = 0x28):
    """S7comm job: PLC Control (0x28) con servicio PI, o PLC Stop (0x29)."""
    nombre = servicio.encode()
    if funcion == 0x28:
        param = bytes([0x28]) + b"\x00" * 6 + b"\xfd" + b"\x00\x00" + bytes([len(nombre)]) + nombre
    else:
        param = bytes([0x29]) + b"\x00" * 5 + bytes([len(nombre)]) + nombre
    s7 = b"\x32\x01\x00\x00\x00\x01" + struct.pack(">H", len(param)) + b"\x00\x00" + param
    carga = b"\x03\x00" + struct.pack(">H", len(s7) + 7) + b"\x02\xf0\x80" + s7
    o, d, ip_o, ip_d = _ing_ip(None, t)
    return _ing_t(tcp(o, d, ip_o, ip_d, 49900, 102, carga), t)


def guardar_t(pkts: list, path: Path) -> None:
    """Como guardar, pero respeta los instantes de cada paquete (los ordena)."""
    wrpcap(str(path), sorted(pkts, key=lambda x: float(x.time)))


def fijar_snaplen(path: Path, snaplen: int) -> None:
    """Escribe el limite de tamano de paquete en la cabecera del pcap (los paquetes ya caben)."""
    datos = bytearray(path.read_bytes())
    fmt = "<I" if datos[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">I"
    struct.pack_into(fmt, datos, 16, snaplen)
    path.write_bytes(bytes(datos))


def guardar(pkts: list, path: Path) -> None:
    for i, pk in enumerate(pkts):
        pk.time = 1_700_000_000 + i * 0.5
    wrpcap(str(path), pkts)


def main() -> int:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "pcaps_sinteticos")
    out.mkdir(parents=True, exist_ok=True)
    guardar(punto_a(), out / "punto_a.pcap")
    guardar(punto_b(), out / "punto_b.pcap")
    print(f"[OK] capturas sinteticas en {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
