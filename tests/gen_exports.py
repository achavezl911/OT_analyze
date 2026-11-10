#!/usr/bin/env python3
"""Exportaciones SINTETICAS de una planta ficticia, en tres estilos de columnas.

No son formatos reales de ninguna plataforma: usan nombres de columna plausibles para probar
que la importacion tolera encabezados distintos, valores multiples, JSON anidado y XLSX.

Uso: python tests/gen_exports.py <carpeta_salida>
"""
from __future__ import annotations

import csv
import json
import sys
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

# id, nombre, ip, mac, fabricante, modelo, firmware, tipo, nivel (None = sin dato), zona
ACTIVOS = [
    ("a01", "PLC-BOMBAS", "10.20.1.11", "00:00:bc:10:00:11", "Rockwell Automation", "ControlLogix 1756-L83E", "33.011", "PLC", 1, "Control"),
    ("a02", "PLC-TURBINA", "10.20.1.12", "00:1b:1b:10:00:12", "Siemens", "S7-1500 CPU 1516", "2.9.4", "PLC", 1, "Control"),
    ("a03", "PLC-CALDERA", "10.20.1.13", "00:80:f4:10:00:13", "Schneider Electric", "Modicon M580", "3.20", "PLC", 1, "Control"),
    ("a04", "RTU-SUBEST-1", "10.20.1.21", "00:00:54:10:00:21", "ABB", "RTU560", "13.4", "RTU", 1, "Campo"),
    ("a05", "RTU-SUBEST-2", "10.20.1.22", "00:00:54:10:00:22", "ABB", "RTU560", "13.4", "RTU", 1, "Campo"),
    ("a06", "IED-PROT-1", "10.20.1.31", "00:30:a7:10:00:31", "SEL", "SEL-751", "R308", "IED", 1, "Campo"),
    ("a07", "IED-PROT-2", "10.20.1.32", "00:30:a7:10:00:32", "SEL", "SEL-751", "R308", "IED", 1, "Campo"),
    ("a08", "RIO-ANALOG-1", "10.20.1.41", "00:00:bc:10:00:41", "Rockwell Automation", "Point I/O", "6.1", "Remote I/O", 0, "Campo"),
    ("a09", "HMI-SALA-1", "10.20.2.11", "00:1b:1b:20:00:11", "Siemens", "SIMATIC HMI", "17.0", "HMI", 2, "Supervision"),
    ("a10", "HMI-SALA-2", "10.20.2.12", "00:1b:1b:20:00:12", "Siemens", "SIMATIC HMI", "17.0", "HMI", 2, "Supervision"),
    ("a11", "HMI-CALDERA", "10.20.2.13", "00:00:bc:20:00:13", "Rockwell Automation", "PanelView Plus 7", "12.0", "HMI", 2, "Supervision"),
    ("a12", "ING-WS-01", "10.20.2.21", "00:50:56:20:00:21", "Dell", "Precision 5820", "", "Engineering Workstation", 2, "Supervision"),
    ("a13", "SCADA-SRV-1", "10.20.3.11", "00:50:56:30:00:11", "VMware", "Virtual Machine", "", "SCADA Server", 3, "Supervision"),
    ("a14", "HISTORIADOR", "10.20.3.12", "00:50:56:30:00:12", "VMware", "Virtual Machine", "", "Historian", 3, "Supervision"),
    ("a15", "DC-OT-01", "10.20.3.13", "00:50:56:30:00:13", "VMware", "Virtual Machine", "", "Domain Controller", 3, "Supervision"),
    ("a16", "FW-DMZ", "10.20.35.1", "00:90:fb:35:00:01", "Fortinet", "FortiGate 100F", "7.2.5", "Firewall", None, "DMZ"),
    ("a17", "PATCH-SRV", "10.20.35.10", "00:50:56:35:00:10", "VMware", "Virtual Machine", "", "Server", None, "DMZ"),
    ("a18", "JUMP-SRV", "10.20.35.11", "00:50:56:35:00:11", "VMware", "Virtual Machine", "", "Server", None, "DMZ"),
    ("a19", "ERP-SRV", "10.30.4.10", "00:50:56:40:00:10", "VMware", "Virtual Machine", "", "Server", 4, "Corporativa"),
    ("a20", "PC-INGENIERO", "10.30.4.21", "3c:52:82:40:00:21", "HP", "EliteDesk 800", "", "Workstation", 4, "Corporativa"),
    ("a21", "SW-CAMPO-1", "10.20.0.1", "00:0d:65:00:00:01", "Cisco", "IE-3300", "17.9.3", "Switch", None, "Control"),
    ("a22", "SW-CAMPO-2", "10.20.0.2", "00:0d:65:00:00:02", "Cisco", "IE-3300", "17.9.3", "Switch", None, "Campo"),
    ("a23", "SW-CORE", "10.20.0.10", "00:0d:65:00:00:10", "Cisco", "Catalyst 9300", "17.9.4", "Switch", None, "Supervision"),
    ("a24", "RTR-PLANTA", "10.20.0.254", "00:0d:65:00:00:fe", "Cisco", "ISR 4331", "17.6.4", "Router", None, "DMZ"),
    ("a25", "CAMARA-01", "10.20.5.5", "00:40:8c:50:00:05", "Axis", "P3245", "10.12", "Camera", None, "Corporativa"),
]

# origen, destino, protocolo, puerto, transporte, paquetes, bytes
ENLACES = [
    ("a09", "a01", "Modbus/TCP", 502, "tcp", 120000, 9_800_000), ("a10", "a01", "EtherNet/IP", 44818, "tcp", 90000, 7_200_000),
    ("a09", "a02", "S7comm", 102, "tcp", 80000, 6_100_000), ("a10", "a02", "S7comm", 102, "tcp", 75000, 5_900_000),
    ("a11", "a03", "Modbus/TCP", 502, "tcp", 66000, 4_800_000), ("a12", "a02", "S7comm", 102, "tcp", 9000, 1_200_000),
    ("a12", "a01", "EtherNet/IP", 44818, "tcp", 8000, 1_000_000), ("a12", "a03", "Modbus/TCP", 502, "tcp", 7000, 800_000),
    ("a13", "a04", "IEC 60870-5-104", 2404, "tcp", 51000, 3_300_000), ("a13", "a05", "IEC 60870-5-104", 2404, "tcp", 50000, 3_200_000),
    ("a13", "a06", "DNP3", 20000, "tcp", 31000, 2_100_000), ("a13", "a07", "DNP3", 20000, "tcp", 30500, 2_000_000),
    ("a13", "a08", "EtherNet/IP", 44818, "tcp", 22000, 1_700_000), ("a01", "a08", "EtherNet/IP", 2222, "udp", 400000, 24_000_000),
    ("a14", "a13", "OPC UA", 4840, "tcp", 120000, 90_000_000), ("a09", "a13", "OPC UA", 4840, "tcp", 40000, 12_000_000),
    ("a10", "a13", "OPC UA", 4840, "tcp", 38000, 11_000_000), ("a15", "a13", "SMB", 445, "tcp", 6000, 3_000_000),
    ("a15", "a14", "SMB", 445, "tcp", 5000, 2_500_000), ("a15", "a12", "SMB", 445, "tcp", 4000, 2_000_000),
    ("a14", "a17", "HTTPS", 443, "tcp", 3000, 900_000), ("a17", "a15", "SMB", 445, "tcp", 2500, 800_000),
    ("a18", "a13", "RDP", 3389, "tcp", 18000, 40_000_000), ("a18", "a12", "RDP", 3389, "tcp", 14000, 31_000_000),
    ("a20", "a18", "RDP", 3389, "tcp", 9000, 20_000_000), ("a19", "a14", "HTTPS", 443, "tcp", 7000, 4_000_000),
    ("a16", "a24", "SNMP", 161, "udp", 900, 120_000), ("a21", "a23", "SNMP", 161, "udp", 800, 100_000),
    ("a22", "a23", "SNMP", 161, "udp", 790, 99_000), ("a23", "a24", "SNMP", 161, "udp", 780, 98_000),
    ("a12", "a21", "Telnet", 23, "tcp", 300, 40_000), ("a18", "a23", "SSH", 22, "tcp", 500, 70_000),
    ("a13", "a15", "DNS", 53, "udp", 8000, 700_000), ("a14", "a15", "NTP", 123, "udp", 4000, 300_000),
    ("a25", "a19", "HTTP", 80, "tcp", 30000, 50_000_000), ("a20", "a19", "HTTPS", 443, "tcp", 10000, 6_000_000),
    ("a13", "a17", "HTTPS", 443, "tcp", 2000, 500_000),
]


def nivel_txt(n) -> str:
    return "" if n is None else str(n)


def estilo_a(out: Path) -> dict:
    """CSV con ids: 'from'/'to' referencian el id del activo."""
    with open(out / "estilo_a_activos.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "label", "ip", "mac_address", "vendor", "product_name", "firmware_version", "type",
                    "level", "zone"])
        for i, n, ip, mac, v, m, fw, t, lv, z in ACTIVOS:
            w.writerow([i, n, ip, mac, v, m, fw, t, nivel_txt(lv), z])
    with open(out / "estilo_a_enlaces.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["from", "to", "protocol", "port", "transport", "packets", "bytes"])
        for o, d, p, pt, l4, pk, by in ENLACES:
            w.writerow([o, d, p, pt, l4, pk, by])
    return {"activos": out / "estilo_a_activos.csv", "enlaces": out / "estilo_a_enlaces.csv"}


def estilo_b(out: Path) -> dict:
    """CSV con encabezados en 'Title Case', punto y coma, enlaces por nombre y bytes con unidad."""
    ndict = {a[0]: a for a in ACTIVOS}
    with open(out / "estilo_b_activos.csv", "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh, delimiter=";")
        w.writerow(["Reporte de activos", "", ""])           # linea de titulo antes del encabezado
        w.writerow(["Asset Name", "IP Address", "MAC Address", "Vendor", "Model", "Firmware Version",
                    "Asset Type", "Purdue Level", "Virtual Zone"])
        for i, n, ip, mac, v, m, fw, t, lv, z in ACTIVOS:
            w.writerow([n, ip, mac.upper().replace(":", "-"), v, m, fw, t,
                        "" if lv is None else f"Level {lv}", z])
    with open(out / "estilo_b_enlaces.csv", "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh, delimiter=";")
        w.writerow(["Source Asset", "Destination Asset", "Protocol", "Port", "Total Packets", "Total Bytes"])
        for o, d, p, pt, l4, pk, by in ENLACES:
            w.writerow([ndict[o][1], ndict[d][1], p, pt, f"{pk:,}", f"{by / 1024 / 1024:.1f} MB"])
    return {"activos": out / "estilo_b_activos.csv", "enlaces": out / "estilo_b_enlaces.csv"}


def estilo_c(out: Path) -> dict:
    """JSON anidado de tipo API (listas dentro de 'content', zona como objeto, varias IP)
    y enlaces por IP. El nivel se omite cuando no se conoce (no es lo mismo que nivel 0)."""
    contenido = []
    for i, n, ip, mac, v, m, fw, t, lv, z in ACTIVOS:
        a = {"id": i, "name": n, "ip_addresses": [{"address": ip}], "mac_addresses": [mac],
             "vendor": v, "model": m, "firmware": fw, "asset_type": {"name": t}, "zone": {"name": z}}
        if lv is not None:
            a["pera_level"] = lv
        contenido.append(a)
    (out / "estilo_c_activos.json").write_text(
        json.dumps({"total": len(contenido), "content": contenido}, indent=1), encoding="utf-8")
    ip_de = {a[0]: a[2] for a in ACTIVOS}
    with open(out / "estilo_c_enlaces.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["Source", "Destination", "Protocol", "Port", "Packets", "Bytes"])
        for o, d, p, pt, l4, pk, by in ENLACES:
            w.writerow([ip_de[o], ip_de[d], p, pt, pk, by])
    return {"activos": out / "estilo_c_activos.json", "enlaces": out / "estilo_c_enlaces.csv"}


def escribir_xlsx(path: Path, filas: list) -> None:
    """XLSX minimo (una hoja, cadenas compartidas), sin dependencias."""
    compartidas: list = []

    def idx(s):
        if s not in compartidas:
            compartidas.append(s)
        return compartidas.index(s)

    def letra(i):
        return chr(65 + i)

    xml_filas = []
    for r, fila in enumerate(filas, 1):
        celdas = []
        for c, v in enumerate(fila):
            if isinstance(v, (int, float)):
                celdas.append(f'<c r="{letra(c)}{r}"><v>{v}</v></c>')
            else:
                celdas.append(f'<c r="{letra(c)}{r}" t="s"><v>{idx(str(v))}</v></c>')
        xml_filas.append(f'<row r="{r}">{"".join(celdas)}</row>')
    ns = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/'
                   'package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>')
        z.writestr("xl/workbook.xml", f'<?xml version="1.0"?><workbook {ns} xmlns:r="http://schemas.openxmlformats.org/'
                   f'officeDocument/2006/relationships"><sheets><sheet name="Hoja1" sheetId="1" r:id="rId1"/></sheets></workbook>')
        z.writestr("xl/_rels/workbook.xml.rels", '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/'
                   'package/2006/relationships"><Relationship Id="rId1" Target="worksheets/sheet1.xml"/></Relationships>')
        z.writestr("xl/sharedStrings.xml", f'<?xml version="1.0"?><sst {ns}>'
                   + "".join(f"<si><t>{escape(s)}</t></si>" for s in compartidas) + "</sst>")
        z.writestr("xl/worksheets/sheet1.xml", f'<?xml version="1.0"?><worksheet {ns}><sheetData>'
                   + "".join(xml_filas) + "</sheetData></worksheet>")


def estilo_d(out: Path) -> dict:
    """Los mismos datos del estilo A en XLSX."""
    escribir_xlsx(out / "estilo_d_activos.xlsx",
                  [["id", "label", "ip", "mac_address", "vendor", "product_name", "firmware_version", "type", "level", "zone"]]
                  + [[i, n, ip, mac, v, m, fw, t, nivel_txt(lv), z] for i, n, ip, mac, v, m, fw, t, lv, z in ACTIVOS])
    escribir_xlsx(out / "estilo_d_enlaces.xlsx",
                  [["from", "to", "protocol", "port", "transport", "packets", "bytes"]]
                  + [[o, d, p, pt, l4, pk, by] for o, d, p, pt, l4, pk, by in ENLACES])
    return {"activos": out / "estilo_d_activos.xlsx", "enlaces": out / "estilo_d_enlaces.xlsx"}


# --- Claroty xDome (D37): encabezados exactos de la consulta de comunicaciones y de All Devices;
# --- datos inventados (IPs 10.10.x.x y 203.0.113.x, IDs AAAAAAA).
XD_COMUNICACIONES = [
    "SIDE A IP (COMM.)", "SIDE A IP (CURRENT)", "SIDE A DEVICE ID", "SIDE A DEVICE TYPE", "COMM. TYPE", "PROTOCOL",
    "DIRECTION", "PORT", "DATE", "TOTAL BYTES", "SIDE B IP (COMM.)", "SIDE B IP (CURRENT)", "SIDE B DEVICE ID",
    "SIDE B DEVICE TYPE", "SIDE B DOMAINS"]
XD_INVENTARIO = [
    "CONN. TYPE", "DEVICE NAME", "IP", "MAC", "MAC OUI", "NETWORK", "CATEGORY", "SUB CATEGORY", "MANUFACTURER",
    "TYPE", "MODEL", "OS", "VLAN", "LAST SEEN / REPORTED", "RISK SCORE", "RISK SCORE POINTS",
    "EXPOSURE SCENARIOS", "SUSPICIOUS", "LABELS", "ASSIGNEES", "NOTES"]


def xd_fila(a: str, b: str, direccion: str = "Bidirectional", puerto="N/A", proto: str = "N/A",
            dia: str = "2026-11-02", nbytes=100, tipo_a: str = "N/A", tipo_b: str = "N/A",
            ambito: str = "Intra-Site (Internal)", dominios: str = "N/A", actual_a: str = "") -> list:
    return [a, actual_a or a, "AAAAAAA", tipo_a, ambito, proto, direccion, puerto, dia, nbytes,
            b, b, "AAAAAAA", tipo_b, dominios]


def xd_escribir_comunicaciones(path: Path, filas: list) -> Path:
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(XD_COMUNICACIONES)
        w.writerows(filas)
    return path


def xdome(out: Path) -> dict:
    """Dos consultas de comunicaciones con el mismo par visto desde lados opuestos y el inventario."""
    out.mkdir(parents=True, exist_ok=True)
    c1 = xd_escribir_comunicaciones(out / "xdome_comunicaciones_1.csv", [
        xd_fila("10.10.1.10", "10.10.2.20", "From B to A", 502, "Modbus", nbytes=1000,
                tipo_a="HMI", tipo_b="PLC", actual_a="10.10.1.10, 10.10.9.9"),
        xd_fila("10.10.1.10", "10.10.3.30", "Bidirectional", 445, "N/A", "2026-11-02", 100, tipo_b="Historian"),
        xd_fila("10.10.1.10", "10.10.3.30", "Bidirectional", 445, "N/A", "2026-11-03", 50, tipo_b="Historian"),
        xd_fila("10.10.1.10", "203.0.113.5", "From A to B", 443, "TLS 1.2", nbytes=7,
                ambito="Internet (External)", dominios="update.example.com, cdn.example.com"),
        xd_fila("10.10.1.10", "10.10.5.50", "From A to B", 53, "DNS", nbytes=3, tipo_b="Domain Server"),
    ])
    c2 = xd_escribir_comunicaciones(out / "xdome_comunicaciones_2.csv", [
        xd_fila("10.10.3.30", "10.10.1.10", "Bidirectional", 445, "N/A", "2026-11-04", 10,
                tipo_a="Historian", tipo_b="HMI"),
    ])
    inv = [XD_INVENTARIO,
           ["Ethernet", "HMI-1", "10.10.1.10", "aa:bb:cc:00:00:01", "Acme", "Net1", "OT", "Operator", "Acme",
            "HMI", "H100", "Windows", "10", "2026-11-02", "Low", 10, "N/A", "No", "N/A", "N/A", "N/A"],
           ["Ethernet", "PLC-1", "10.10.2.20", "aa:bb:cc:00:00:02", "Acme", "Net1", "OT", "Controller", "Acme",
            "PLC", "P200", "N/A", "Unknown", "2026-11-02", "Low", 5, "N/A", "No", "N/A", "N/A", "N/A"],
           ["Ethernet", "SRV-1", "10.10.3.30, 10.10.3.31", "aa:bb:cc:00:00:03", "Acme", "Net1", "IT", "Server",
            "Acme", "Other", "N/A", "Linux", "20", "2026-11-02", "Low", 5, "N/A", "No", "N/A", "N/A", "N/A"]]
    escribir_xlsx(out / "xdome_all_devices.xlsx", inv)
    return {"comunicaciones": [c1, c2], "inventario": out / "xdome_all_devices.xlsx"}


def escribir(out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    return {"a": estilo_a(out), "b": estilo_b(out), "c": estilo_c(out), "d": estilo_d(out)}


if __name__ == "__main__":
    destino = Path(sys.argv[1] if len(sys.argv) > 1 else "exports_sinteticos")
    escribir(destino)
    print(f"[OK] exportaciones sinteticas en {destino}")
