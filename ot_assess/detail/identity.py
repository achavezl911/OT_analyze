"""Colector: identidad de equipos (CDP, LLDP, banners, DHCP, NetBIOS...)."""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..util import g
from .base import COLLECTORS, RowCtx


@COLLECTORS
def identidad(rc: RowCtx) -> None:
    cap, row, idx = rc.cap, rc.row, rc.idx
    sip, smac = rc.sip, rc.smac
    add_ident = rc.add_ident
    # ---- identidad de equipos ---------------------------------------- #
    cdp_dev = g(row, idx, "cdp.deviceid")
    cdp_sw = g(row, idx, "cdp.software_version")
    cdp_pf = g(row, idx, "cdp.platform")
    if cdp_dev or cdp_sw or cdp_pf:
        add_ident(sip, smac, "CDP", f"{cdp_dev} / {cdp_pf}".strip(" /"),
                  cdp_sw.replace("\n", " ")[:400])
        if smac in cap.hosts:
            cap.hosts[smac]["hostnames"].add(cdp_dev)

    lldp_name = g(row, idx, "lldp.tlv.system.name")
    lldp_desc = g(row, idx, "lldp.tlv.system.desc")
    if lldp_name or lldp_desc:
        add_ident(sip, smac, "LLDP", lldp_name or "(sin nombre)",
                  lldp_desc.replace("\n", " ")[:400])
        if smac in cap.hosts and lldp_name and "not set" not in lldp_name.lower():
            cap.hosts[smac]["hostnames"].add(lldp_name)

    srv = g(row, idx, "http.server")
    if srv:
        add_ident(sip, smac, "Banner HTTP", srv)
    ua = g(row, idx, "http.user_agent")
    if ua:
        add_ident(sip, smac, "User-Agent HTTP", ua[:200])
    host_hdr = g(row, idx, "http.host")
    if host_hdr:
        add_ident(sip, smac, "Host HTTP", host_hdr[:120])

    dhcp_host = g(row, idx, "dhcp.option.hostname")
    if dhcp_host:
        add_ident(sip, smac, "Hostname DHCP", dhcp_host)
        if smac in cap.hosts:
            cap.hosts[smac]["hostnames"].add(dhcp_host)
    dhcp_vc = g(row, idx, "dhcp.option.vendor_class_id")
    if dhcp_vc:
        add_ident(sip, smac, "Vendor class DHCP", dhcp_vc)

    nb = g(row, idx, "nbns.name")
    if nb:
        if smac in cap.hosts:
            cap.hosts[smac]["hostnames"].add(nb.strip("<> "))
    brs = g(row, idx, "browser.server")
    if brs:
        add_ident(sip, smac, "SMB Browser", brs)
    nos = g(row, idx, "smb.native_os")
    if nos:
        add_ident(sip, smac, "SMB Native OS", nos)
    sni = g(row, idx, "tls.handshake.extensions_server_name")
    if sni:
        add_ident(sip, smac, "TLS SNI", sni)

    _identidad_ot(rc)


# ---- V1b (D90): lo que el equipo dice de si mismo en su protocolo OT ------------------------ #
_TABLA: dict = {}


def _fabricante(tabla: str, valor: int) -> str:
    """Nombre del fabricante por su ID en data/fabricantes_ot.json; si no esta, 'CIP vendor <n>'."""
    if not _TABLA:
        ruta = Path(__file__).resolve().parent.parent / "data" / "fabricantes_ot.json"
        _TABLA.update(json.loads(ruta.read_text(encoding="utf-8")))
    nombre = (_TABLA.get(tabla) or {}).get(str(valor))
    return nombre or ("CIP" if tabla == "cip" else "PROFINET") + f" vendor {valor}"


def _num(texto: str):
    try:
        return int(texto.strip(), 0)
    except ValueError:
        try:
            return int(texto.strip(), 10)
        except ValueError:
            return None


def _lista(valor: str) -> list:
    return valor.split("|") if valor else []


def _version(mayor, menor) -> str:
    """Formato de Rockwell: menor a 3 digitos (20.011). V1a compara numerico: 20.011 = 20.11."""
    return "" if mayor is None or menor is None else f"{mayor}.{menor:03d}"


_RE_MLFB_SIEMENS = re.compile(r"^6(ES7|AG1|GK|AV)", re.IGNORECASE)


def _fabricante_s7(mlfb: str) -> str:
    """S7comm tambien lo hablan equipos de otros fabricantes: Siemens solo si el MLFB es un numero de pedido de Siemens
    (6ES7 SIMATIC S7, 6AG1 SIPLUS, 6GK comunicaciones, 6AV HMI). Asi un PLC detras de un enrutador tambien cruza."""
    return "Siemens" if _RE_MLFB_SIEMENS.match(mlfb.replace(" ", "")) else ""


def _s7_modulo(rc: RowCtx) -> tuple:
    """SZL 0x0011: MLFB del registro de indice 1 (si no, el primero no vacio) y firmware del registro de indice 7
    (firmware basico: Ausbg = 'V' y la primera cifra, Ausbe = las otras dos -> V2.9.5). Sin la 'V' no se interpreta."""
    indices = [_num(x) for x in _lista(rc.get("s7comm.szl.xy11.0001.index"))]
    mlfbs = [x.strip("\x00 ") for x in _lista(rc.get("s7comm.szl.xy11.0001.anz"))]
    ausbg = [_num(x) for x in _lista(rc.get("s7comm.szl.xy11.0001.ausbg"))]
    ausbe = [_num(x) for x in _lista(rc.get("s7comm.szl.xy11.0001.ausbe"))]
    mlfb = next((m for i, m in zip(indices, mlfbs) if i == 1 and m), "") or next((m for m in mlfbs if m), "")
    fw = next((f"V{g & 0xFF}.{e >> 8}.{e & 0xFF}" for i, g, e in zip(indices, ausbg, ausbe)
               if i == 7 and g is not None and e is not None and g >> 8 == 0x56), "")
    return mlfb, fw


def _registrar(rc: RowCtx, tipo: str, ip: str, fab: str, modelo: str, firmware: str, nombre: str) -> None:
    if not (fab or modelo or firmware or nombre):
        return
    partes = [f"fabricante={fab}" if fab else "", f"firmware={firmware}" if firmware else "",
              f"nombre={nombre}" if nombre else ""]
    rc.add_ident(ip, rc.smac, tipo, modelo or fab or nombre, "; ".join(x for x in partes if x))
    rc.cap.identity[-1]["ot"] = {"fabricante": fab, "modelo": modelo, "firmware": firmware, "nombre": nombre}


def _identidad_ot(rc: RowCtx) -> None:
    """Un registro por respuesta, con la IP y la MAC de ORIGEN (el equipo descrito). Las peticiones no traen estos
    campos, asi que no crean identidad."""
    sip = rc.sip
    # CIP: ListIdentity o respuesta del objeto Identity
    revs = [_num(x) for x in _lista(rc.get("enip.lir.revision"))]
    lir = [_version(r >> 8, r & 0xFF) if r is not None else "" for r in revs]
    idn = [_version(_num(a), _num(b)) for a, b in
           zip(_lista(rc.get("cip.id.major_rev")), _lista(rc.get("cip.id.minor_rev")))]
    for vend, nom, vers in (("enip.lir.vendor", "enip.lir.name", lir), ("cip.id.vendor_id", "cip.id.product_name", idn)):
        nombres = _lista(rc.get(nom))
        for k, v in enumerate(_lista(rc.get(vend))):
            n = _num(v)
            if n is not None:
                _registrar(rc, "CIP Identity", sip, _fabricante("cip", n),
                           nombres[k].strip() if k < len(nombres) else "", vers[k] if k < len(vers) else "", "")
    # Modbus: Read Device Identification (43/14); objetos por id alineados con su valor
    ids, vals = _lista(rc.get("modbus.object_id")), _lista(rc.get("modbus.object_str_value"))
    if ids and len(ids) == len(vals):
        obj: dict = {}
        for i, v in zip(ids, vals):
            n = _num(i)
            if n is not None and v.strip():
                obj.setdefault(n, v.strip())
        _registrar(rc, "Modbus MEI", sip, obj.get(0, ""), obj.get(5) or obj.get(4) or obj.get(1) or "",
                   obj.get(2, ""), "")
    # S7comm: SZL 0x0011 (MLFB y firmware basico, ver _s7_modulo) y 0x001C (nombre del PLC o del modulo)
    mlfb, fw_s7 = _s7_modulo(rc)
    nom_s7 = (rc.get("s7comm.szl.001c.0001.name") or rc.get("s7comm.szl.001c.0002.name")).split("|")[0].strip("\x00 ")
    _registrar(rc, "S7 SZL", sip, _fabricante_s7(mlfb), mlfb, fw_s7, nom_s7)
    # PROFINET DCP: solo respuestas (tipo de servicio 1); sin firmware. La IP sale del bloque IP si la trama no la trae
    if rc.get("pn_dcp.service_type") == "1":
        modelo = rc.get("pn_dcp.suboption_device_devicevendorvalue").split("|")[0].strip()
        vid = _num(rc.get("pn_dcp.suboption_vendor_id").split("|")[0] or "x")
        _registrar(rc, "PROFINET DCP", sip or rc.get("pn_dcp.suboption_ip_ip").split("|")[0],
                   _fabricante("profinet", vid) if vid is not None else "", modelo, "",
                   rc.get("pn_dcp.suboption_device_nameofstation").split("|")[0].strip())
