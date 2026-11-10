"""Colector: operaciones de escritura y comando sobre protocolos OT.

Para soportar un protocolo nuevo basado en un codigo de funcion, agregar una
fila a PROTOCOLOS. Los que no encajan (CIP, MMS, GE SRTP, UMAS) tienen su propia logica abajo.

D1 (D92): cada operacion lleva la llave "clase" (descarga, carga, modo, reinicio, firmware, forzado,
configuracion, escritura o "" si no es una operacion de ingenieria ni de escritura).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ..i18n import t
from ..util import g
from .base import COLLECTORS, RowCtx

CIP_SERVICES = {
    0x01: "Get_Attributes_All",
    0x05: "Reset",
    0x06: "Start",
    0x07: "Stop",
    0x08: "Create",
    0x09: "Delete",
    0x0D: "Apply_Attributes",
    0x0E: "Get_Attribute_Single",
    0x10: "Set_Attribute_Single",
    0x4D: "Write Tag",
    0x4E: "Read Modify Write Tag",
    0x53: "Write Tag Fragmented",
}
CIP_CRITICAL = {0x05, 0x06, 0x07, 0x08, 0x09, 0x0D, 0x10, 0x4D, 0x4E, 0x53}
MODBUS_FUNCS = {
    5: "Write Single Coil", 6: "Write Single Register",
    15: "Write Multiple Coils", 16: "Write Multiple Registers",
    22: "Mask Write Register", 23: "Read/Write Multiple Registers",
    8: "Diagnostics", 20: "Read File Record", 21: "Write File Record",
    43: "Encapsulated Interface (Device ID)",
}
DNP3_FUNCS = {
    1: "Read", 2: "Write", 3: "Select", 4: "Operate", 5: "Direct Operate",
    6: "Direct Operate sin respuesta", 7: "Freeze", 13: "Cold Restart",
    14: "Warm Restart", 18: "Stop Application", 20: "Enable Unsolicited",
    21: "Disable Unsolicited", 23: "Delay Measurement", 25: "Open File",
    27: "Delete File", 31: "Activate Config", 32: "Authenticate",
}
IEC104_TYPES = {
    45: "C_SC_NA_1 comando simple", 46: "C_DC_NA_1 comando doble",
    47: "C_RC_NA_1 comando de regulacion", 48: "C_SE_NA_1 setpoint normalizado",
    49: "C_SE_NB_1 setpoint escalado", 50: "C_SE_NC_1 setpoint flotante",
    51: "C_BO_NA_1 bitstring", 100: "C_IC_NA_1 interrogacion general",
    101: "C_CI_NA_1 interrogacion de contadores", 102: "C_RD_NA_1 lectura",
    103: "C_CS_NA_1 sincronizacion de reloj", 105: "C_RP_NA_1 reset de proceso",
    107: "C_TS_TA_1 prueba",
}
S7_FUNCS = {
    0x04: "Read Var", 0x05: "Write Var", 0x1A: "Request Download",
    0x1B: "Download Block", 0x1C: "Download Ended", 0x1D: "Start Upload",
    0x1E: "Upload", 0x1F: "Upload Ended", 0x28: "PLC Control",
    0x29: "PLC Stop",
}
S7_CRITICAL = {0x05, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x28, 0x29}

# --- D1 (D92): clase de ingenieria de cada operacion ---------------------------------------------
S7_CLASES = {0x05: "escritura", 0x1A: "descarga", 0x1B: "descarga", 0x1C: "descarga", 0x1D: "carga",
             0x1E: "carga", 0x1F: "carga", 0x29: "modo"}
S7_PI = {"P_PROGRAM": "modo", "_INSE": "descarga", "_DELE": "descarga", "_MODU": "configuracion",
         "_GARB": "configuracion"}
CIP_CLASES = {0x05: "reinicio", 0x06: "modo", 0x07: "modo", 0x0D: "configuracion", 0x10: "escritura",
              0x4D: "escritura", 0x4E: "escritura", 0x53: "escritura"}
CIP_CLASE_FIRMWARE = 0xA1
CIP_OP_FIRMWARE = "Transferencia a memoria no volatil (clase 0xA1)"
CIP_LECTURAS = {0x01, 0x0E}
DNP3_CLASES = {13: "reinicio", 14: "reinicio", 18: "modo", 31: "configuracion"}
# 100-102 (interrogacion y lectura) y 107 (C_TS_TA_1, prueba de enlace) no cambian el proceso: sin clase a proposito.
IEC104_CLASES = {45: "escritura", 46: "escritura", 47: "escritura", 48: "escritura", 49: "escritura",
                 50: "escritura", 51: "escritura", 103: "escritura", 105: "reinicio"}
MODBUS_ESCRITURAS = {5, 6, 15, 16, 21, 22, 23}

# GE SRTP (puerto 18245): codigo de servicio -> (nombre, clase). Lecturas no se reportan.
SRTP_PUERTO = 18245
SRTP_CODIGOS = {
    0x07: ("WRITE_SYS_MEM", "escritura"), 0x08: ("WRITE_TASK_MEM", "escritura"),
    0x09: ("WRITE_PROG_MEM", "descarga"), 0x40: ("PROG_LOAD", "descarga"),
    0x3F: ("PROG_STORE", "carga"), 0x23: ("SET_PLC_RUN", "modo"),
    0x20: ("PROG_LOGON", "configuracion"), 0x21: ("CHANGE_PRIV", "configuracion"),
    0x22: ("SET_CPU_ID", "configuracion"), 0x39: ("CLR_FAULT", "configuracion"),
    0x24: ("SET_PLC_TIME", "escritura"), 0x44: ("TOGGLE_FORCE_SYS_MEM", "forzado"),
}
SRTP_MIN = 56
SRTP_BYTE_TIPO, SRTP_BYTE_CORTO, SRTP_BYTE_EXT = 31, 42, 50

# UMAS de Schneider (Modbus FC 90): segundo byte de modbus.data -> (operacion, clase).
UMAS_FC = 90
UMAS_CODIGOS = {
    0x30: ("transferencia al PLC", "descarga"), 0x31: ("transferencia al PLC", "descarga"),
    0x32: ("transferencia al PLC", "descarga"), 0x33: ("transferencia desde el PLC", "carga"),
    0x34: ("transferencia desde el PLC", "carga"), 0x35: ("transferencia desde el PLC", "carga"),
    0x40: ("inicio del PLC", "modo"), 0x41: ("paro del PLC", "modo"),
}

# FINS de Omron (UDP y TCP 9600): comando -> (operacion, clase).
FINS_PUERTO = 9600
FINS_CODIGOS = {
    0x0102: ("escritura de memoria", "escritura"), 0x0306: ("lectura de area de programa", "carga"),
    0x0307: ("escritura de area de programa", "descarga"), 0x0308: ("borrado de area de programa", "descarga"),
    0x0401: ("RUN", "modo"), 0x0402: ("STOP", "modo"), 0x0702: ("escritura de reloj", "escritura"),
    0x2301: ("forzado de E/S", "forzado"),
}


def _primero(valor: str) -> str:
    return next((v for v in (valor or "").split("|") if v), "")


def _s7_servicio(rc: RowCtx) -> str:
    return _primero(rc.get("s7comm.param.pistart.servicename")).strip()


def _s7_clase(c: int, rc: RowCtx) -> str:
    if c == 0x28:
        return S7_PI.get(_s7_servicio(rc), "configuracion")
    return S7_CLASES.get(c, "")


def _s7_detalle(rc: RowCtx) -> str:
    partes = []
    if _s7_servicio(rc):
        partes.append(f"servicio={_s7_servicio(rc)}")
    tipo = _primero(rc.get("s7comm.data.blockcontrol.block_type"))
    if tipo:
        partes.append(f"bloque={tipo} {_primero(rc.get('s7comm.data.blockcontrol.block_number'))}".strip())
    return " ".join(partes)


@dataclass(frozen=True)
class Protocolo:
    nombre: str
    campo: str                          # campo de tshark con el codigo de funcion
    puerto: int                         # puerto del servidor: solo se cuenta la peticion
    codigos: frozenset                  # codigos que se reportan
    operacion: Callable[[int], str]     # texto de la operacion
    detalle: Callable[[RowCtx], str]    # columna "detalle"
    clase: Callable[[int, RowCtx], str] = lambda c, rc: ""    # clase de ingenieria (D1)


PROTOCOLOS = [
    Protocolo("Modbus/TCP", "modbus.func_code", 502, frozenset(MODBUS_FUNCS),
              lambda c: f"FC{c} {MODBUS_FUNCS[c]}",
              lambda rc: f"ref={rc.get('modbus.reference_num')}",
              lambda c, rc: "escritura" if c in MODBUS_ESCRITURAS else ""),
    Protocolo("DNP3", "dnp3.al.func", 20000, frozenset(DNP3_FUNCS) - {1},  # 1 = Read
              lambda c: f"FC{c} {DNP3_FUNCS[c]}",
              lambda rc: f"src={rc.get('dnp3.src')} dst={rc.get('dnp3.dst')}",
              lambda c, rc: DNP3_CLASES.get(c, "escritura")),
    Protocolo("IEC 60870-5-104", "iec60870_asdu.typeid", 2404, frozenset(IEC104_TYPES),
              lambda c: f"TypeID {c} {IEC104_TYPES[c]}",
              lambda rc: f"causa={rc.get('iec60870_asdu.causetx')}",
              lambda c, rc: IEC104_CLASES.get(c, "")),
    Protocolo("S7comm", "s7comm.param.func", 102, frozenset(S7_CRITICAL),
              lambda c: S7_FUNCS.get(c, f"funcion 0x{c:02x}"),
              _s7_detalle, _s7_clase),
]


def filtro_srtp() -> str:
    """Pieza del filtro de detalle: solo las peticiones SRTP con los codigos de SRTP_CODIGOS (tshark 4.4 no
    acepta `in {..}` sobre rebanadas de bytes)."""
    def con(byte: int) -> str:
        return " || ".join(f"tcp.payload[{byte}] == 0x{c:02x}" for c in SRTP_CODIGOS)
    return (f"tcp.dstport == {SRTP_PUERTO} && tcp.len >= {SRTP_MIN} && tcp.payload[0:2] == 02:00 && "
            f"((tcp.payload[{SRTP_BYTE_TIPO}] == 0xc0 && ({con(SRTP_BYTE_CORTO)})) || "
            f"(tcp.payload[{SRTP_BYTE_TIPO}] == 0x80 && ({con(SRTP_BYTE_EXT)})))")


def filtro_umas() -> str:
    return (f"modbus.func_code == {UMAS_FC} && ("
            + " || ".join(f"modbus.data[1] == 0x{c:02x}" for c in UMAS_CODIGOS) + ")")


def filtro_fins() -> str:
    return "omron.command in {" + ", ".join(f"0x{c:04x}" for c in FINS_CODIGOS) + "}"


def _codigo(token: str):
    """'0x29' o '41' -> 41; None si no es numerico."""
    try:
        return int(token, 16) if token.startswith("0x") else int(token)
    except ValueError:
        return None


@COLLECTORS
def control_por_codigo(rc: RowCtx) -> None:
    for p in PROTOCOLOS:
        for token in (rc.get(p.campo) or "").split("|"):
            if not token:
                continue
            code = _codigo(token)
            if code is None:
                continue
            if code in p.codigos and rc.toward_server(p.puerto):
                rc.cap.control_ops.append({
                    "frame": rc.frame, "t": rc.t, "proto": p.nombre,
                    "src": rc.sip, "dst": rc.get("ip.dst"),
                    "op": p.operacion(code), "detalle": p.detalle(rc),
                    "clase": p.clase(code, rc),
                })


@COLLECTORS
def control_cip(rc: RowCtx) -> None:
    cap, row, idx = rc.cap, rc.row, rc.idx
    sip, frame, t = rc.sip, rc.frame, rc.t
    firmware = any(_codigo(c) == CIP_CLASE_FIRMWARE for c in (g(row, idx, "cip.class") or "").split("|") if c)
    for sv in (g(row, idx, "cip.service") or "").split("|"):
        if not sv:
            continue
        try:
            code = int(sv, 16) if sv.startswith("0x") else int(sv)
        except ValueError:
            continue
        # El bit alto marca respuesta: solo contamos la peticion, si no
        # cada operacion se contaria dos veces.
        if code & 0x80:
            continue
        # Clase 0xA1 (memoria no volatil): cualquier peticion que no sea lectura es una carga de firmware.
        fw = firmware and code not in CIP_LECTURAS
        if fw or code in CIP_CRITICAL:
            cap.control_ops.append({
                "frame": frame, "t": t, "proto": "CIP / EtherNet/IP",
                "src": sip, "dst": g(row, idx, "ip.dst"),
                "op": CIP_OP_FIRMWARE if fw else CIP_SERVICES.get(code, f"servicio 0x{code:02x}"),
                "detalle": g(row, idx, "cip.symbol")[:80],
                "clase": "firmware" if fw else CIP_CLASES.get(code, ""),
            })


@COLLECTORS
def control_mms(rc: RowCtx) -> None:
    cap, row, idx = rc.cap, rc.row, rc.idx
    sip, frame, t = rc.sip, rc.frame, rc.t
    mmsreq = g(row, idx, "mms.confirmedServiceRequest")
    if mmsreq:
        cap.control_ops.append({
            "frame": frame, "t": t, "proto": "IEC 61850 MMS",
            "src": sip, "dst": g(row, idx, "ip.dst"),
            "op": f"MMS {mmsreq}", "detalle": "", "clase": "",
        })


@COLLECTORS
def control_srtp(rc: RowCtx) -> None:
    """GE SRTP: sin dissector en tshark 4.4, la carga llega como data.data (hex)."""
    if not rc.toward_server(SRTP_PUERTO):
        return
    datos = _primero(rc.get("data.data")).replace(":", "")
    if len(datos) < 2 * SRTP_MIN or datos[:4].lower() != "0200":
        return
    tipo = datos[2 * SRTP_BYTE_TIPO:2 * SRTP_BYTE_TIPO + 2].lower()
    byte = SRTP_BYTE_CORTO if tipo == "c0" else SRTP_BYTE_EXT if tipo == "80" else None
    if byte is None:
        return
    code = int(datos[2 * byte:2 * byte + 2], 16)
    if code in SRTP_CODIGOS:
        nombre, clase = SRTP_CODIGOS[code]
        rc.cap.control_ops.append({
            "frame": rc.frame, "t": rc.t, "proto": "GE SRTP", "src": rc.sip, "dst": rc.get("ip.dst"),
            "op": f"SRTP 0x{code:02x} {nombre}", "detalle": "", "clase": clase,
        })


@COLLECTORS
def control_umas(rc: RowCtx) -> None:
    """UMAS de Schneider (Modbus FC 90): modbus.data = clave de sesion + codigo UMAS + ..."""
    if not rc.toward_server(502):
        return
    if UMAS_FC not in {_codigo(c) for c in (rc.get("modbus.func_code") or "").split("|") if c}:
        return
    datos = _primero(rc.get("modbus.data")).replace(":", "")
    if len(datos) < 4:
        return
    try:
        code = int(datos[2:4], 16)
    except ValueError:
        return
    if code in UMAS_CODIGOS:
        nombre, clase = UMAS_CODIGOS[code]
        rc.cap.control_ops.append({
            "frame": rc.frame, "t": rc.t, "proto": "Modbus/TCP (UMAS)", "src": rc.sip,
            "dst": rc.get("ip.dst"), "op": f"UMAS 0x{code:02x} {nombre}", "detalle": "", "clase": clase,
        })


@COLLECTORS
def control_fins(rc: RowCtx) -> None:
    """FINS de Omron: solo comandos (ICF con el bit 0x40 apagado)."""
    if not rc.toward_server(FINS_PUERTO):
        return
    icf = _codigo(_primero(rc.get("omron.icf")))
    if icf is None or icf & 0x40:
        return
    for token in (rc.get("omron.command") or "").split("|"):
        code = _codigo(token) if token else None
        if code in FINS_CODIGOS:
            nombre, clase = FINS_CODIGOS[code]
            rc.cap.control_ops.append({
                "frame": rc.frame, "t": rc.t, "proto": "Omron FINS", "src": rc.sip, "dst": rc.get("ip.dst"),
                "op": f"FINS 0x{code:04x} {nombre}", "detalle": "", "clase": clase,
            })


DCP_PROTO = "PROFINET DCP"
DCP_OP_IP = "DCP Set IP"
DCP_OP_NOMBRE = "DCP Set nombre de estacion"
DCP_OP_DHCP = "DCP Set DHCP"
DCP_OP_SIGNAL = "DCP Signal"
DCP_OP_FABRICA = "DCP restablecer a fabrica"
DCP_CONTROL_FABRICA = frozenset({"5", "6"})   # Reset Factory Settings / Reset to Factory
# Opcion DCP -> campo con la subopcion de ese bloque (la peticion Set repite option/suboption por bloque).
DCP_SUBOPCION = {"1": "pn_dcp.suboption_ip", "2": "pn_dcp.suboption_device", "3": "pn_dcp.suboption_dhcp",
                 "5": "pn_dcp.suboption_control"}


def _lista(rc: RowCtx, campo: str) -> list:
    return rc.get(campo).split("|") if rc.get(campo) else []


@COLLECTORS
def control_dcp_set(rc: RowCtx) -> None:
    """PROFINET DCP Set (peticion): cambia IP, nombre de estacion o restablece a fabrica, por capa 2 y sin
    autenticacion. Sin IP: origen y destino son las MAC. Identify/Get y las respuestas no son operaciones."""
    if rc.get("pn_dcp.service_id") != "4" or rc.get("pn_dcp.service_type") != "0":
        return
    sig = {c: _lista(rc, f) for c, f in DCP_SUBOPCION.items()}
    ips, mascaras = _lista(rc, "pn_dcp.suboption_ip_ip"), _lista(rc, "pn_dcp.suboption_ip_subnetmask")
    nombres = _lista(rc, "pn_dcp.suboption_device_nameofstation")
    opciones = _lista(rc, "pn_dcp.option")
    cualif = _lista(rc, "pn_dcp.block_qualifier")
    usados = {c: 0 for c in DCP_SUBOPCION}
    n_ip = n_nom = 0
    for i, opcion in enumerate(opciones):
        if opcion not in DCP_SUBOPCION:
            continue
        lista = sig[opcion]
        sub = lista[usados[opcion]] if usados[opcion] < len(lista) else ""
        usados[opcion] += 1
        q = cualif[i] if len(cualif) == len(opciones) else (cualif[0] if cualif else "")
        op = detalle = clase = ""
        if opcion == "1" and sub == "2":
            ip = ips[n_ip] if n_ip < len(ips) else ""
            mascara = mascaras[n_ip] if n_ip < len(mascaras) else ""
            n_ip += 1
            op, clase = DCP_OP_IP, "configuracion"
            detalle = "; ".join(x for x in (f"IP {ip}", f"mascara {mascara}" if mascara else "",
                                            "permanente" if q == "1" else "temporal" if q == "0" else "") if x)
        elif opcion == "2" and sub == "2":
            nombre = nombres[n_nom] if n_nom < len(nombres) else ""
            n_nom += 1
            op, clase, detalle = DCP_OP_NOMBRE, "configuracion", f"nombre {nombre}"
        elif opcion == "3":
            op, clase = DCP_OP_DHCP, "configuracion"
        elif opcion == "5" and sub == "3":
            op = DCP_OP_SIGNAL
        elif opcion == "5" and sub in DCP_CONTROL_FABRICA:
            op, clase = DCP_OP_FABRICA, "reinicio"
        if op:
            rc.cap.control_ops.append({
                "frame": rc.frame, "t": rc.t, "proto": DCP_PROTO, "src": rc.smac, "dst": rc.get("eth.dst"),
                "op": op, "detalle": detalle[:80], "clase": clase,
            })


def op_visible(o: dict) -> str:
    """Nombre de la operacion para las salidas (las de DCP se traducen)."""
    return t(o["op"]) if o["proto"] == DCP_PROTO else o["op"]


def detalle_visible(o: dict) -> str:
    """Detalle para las salidas; en DCP se traducen las palabras fijas."""
    if o["proto"] != DCP_PROTO or not o["detalle"]:
        return o["detalle"]
    partes = []
    for x in o["detalle"].split("; "):
        if x in ("permanente", "temporal"):
            partes.append(t(x))
        elif x.startswith("mascara "):
            partes.append(t("mascara {m}", m=x[8:]))
        elif x.startswith("nombre "):
            partes.append(t("nombre {n}", n=x[7:]))
        else:
            partes.append(x)
    return "; ".join(partes)
