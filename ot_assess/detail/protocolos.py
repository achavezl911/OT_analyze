"""Colector T4: seguridad de protocolo (OPC UA sin seguridad, TLS debil, Modbus FC8, DNP3 reinicio).

Cada evento va a cap.protocolo_eventos con un `tipo`; las reglas de rules/protocolos.py los agrupan.
Campos de tshark (validados con tshark 4.4; si uno falta en otra version se omite con aviso y el
colector correspondiente no genera eventos):
  OPC UA  opcua.transport.type, opcua.security.spu, opcua.MessageSecurityMode, opcua.servicenodeid.numeric
  TLS     tls.handshake.type, tls.handshake.version, tls.handshake.ciphersuite
  Modbus  modbus.func_code, modbus.diagnostic_code, mbtcp.unit_id
  DNP3    dnp3.al.func, dnp3.src, dnp3.dst
"""
from __future__ import annotations

from ..catalog import TLS_SUITES_DEBILES, TLS_VERSIONES_OBSOLETAS
from ..util import _int_or_none
from .base import COLLECTORS, RowCtx
from .control import _codigo

OPCUA_OPEN_REQUEST = 446                       # OpenSecureChannelRequest
OPCUA_SERVICIOS_ESCRITURA = {673: "Write", 712: "Call"}
OPCUA_MODOS = {1: "None", 2: "Sign", 3: "SignAndEncrypt"}
MODBUS_FC_DIAG = 8
MODBUS_SUBF_GRAVES = {1: "Restart Communications Option", 4: "Force Listen Only Mode"}
DNP3_REINICIO = {13: "Cold Restart", 14: "Warm Restart", 18: "Stop Application"}


def _lista(rc: RowCtx, campo: str) -> list:
    return [x for x in rc.get(campo).split("|") if x]


def _puerto_destino(rc: RowCtx):
    return _int_or_none(rc.get("tcp.dstport")) or _int_or_none(rc.get("udp.dstport"))


@COLLECTORS
def opcua_seguridad(rc: RowCtx) -> None:
    servicios = {_codigo(x) for x in _lista(rc, "opcua.servicenodeid.numeric")}
    base = {"frame": rc.frame, "cliente": rc.sip, "servidor": rc.get("ip.dst"), "puerto": _puerto_destino(rc)}
    for nodo, nombre in OPCUA_SERVICIOS_ESCRITURA.items():
        if nodo in servicios:
            rc.cap.protocolo_eventos.append({"tipo": "opcua_escritura", "servicio": nombre, **base})
    # Solo la peticion de apertura del canal: la respuesta repite la politica y el
    # GetEndpoints lista politicas que el servidor ofrece, no las que se usan.
    if OPCUA_OPEN_REQUEST not in servicios or "OPN" not in _lista(rc, "opcua.transport.type"):
        return
    politica = (_lista(rc, "opcua.security.spu") or [""])[0]
    modo = _codigo((_lista(rc, "opcua.MessageSecurityMode") or [""])[0])
    if politica.endswith("#None") or modo == 1:
        rc.cap.protocolo_eventos.append({
            "tipo": "opcua_sin_seguridad", "politica": politica or "-",
            "modo": OPCUA_MODOS.get(modo, "-"), **base})


@COLLECTORS
def tls_debil(rc: RowCtx) -> None:
    tipos = _lista(rc, "tls.handshake.type")
    # Solo el ServerHello: lo que el cliente ofrece no es lo negociado.
    if "2" not in tipos or "1" in tipos:
        return
    version = _codigo((_lista(rc, "tls.handshake.version") or [""])[0])
    suite = _codigo((_lista(rc, "tls.handshake.ciphersuite") or [""])[0])
    motivos = []
    if version in TLS_VERSIONES_OBSOLETAS:
        motivos.append(TLS_VERSIONES_OBSOLETAS[version])
    if suite in TLS_SUITES_DEBILES:
        motivos.append(TLS_SUITES_DEBILES[suite])
    if not motivos:
        return
    rc.cap.protocolo_eventos.append({
        "tipo": "tls_debil", "frame": rc.frame, "servidor": rc.sip, "cliente": rc.get("ip.dst"),
        "puerto": _int_or_none(rc.get("tcp.srcport")) or _int_or_none(rc.get("udp.srcport")),
        "version": TLS_VERSIONES_OBSOLETAS.get(version, "TLS 1.2+"),
        "suite": TLS_SUITES_DEBILES.get(suite) or (f"0x{suite:04X}" if suite is not None else "-"),
        "motivos": motivos})


@COLLECTORS
def modbus_diagnostico(rc: RowCtx) -> None:
    if MODBUS_FC_DIAG not in {_codigo(x) for x in _lista(rc, "modbus.func_code")}:
        return
    if not rc.toward_server(502):
        return
    sub = _codigo((_lista(rc, "modbus.diagnostic_code") or [""])[0])
    rc.cap.protocolo_eventos.append({
        "tipo": "modbus_diagnostico", "frame": rc.frame, "origen": rc.sip, "destino": rc.get("ip.dst"),
        "unidad": (_lista(rc, "mbtcp.unit_id") or ["-"])[0],
        "subfuncion": sub, "grave": sub in MODBUS_SUBF_GRAVES})


@COLLECTORS
def dnp3_reinicio(rc: RowCtx) -> None:
    if not rc.toward_server(20000):
        return
    for x in _lista(rc, "dnp3.al.func"):
        code = _codigo(x)
        if code in DNP3_REINICIO:
            rc.cap.protocolo_eventos.append({
                "tipo": "dnp3_reinicio", "frame": rc.frame, "maestro": rc.sip, "outstation": rc.get("ip.dst"),
                "codigo": code, "enlace": f"{rc.get('dnp3.src')}->{rc.get('dnp3.dst')}"})
