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

import weakref

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


# --- Evidencia observable de IEC 62351 (D117): agregados por clave, sin un evento por paquete ---
PUERTOS_TLS_62351 = (19998, 19999, 3782)
DNP3_AUTENTICACION = {32: "Authenticate Request", 33: "Authenticate Request No Ack", 131: "Authenticate Response"}
# SV no pasa por el detalle (trafico ciclico de alta tasa): sus pares salen de cap.l2_flows en iec62351.py.
DECODIFICADOS_62351 = {"MMS": "MMS", "S7COMM": "S7comm", "GOOSE": "GOOSE"}
# Indice (tipo, clave) -> evento por captura, para no recorrer protocolo_eventos en cada paquete.
# Se rehace si la lista de eventos cambio de objeto (filtro de equipos propios, recarga del cache).
_INDICE_62351: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()


def _acumular(rc: RowCtx, clave: tuple, evento: dict) -> None:
    lista = rc.cap.protocolo_eventos
    guardado = _INDICE_62351.get(rc.cap)
    if guardado is None or guardado[0] is not lista:
        guardado = (lista, {(e["tipo"], tuple(e["clave"])): e for e in lista if "clave" in e})
        _INDICE_62351[rc.cap] = guardado
    k = (evento["tipo"], tuple(clave))
    e = guardado[1].get(k)
    if e is not None:
        e["n"] += 1
        return
    e = {**evento, "clave": list(clave), "n": 1}
    lista.append(e)
    guardado[1][k] = e


@COLLECTORS
def evidencia_62351(rc: RowCtx) -> None:
    """ServerHello desde los puertos TLS de 62351, funciones de autenticacion segura de DNP3 y
    protocolo decodificado por par (MMS contra S7comm en 102, GOOSE en capa 2; SV sale de cap.l2_flows)."""
    if "2" in _lista(rc, "tls.handshake.type"):
        puerto = _int_or_none(rc.get("tcp.srcport"))
        if puerto in PUERTOS_TLS_62351:
            _acumular(rc, (puerto, rc.sip, rc.get("ip.dst")), {
                "tipo": "p62351_tls", "puerto": puerto, "servidor": rc.sip, "cliente": rc.get("ip.dst")})
    for x in _lista(rc, "dnp3.al.func"):
        code = _codigo(x)
        if code in DNP3_AUTENTICACION:
            # 32 y 33 las envia el maestro; 131 es la respuesta de la outstation.
            maestro, outstation = (rc.get("ip.dst"), rc.sip) if code == 131 else (rc.sip, rc.get("ip.dst"))
            _acumular(rc, (code, maestro, outstation), {
                "tipo": "p62351_dnp3_auth", "codigo": code, "maestro": maestro, "outstation": outstation})
    proto = DECODIFICADOS_62351.get(rc.get("_ws.col.protocol").upper())
    if proto:
        origen, destino = rc.sip or rc.smac, rc.get("ip.dst") or rc.get("eth.dst")
        _acumular(rc, (proto, origen, destino), {
            "tipo": "p62351_visto", "proto": proto, "origen": origen, "destino": destino})
