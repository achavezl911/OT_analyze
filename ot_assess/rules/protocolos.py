"""Reglas T4: OPC UA sin seguridad, TLS obsoleto o debil, Modbus FC8 y reinicio o paro DNP3 (D54)."""
from __future__ import annotations

import collections
import re

from ..detail.protocolos import DNP3_REINICIO, MODBUS_SUBF_GRAVES
from ..i18n import t, unir
from ..model import Capture
from .base import RULES, finding

_PURDUE_BAJO = re.compile(r"Nivel [012]")
_MAX_FILAS = 10


def _eventos(cap: Capture, tipo: str) -> list:
    return [e for e in cap.protocolo_eventos if e["tipo"] == tipo]


def _filas(cuenta: collections.Counter, plantilla: str) -> str:
    """Una linea por combinacion distinta; `plantilla` recibe los campos de la clave y n."""
    filas = [t(plantilla, n=n, **dict(k)) for k, n in sorted(cuenta.items(), key=lambda kv: (-kv[1], kv[0]))]
    extra = len(filas) - _MAX_FILAS
    if extra > 0:
        filas = filas[:_MAX_FILAS] + [t(" y {n} mas", n=extra)]
    return unir("\n", filas)


def _es_ot(cap: Capture, ip: str) -> bool:
    """El equipo de esa IP esta en Purdue 0-2 o tiene rol OT (no PC Windows, infraestructura ni indeterminado)."""
    for h in cap.hosts.values():
        if ip in h["ips"]:
            return bool(_PURDUE_BAJO.search(h.get("purdue") or "")) or (h.get("role") or "").startswith("Dispositivo OT")
    return False


@RULES
def opcua_sin_seguridad(cap: Capture) -> None:
    ev = _eventos(cap, "opcua_sin_seguridad")
    if not ev:
        return
    escriben = {(e["servidor"], e["puerto"]) for e in _eventos(cap, "opcua_escritura")}
    servidores = {(e["servidor"], e["puerto"]) for e in ev}
    expuestos = servidores & escriben
    cuenta = collections.Counter(
        (("cliente", e["cliente"]), ("servidor", e["servidor"]), ("puerto", e["puerto"]),
         ("politica", e["politica"]), ("modo", e["modo"])) for e in ev)
    texto = _filas(cuenta, "{cliente} -> {servidor}:{puerto}, politica {politica}, modo {modo} ({n} aperturas de canal)")
    if expuestos:
        texto = unir("\n", [texto, unir("; ", (t("{s}:{p} tambien recibe Write o Call", s=s, p=p)
                                               for s, p in sorted(expuestos)))])
    finding(
        cap, "Media",
        "OPC UA sin seguridad de mensajes (politica None)",
        texto,
        "Con SecurityPolicy None el canal no firma ni cifra: quien ve la red puede leer y alterar lecturas, "
        "escrituras y llamadas, y suplantar a cualquiera de los dos extremos. Es mas grave si el mismo "
        "servidor acepta Write o Call.",
        "Exigir Basic256Sha256 o superior con Sign&Encrypt y deshabilitar el endpoint None en el servidor; "
        "dejar el modo None solo para pruebas en red aislada.",
        categoria="Cifrado",
        activos=[e["servidor"] for e in ev] + [e["cliente"] for e in ev],
    )
    if expuestos:        # Alta si el mismo servidor acepta Write o Call
        cap.findings[-1]["severidad"] = "Alta"


@RULES
def tls_obsoleto(cap: Capture) -> None:
    ev = _eventos(cap, "tls_debil")
    if not ev:
        return
    sni = {}
    for n in cap.nombres_servidor:
        if n["fuente"] == "TLS SNI":
            sni.setdefault(n["ip"], n["nombre"])
    cuenta = collections.Counter(
        (("servidor", e["servidor"]), ("puerto", e["puerto"]), ("version", e["version"]), ("suite", e["suite"]),
         ("sni", sni.get(e["servidor"], "-"))) for e in ev)
    texto = _filas(cuenta, "{servidor}:{puerto}, version {version}, suite {suite}, SNI {sni} ({n} ServerHello)")
    ot = any(_es_ot(cap, e["servidor"]) for e in ev)
    finding(
        cap, "Media",
        "TLS obsoleto o con suite debil negociado por el servidor",
        texto,
        "El ServerHello fija lo que se usa de verdad. SSL 3.0, TLS 1.0 y TLS 1.1 estan obsoletos, y las suites "
        "NULL, EXPORT, anonimas, RC4, DES y 3DES no dan una proteccion real: el trafico puede descifrarse o "
        "alterarse. Si el servidor es un equipo OT, rara vez se podra parchar, y el riesgo se prolonga.",
        "Deshabilitar en el servidor SSL 3.0, TLS 1.0 y 1.1 y las suites debiles; dejar TLS 1.2 o superior con "
        "suites AEAD. Si el equipo no lo permite, aislarlo detras de un proxy TLS o un firewall OT.",
        categoria="Cifrado",
        activos=[e["servidor"] for e in ev],
    )
    if ot:               # Alta si el servidor es un equipo OT o esta en Purdue 0-2
        cap.findings[-1]["severidad"] = "Alta"


@RULES
def modbus_fc8(cap: Capture) -> None:
    ev = _eventos(cap, "modbus_diagnostico")
    graves = [e for e in ev if e["grave"]]
    resto = [e for e in ev if not e["grave"]]

    def clave(e):
        return (("origen", e["origen"]), ("destino", e["destino"]), ("unidad", e["unidad"]),
                ("subfuncion", "-" if e["subfuncion"] is None else
                 f"{e['subfuncion']} {MODBUS_SUBF_GRAVES.get(e['subfuncion'], '')}".strip()))
    plantilla = "{origen} -> {destino}, unidad {unidad}, subfuncion {subfuncion} ({n} solicitudes)"
    if graves:
        finding(
            cap, "Alta",
            "Modbus FC8 que reinicia o silencia el equipo",
            _filas(collections.Counter(clave(e) for e in graves), plantilla),
            "Las subfunciones 1 (Restart Communications) y 4 (Force Listen Only Mode) dejan al esclavo sin "
            "responder o reiniciando su comunicacion: un solo mensaje puede sacar de servicio al equipo. "
            "Modbus no autentica al origen.",
            "Restringir FC8 por firewall OT o inspeccion profunda que bloquee las subfunciones 1 y 4 salvo desde "
            "la estacion de ingenieria autorizada.",
            categoria="Control",
            activos=[e["destino"] for e in graves] + [e["origen"] for e in graves],
        )
    if resto:
        finding(
            cap, "Baja",
            "Modbus FC8 de diagnostico (sin reinicio ni silencio)",
            _filas(collections.Counter(clave(e) for e in resto), plantilla),
            "El diagnostico Modbus (consulta de eco, contadores, registro de diagnostico) no cambia el estado del "
            "equipo, pero conviene que solo lo use la estacion de ingenieria o de mantenimiento.",
            "Confirmar que el origen es una estacion de mantenimiento autorizada y, si no, bloquear FC8 por firewall OT.",
            categoria="Control",
            activos=[e["destino"] for e in resto] + [e["origen"] for e in resto],
        )


@RULES
def dnp3_reinicio(cap: Capture) -> None:
    ev = _eventos(cap, "dnp3_reinicio")
    if not ev:
        return
    cuenta = collections.Counter(
        (("maestro", e["maestro"]), ("outstation", e["outstation"]), ("enlace", e["enlace"]),
         ("codigo", f"{e['codigo']} {DNP3_REINICIO[e['codigo']]}")) for e in ev)
    finding(
        cap, "Alta",
        "DNP3 con reinicio o paro de aplicacion (Cold Restart, Warm Restart, Stop Application)",
        _filas(cuenta, "{maestro} -> {outstation} (enlace {enlace}), codigo {codigo} ({n} solicitudes)"),
        "Los codigos 13 (Cold Restart), 14 (Warm Restart) y 18 (Stop Application) reinician o detienen la "
        "aplicacion de la outstation y la sacan de servicio. Solo el maestro autorizado debe enviarlos, y casi "
        "nunca en operacion normal.",
        "Restringir por firewall OT o inspeccion profunda que bloquee esos codigos salvo desde la estacion de "
        "ingenieria autorizada; usar Secure Authentication de DNP3 donde el equipo lo permita.",
        categoria="Control",
        activos=[e["outstation"] for e in ev] + [e["maestro"] for e in ev],
    )
