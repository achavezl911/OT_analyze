"""Colector: credenciales y administracion en texto claro.

SEC1 (D138): el registro NUNCA lleva el valor del secreto (comunidad SNMP, Authorization, argumento de FTP
USER/PASS, texto de Telnet). Se guarda el hecho: tipo, origen, destino, puerto, trama, fecha UTC y datos no
secretos (version SNMP, esquema HTTP, comando FTP). Tampoco el largo del valor: revelaria el largo de la
contrasena."""
from __future__ import annotations

import datetime

from ..util import g
from .base import COLLECTORS, RowCtx


def _fecha_utc(t: float) -> str:
    if not t:
        return ""
    try:
        d = datetime.datetime.fromtimestamp(t, datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return ""
    return d.strftime("%Y-%m-%d %H:%M:%S UTC")


def _esquema_http(auth: str) -> str:
    e = auth.split(None, 1)[0].lower() if auth.strip() else ""
    return {"basic": "Basic", "bearer": "Bearer"}.get(e, "otro")


@COLLECTORS
def texto_claro(rc: RowCtx) -> None:
    cap, row, idx = rc.cap, rc.row, rc.idx
    sip, frame = rc.sip, rc.frame
    dip = g(row, idx, "ip.dst").split("|")[0]
    puerto = g(row, idx, "tcp.dstport") or g(row, idx, "udp.dstport")
    fecha = _fecha_utc(rc.t)

    def anota(tipo: str, detalle: str) -> None:
        cap.cleartext.append({
            "frame": frame, "ip": sip, "dst": dip, "puerto": puerto, "fecha_utc": fecha,
            "tipo": tipo, "detalle": detalle,
        })

    # ---- texto claro / credenciales ---------------------------------- #
    comm = g(row, idx, "snmp.community")
    if comm:
        ver = g(row, idx, "snmp.msgVersion")
        anota("SNMP community", f"version={ver or '?'}")
    auth = g(row, idx, "http.authorization")
    if auth:
        anota("HTTP Authorization", f"esquema={_esquema_http(auth)}")
    ftpc = g(row, idx, "ftp.request.command")
    if ftpc and ftpc.upper() in ("USER", "PASS"):
        anota(f"FTP {ftpc.upper()}", f"comando={ftpc.upper()}")
    tel = g(row, idx, "telnet.data")
    if tel:
        anota("Telnet", "")
    for fld, label in (("tftp.source_file", "TFTP lectura"),
                       ("tftp.destination_file", "TFTP escritura")):
        v = g(row, idx, fld)
        if v:
            anota(label, v[:120])
    ntlm_u = g(row, idx, "ntlmssp.auth.username")
    if ntlm_u and ntlm_u not in ("NULL", ""):
        anota("Autenticacion NTLM", f"{g(row, idx, 'ntlmssp.auth.domain')}\\{ntlm_u}")
