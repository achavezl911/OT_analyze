"""Colector: credenciales y administracion en texto claro."""
from __future__ import annotations

from ..util import g
from .base import COLLECTORS, RowCtx


@COLLECTORS
def texto_claro(rc: RowCtx) -> None:
    cap, row, idx = rc.cap, rc.row, rc.idx
    sip, frame = rc.sip, rc.frame
    # ---- texto claro / credenciales ---------------------------------- #
    comm = g(row, idx, "snmp.community")
    if comm:
        ver = g(row, idx, "snmp.msgVersion")
        cap.cleartext.append({
            "frame": frame, "ip": sip, "tipo": "SNMP community",
            "detalle": f"community='{comm}' version={ver or '?'}",
        })
    auth = g(row, idx, "http.authorization")
    if auth:
        cap.cleartext.append({
            "frame": frame, "ip": sip, "tipo": "HTTP Authorization",
            "detalle": auth[:120],
        })
    ftpc = g(row, idx, "ftp.request.command")
    if ftpc and ftpc.upper() in ("USER", "PASS"):
        cap.cleartext.append({
            "frame": frame, "ip": sip, "tipo": f"FTP {ftpc.upper()}",
            "detalle": g(row, idx, "ftp.request.arg")[:80],
        })
    tel = g(row, idx, "telnet.data")
    if tel:
        cap.cleartext.append({
            "frame": frame, "ip": sip, "tipo": "Telnet",
            "detalle": tel.replace("\r", " ").replace("\n", " ")[:80],
        })
    for fld, label in (("tftp.source_file", "TFTP lectura"),
                       ("tftp.destination_file", "TFTP escritura")):
        v = g(row, idx, fld)
        if v:
            cap.cleartext.append({
                "frame": frame, "ip": sip, "tipo": label, "detalle": v[:120],
            })
    ntlm_u = g(row, idx, "ntlmssp.auth.username")
    if ntlm_u and ntlm_u not in ("NULL", ""):
        cap.cleartext.append({
            "frame": frame, "ip": sip, "tipo": "Autenticacion NTLM",
            "detalle": f"{g(row, idx, 'ntlmssp.auth.domain')}\\{ntlm_u}",
        })
