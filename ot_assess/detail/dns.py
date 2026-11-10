"""Colector: eventos DNS tipados y nombres de servidor vistos por TLS (SNI) y HTTP (Host).

tshark entrega los campos con varios valores como "v1|v2|...". dns.resp.* trae un valor por
registro (respuesta, autoridad, adicional, en ese orden); dns.a, dns.cname, ... traen solo los
de su tipo y en el mismo orden, asi que se recorre resp.type y se toma el siguiente de cada lista.
"""
from __future__ import annotations

import ipaddress

from .base import COLLECTORS, RowCtx

TIPOS = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
         33: "SRV", 64: "SVCB", 65: "HTTPS", 251: "IXFR", 252: "AXFR", 255: "ANY"}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
# tipo -> campo de tshark con el valor
CAMPO_TIPO = {"A": "dns.a", "AAAA": "dns.aaaa", "CNAME": "dns.cname", "NS": "dns.ns",
              "PTR": "dns.ptr.domain_name", "MX": "dns.mx.mail_exchange",
              "SRV": "dns.srv.target", "TXT": "dns.txt", "SOA": "dns.soa.mname"}


def _nombre_de(valor: str, tabla: dict) -> str:
    """Numero -> nombre; acepta tambien el texto que tshark pueda dar."""
    v = valor.strip()
    try:
        n = int(v, 0)
    except ValueError:
        return v.upper()
    return tabla.get(n, str(n))


def tipo_dns(valor: str) -> str:
    return _nombre_de(valor, TIPOS)


def rcode_dns(valor: str) -> str:
    return _nombre_de(valor, RCODES)


def _limpio(nombre: str) -> str:
    return nombre.strip().lower().rstrip(".")


def _lista(valor: str) -> list:
    return valor.split("|") if valor else []


def respuestas(get) -> list:
    """[(dueno, tipo, valor, ttl)] de los primeros dns.count.answers registros."""
    nombres, tipos = _lista(get("dns.resp.name")), _lista(get("dns.resp.type"))
    ttls = _lista(get("dns.resp.ttl"))
    try:
        n_resp = int(get("dns.count.answers").split("|")[0])
    except ValueError:
        n_resp = len(tipos)
    valores = {tipo: _lista(get(campo)) for tipo, campo in CAMPO_TIPO.items()}
    pos = {t: 0 for t in valores}
    out = []
    for i, t in enumerate(tipos):
        tipo = tipo_dns(t)
        valor = ""
        if tipo in valores:       # se consume siempre, aunque el registro no se guarde
            if pos[tipo] < len(valores[tipo]):
                valor = valores[tipo][pos[tipo]]
            pos[tipo] += 1
        if i >= n_resp:
            continue
        ttl = ttls[i] if i < len(ttls) else ""
        out.append((_limpio(nombres[i]) if i < len(nombres) else "", tipo,
                    valor.strip(), int(ttl) if ttl.isdigit() else None))
    return out


def _es_ip(texto: str) -> bool:
    try:
        ipaddress.ip_address(texto)
        return True
    except ValueError:
        return False


def _es_multicast_dns(get) -> bool:
    """mDNS (UDP 5353) y LLMNR (UDP 5355) tambien traen campos dns.*: no son DNS de servidor."""
    if {get("udp.srcport"), get("udp.dstport")} & {"5353", "5355"}:
        return True
    dst = (get("ip.dst") or get("ipv6.dst")).split("|")[0]
    try:
        return ipaddress.ip_address(dst).is_multicast
    except ValueError:
        return False


@COLLECTORS
def dns(rc: RowCtx) -> None:
    cap, get = rc.cap, rc.get
    nombre = _limpio(get("dns.qry.name").split("|")[0])
    if nombre and not _es_multicast_dns(get):
        es_resp = get("dns.flags.response").split("|")[0].lower() in ("1", "true")
        qtipo = get("dns.qry.type").split("|")[0]
        rcode = get("dns.flags.rcode").split("|")[0]
        cap.dns_eventos.append({
            "t": rc.t, "src": rc.sip, "dst": get("ip.dst"), "id": get("dns.id").split("|")[0],
            "resp": es_resp, "nombre": nombre,
            "tipo": tipo_dns(qtipo) if qtipo else "",
            "rcode": rcode_dns(rcode) if es_resp and rcode else "",
            "respuestas": respuestas(get) if es_resp else [],
        })
    dst = get("ip.dst")
    if not dst:
        return
    sni = get("tls.handshake.extensions_server_name").split("|")[0]
    if sni and not _es_ip(sni):
        cap.nombres_servidor.append({"fuente": "TLS SNI", "ip": dst, "nombre": _limpio(sni), "src": rc.sip,
                                     "t": rc.t})
    for host in _lista(get("http.host")):
        host = host.strip()
        if host.startswith("["):
            continue
        if host.count(":") == 1:
            host = host.split(":")[0]
        if host and not _es_ip(host):
            cap.nombres_servidor.append({"fuente": "HTTP Host", "ip": dst, "nombre": _limpio(host),
                                         "src": rc.sip, "t": rc.t})
