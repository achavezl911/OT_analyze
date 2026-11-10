"""Piezas comunes de los detectores por indicador (T8 acceso remoto, T9 evasion): coincidencia de dominios,
ambito OT/IT, destino Internet/interno, descarte por destino de muchos puertos y acumulador de indicadores.

Funciones puras sin tshark ni reglas. Extraido de acceso_remoto.py sin cambiar su comportamiento.
"""
from __future__ import annotations

import ipaddress
import re

M_PUERTO, M_DNS, M_SNI, M_HTTP, M_EXPORT = "puerto", "DNS", "SNI", "HTTP", "dominio exportado"
VERIFICADO, SIN_VERIFICAR = "verificado", "sin verificar"
D_INTERNET, D_INTERNO, D_INDETERMINADO = "Internet", "interno", "sin determinar"
A_OT, A_IT = "OT", "IT"
D_DESCARTADO = "descartado"
PUERTOS_SERVIDOR_MAX = 100   # un destino con mas puertos distintos no "sirve" herramientas: es un artefacto
MAX_DESTINOS = 5
_NIVEL = re.compile(r"^Nivel (\d+(?:\.\d+)?)(?:-(\d+(?:\.\d+)?))?$")
_METODO_SNI = {"TLS SNI": M_SNI, "HTTP Host": M_HTTP}


def _limpio(nombre) -> str:
    return str(nombre or "").strip().lower().rstrip(".")


def coincide_dominio(nombre: str, dominio: str) -> bool:
    """Sufijo con limite de etiqueta: 'x.teamviewer.com' si; 'noteamviewer.com' y 'teamviewer.com.evil.net' no."""
    n, d = _limpio(nombre), _limpio(dominio)
    return bool(n and d) and (n == d or n.endswith("." + d))


def es_ot(purdue: str) -> bool:
    """Nivel Purdue entero dentro de 0-2 ('Nivel 1-2' si; 'Nivel 2-3' no: es indeterminado)."""
    m = _NIVEL.match(str(purdue or ""))
    if not m:
        return False
    return float(m.group(2) or m.group(1)) <= 2


_DOCUMENTACION = tuple(ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))


def _publica(ip) -> bool:
    """Direccion de Internet. Los bloques de documentacion (RFC 5737) cuentan como Internet: no son de nadie."""
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    if a.is_multicast:
        return False
    return a.is_global or any(a in n for n in _DOCUMENTACION if a.version == n.version)


def orden_ip(ip: str) -> tuple:
    try:
        a = ipaddress.ip_address(ip)
        return (0, a.version, int(a), "")
    except ValueError:
        return (1, 0, 0, str(ip))


def _destino(ips, externo: bool = False) -> str:
    ips = [i for i in ips if i]
    if externo or any(_publica(i) for i in ips):
        return D_INTERNET
    return D_INTERNO if ips else D_INDETERMINADO


# --------------------------------------------------------------------------- #
# Acumulador de indicadores
# --------------------------------------------------------------------------- #


def puertos_por_destino(pares) -> dict:
    """{ip destino: n de puertos destino distintos} a partir de pares (ip, puerto)."""
    vistos: dict = {}
    for ip, puerto in pares:
        if ip and str(puerto) != "":
            vistos.setdefault(ip, set()).add(str(puerto))
    return {ip: len(v) for ip, v in vistos.items()}


def destinos_de_muchos_puertos(conteo: dict) -> dict:
    """Destinos con mas de PUERTOS_SERVIDOR_MAX puertos distintos: {ip: n}. Sentido invertido, NAT o escaneo."""
    return {ip: n for ip, n in conteo.items() if n > PUERTOS_SERVIDOR_MAX}


def _pares_captura(cap):
    return ((f["dst"], f["dport"]) for f in getattr(cap, "flows", {}).values())


class _Acum:
    """Un indicador por (cliente, herramienta, metodo, indicador). Si la entrada lleva `tipo`, la fila lo repite."""

    def __init__(self, fuente: str, nivel_de, nombre_de, muchos=None):
        self.fuente, self.nivel_de, self.nombre_de = fuente, nivel_de, nombre_de
        self.muchos = muchos or {}
        self.d: dict = {}

    def sumar(self, cliente: str, e: dict, metodo: str, indicador: str, destinos=(), conductos=(), nbytes=0,
              primera="", ultima="", externo: bool = False) -> None:
        k = (cliente, e["herramienta"], metodo, indicador)
        x = self.d.get(k)
        if x is None:
            x = self.d[k] = {"ip": cliente, "herramienta": e["herramienta"], "estado": e["estado"],
                             "tipo": e.get("tipo"), "metodo": metodo, "indicador": indicador, "destinos": set(),
                             "conductos": set(), "bytes": 0, "primera": "", "ultima": "", "externo": False,
                             "fuente": self.fuente}
        x["destinos"].update(i for i in destinos if i)
        x["conductos"].update(conductos)
        x["bytes"] += nbytes
        x["externo"] = x["externo"] or externo
        if primera and (not x["primera"] or primera < x["primera"]):
            x["primera"] = primera
        if ultima and ultima > x["ultima"]:
            x["ultima"] = ultima

    def lista(self) -> list:
        out = []
        for k in sorted(self.d):
            x = self.d[k]
            destinos = sorted(x["destinos"])
            nota = ""
            if x["metodo"] == M_PUERTO and destinos and all(i in self.muchos for i in destinos):
                nota = (f"destino con {max(self.muchos[i] for i in destinos)} puertos distintos: no concluyente "
                        "(sentido invertido, NAT o escaneo)")
            ot_cliente = es_ot(self.nivel_de(x["ip"]))
            ot_destino = any(es_ot(self.nivel_de(i)) for i in destinos)
            fila = {
                "activo": self.nombre_de(x["ip"]), "ip": x["ip"], "herramienta": x["herramienta"],
                "estado": D_DESCARTADO if nota else x["estado"], "nota": nota,
                "metodo": x["metodo"], "indicador": x["indicador"],
                "destino": _destino(destinos, x["externo"]), "destino_ip": ";".join(destinos[:MAX_DESTINOS]),
                "ambito": A_OT if (ot_cliente or ot_destino) else A_IT, "ot": ot_cliente or ot_destino,
                "conductos": len(x["conductos"]), "bytes": x["bytes"], "primera": x["primera"],
                "ultima": x["ultima"], "fuente": x["fuente"]}
            if x["tipo"] is not None:       # solo T9: T8 no lleva tipo
                fila["tipo"] = x["tipo"]
            out.append(fila)
        return sorted(out, key=lambda x: (x["herramienta"], x["ip"], x["metodo"], x["indicador"], x["fuente"]))


def ayudas_exportacion(assets: dict) -> tuple:
    """(ip_de, nivel_de, nombre_de, externo) sobre los activos de una exportacion (ids de activo -> IP)."""
    ips_de = {k: sorted(a.get("ips") or ()) for k, a in assets.items()}

    def ip_de(x):
        return (ips_de.get(x) or [x])[0]

    def nivel_de(ip):
        for k, a in assets.items():
            if ip in (a.get("ips") or ()) or ip == k:
                return a.get("purdue") or ""
        return ""

    def nombre_de(ip):
        for k, a in assets.items():
            if ip in (a.get("ips") or ()) or ip == k:
                return a.get("nombre") or ip
        return ip

    def externo(x):
        return str((assets.get(x) or {}).get("purdue") or "") == "Externo"

    return ip_de, nivel_de, nombre_de, externo


def _mapas_captura(cap) -> tuple:
    nivel, nombre = {}, {}
    for h in getattr(cap, "hosts", {}).values():
        for ip in h.get("ips") or ():
            nivel.setdefault(ip, h.get("purdue") or "")
            hn = sorted(h.get("hostnames") or ())
            if hn:
                nombre.setdefault(ip, hn[0])
    return (lambda ip: nivel.get(ip, "")), (lambda ip: nombre.get(ip, ip))
