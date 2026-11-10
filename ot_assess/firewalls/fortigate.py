"""Adaptador de la configuracion de una FortiGate (FortiOS 6.x/7.x) al modelo comun de firewall (F2).

Entrada: texto de `show full-configuration` (o `show` por secciones) y, opcional, la tabla de rutas
(`get router info routing-table all`); archivo o carpeta con varios archivos. Cada VDOM es un Firewall.
SEGURIDAD: solo se leen las secciones system interface/zone/global, router static, firewall address,
addrgrp, service custom, service group, policy y vip (esta ultima solo por sus nombres). Cualquier otra
seccion (usuarios, VPN, certificados, SNMP...) se descarta sin copiarse, y de las leidas se descarta toda
clave que parezca un secreto (password, passwd, psksecret, private-key, key, secret, community...).
NO validado con una muestra real: sintaxis publica de FortiOS; lo no interpretado queda como aviso.
"""
from __future__ import annotations

import csv
import ipaddress
import re
import shlex
from pathlib import Path

from .modelo import Firewall, Interfaz, Regla, Ruta, Subregla

FABRICANTE = "Fortinet FortiGate"
ACL = "fortigate-policy"
_ANY = ipaddress.IPv4Network("0.0.0.0/0")
BLACKHOLE = "blackhole"

# Servicios predefinidos de FortiOS que no aparecen en la configuracion. Tabla pequena escrita de memoria,
# NO validada contra el fabricante: uno que no este aqui ni en la configuracion queda como aviso y la regla
# como "puerto no resuelto". Valor: lista de (protocolo, puertos de destino); () = todos los puertos.
PREDEFINIDOS = {
    "ALL": [("all", ())], "ALL_TCP": [("tcp", ())], "ALL_UDP": [("udp", ())], "ALL_ICMP": [("icmp", ())],
    "PING": [("icmp", ())], "HTTP": [("tcp", ((80, 80),))], "HTTPS": [("tcp", ((443, 443),))],
    "SSH": [("tcp", ((22, 22),))], "TELNET": [("tcp", ((23, 23),))],
    "DNS": [("tcp", ((53, 53),)), ("udp", ((53, 53),))], "NTP": [("udp", ((123, 123),))],
    "SNMP": [("tcp", ((161, 162),)), ("udp", ((161, 162),))], "RDP": [("tcp", ((3389, 3389),))],
    "SMB": [("tcp", ((445, 445),))], "LDAP": [("tcp", ((389, 389),))], "FTP": [("tcp", ((21, 21),))],
    "SMTP": [("tcp", ((25, 25),))], "POP3": [("tcp", ((110, 110),))], "IMAP": [("tcp", ((143, 143),))],
    "SYSLOG": [("udp", ((514, 514),))], "TFTP": [("udp", ((69, 69),))], "DHCP": [("udp", ((67, 68),))],
    "MYSQL": [("tcp", ((3306, 3306),))], "MS-SQL": [("tcp", ((1433, 1433),))],
    "GRE": [("gre", ())], "ESP": [("esp", ())], "AH": [("ah", ())],
}
_PROTO_NUM = {1: "icmp", 4: "ipinip", 6: "tcp", 17: "udp", 47: "gre", 50: "esp", 51: "ah", 89: "ospf"}

_LEER = {"system interface", "system zone", "system global", "router static", "firewall address",
         "firewall addrgrp", "firewall service custom", "firewall service group", "firewall policy",
         "firewall vip"}
_ENVOLTORIOS = ("global", "vdom")
_SECRETO = re.compile(r"pass|psk|secret|private|^key|key$|community|token|auth-|priv-|cert|^ca$|^enc|"
                      r"^comment|^description", re.IGNORECASE)
_RE_PROMPT = re.compile(r"^\S+(?:\s+\([^)]*\))?\s+[#$]\s+(.*)$")
_RE_MORE = re.compile(r"(?:<-+\s*More\s*-+>|-+\s*More\s*-+)\s*")
_RE_MARCA_CFG = re.compile(r"^\s*(?:\S+(?:\s+\([^)]*\))?\s+[#$]\s+)?config\s+(?:firewall\s+policy|system\s+interface)\b",
                           re.MULTILINE | re.IGNORECASE)
_RE_MARCA_RUTAS = re.compile(r"Routing table for VRF|get router info", re.IGNORECASE)
_RE_RUTA = re.compile(r"^(?P<cod>[A-Za-z][A-Za-z0-9*>]*(?:\s+[A-Za-z]\d?)?)\s+(?P<red>\d+\.\d+\.\d+\.\d+/\d+)"
                      r"\s+(?P<resto>\S.*)$")
_RE_CONT = re.compile(r"^\[(?P<ad>\d+)/(?P<met>\d+)\]\s+via\s+")
_RE_AD = re.compile(r"\[(\d+)/(\d+)\]")
_RE_VIA = re.compile(r"via\s+(\d+\.\d+\.\d+\.\d+)")

# FortiOS escribe la puerta de enlace vacia como 0.0.0.0: es un dato de ruta, no una direccion de escucha.
_SIN_SALTO = "0.0.0.0"  # nosec B104


def _limpiar(texto: str) -> list:
    texto = texto.replace("\x08", "").replace("\r\n", "\n").replace("\r", "\n")
    return [_RE_MORE.sub("", ln).strip() for ln in texto.split("\n")]


def _tokens(linea: str) -> list:
    try:
        return shlex.split(linea)
    except ValueError:
        return linea.split()


class _N:
    """Nodo del arbol: un bloque `config` (nombre = seccion) o un `edit` (nombre = clave)."""
    __slots__ = ("cont", "es_edit", "hijos", "ignorar", "nombre", "sets")

    def __init__(self, nombre, es_edit, ignorar, cont):
        self.nombre, self.es_edit, self.ignorar, self.cont = nombre, es_edit, ignorar, cont
        self.sets: dict = {}
        self.hijos: list = []

    def secciones(self, nombre):
        return [h for h in self.hijos if not h.es_edit and h.nombre == nombre]

    def edits(self):
        return [h for h in self.hijos if h.es_edit]

    def uno(self, clave, defecto=""):
        v = self.sets.get(clave)
        return v[0] if v else defecto


def _arbol(texto: str):
    """(raiz, lineas sueltas fuera de todo bloque). Tolera prompts, bloques sin cerrar y lineas desconocidas."""
    raiz = _N("", False, False, True)
    pila = [raiz]
    sueltas = []
    for ln in _limpiar(texto):
        m = _RE_PROMPT.match(ln)
        if m:
            ln = m[1]
        t = _tokens(ln)
        if not t:
            continue
        c = t[0].lower()
        top = pila[-1]
        if c == "config" and len(t) > 1:
            nombre = " ".join(t[1:]).lower()
            if top.cont:
                ign = nombre not in _LEER and nombre not in _ENVOLTORIOS
                cont = nombre in _ENVOLTORIOS
            else:
                ign, cont = True, False
            n = _N(nombre, False, ign or top.ignorar, cont)
            top.hijos.append(n)
            pila.append(n)
        elif c == "edit" and len(t) > 1 and not top.es_edit and len(pila) > 1:
            n = _N(t[1], True, top.ignorar, top.cont)
            top.hijos.append(n)
            pila.append(n)
        elif c == "next":
            while len(pila) > 1 and not pila[-1].es_edit:
                pila.pop()
            if len(pila) > 1:
                pila.pop()
        elif c == "end":
            while len(pila) > 1 and pila[-1].es_edit:
                pila.pop()
            if len(pila) > 1:
                pila.pop()
        elif c == "set" and len(t) > 2:
            if len(pila) > 1 and not top.ignorar and not _SECRETO.search(t[1]):
                top.sets[t[1].lower()] = t[2:]
        elif c in ("set", "unset"):
            pass
        else:
            sueltas.append(ln)
    return raiz, sueltas


# ---------------------------------------------------------------- redes y servicios

def _red(txt: str):
    try:
        return ipaddress.IPv4Network(txt, strict=False)
    except ValueError:
        return None


def _red_ip_mascara(vals):
    if not vals:
        return None
    if len(vals) == 1:
        return _red(vals[0])
    return _red(vals[0] + "/" + vals[1])


def _rango(txt: str):
    """'443', '8080-8090' -> (ini, fin) o None."""
    a, _, b = txt.partition("-")
    if a.isdigit() and (b.isdigit() or not b):
        ini, fin = int(a), int(b or a)
        if 0 <= ini <= fin <= 65535:
            return ini, fin
    return None


def _unir(rangos) -> tuple:
    out = []
    for a, b in sorted(set(rangos)):
        if out and a <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return tuple(out)


class _Ctx:
    """Resolucion de direcciones y servicios de un VDOM."""

    def __init__(self, nodos, interfaces, avisos):
        self.avisos = avisos
        self.interfaces = interfaces
        self.dir: dict = {}
        self.grp: dict = {}
        self.svc: dict = {}
        self.sgrp: dict = {}
        self.vips: set = set()
        self.ciclos: set = set()
        for sec, destino in (("firewall address", self.dir), ("firewall addrgrp", self.grp),
                             ("firewall service custom", self.svc), ("firewall service group", self.sgrp)):
            for n in nodos(sec):
                for e in n.edits():
                    destino.setdefault(e.nombre, e)
        for n in nodos("firewall vip"):
            self.vips.update(e.nombre for e in n.edits())
        self._memo_d: dict = {}
        self._memo_s: dict = {}

    def avisar(self, txt):
        if txt not in self.avisos:
            self.avisos.append(txt)

    # direcciones -> (redes, sin_resolver)
    def direccion(self, nombre, en_curso=()):
        if nombre in self._memo_d:
            return self._memo_d[nombre]
        if nombre in en_curso:
            self.ciclos.add(nombre)
            return [], []
        if nombre.lower() == "all" and nombre not in self.dir:
            res = ([_ANY], [])
        elif nombre.lower() == "none" and nombre not in self.dir:
            res = ([], [])
        elif nombre in self.grp:
            redes, malos = [], []
            for m in self.grp[nombre].sets.get("member", []):
                r, b = self.direccion(m, tuple(en_curso) + (nombre,))
                redes += r
                malos += b
            if self.grp[nombre].uno("exclude", "disable") == "enable":
                malos.append("grupo con exclude no modelado: " + nombre)
            res = (list(dict.fromkeys(redes)), list(dict.fromkeys(malos)))
        elif nombre in self.dir:
            res = self._objeto(self.dir[nombre])
        elif nombre in self.vips:
            res = ([], ["vip (NAT no modelado): " + nombre])
        else:
            res = ([], ["direccion no definida: " + nombre])
        self._memo_d[nombre] = res
        return res

    def _objeto(self, e):
        tipo = e.uno("type", "ipmask").lower()
        n = e.nombre
        if tipo == "ipmask":
            r = _red_ip_mascara(e.sets.get("subnet"))
            return ([r], []) if r is not None else ([], ["direccion sin subnet valida: " + n])
        if tipo == "iprange":
            try:
                a = ipaddress.IPv4Address(e.uno("start-ip"))
                b = ipaddress.IPv4Address(e.uno("end-ip"))
                return list(ipaddress.summarize_address_range(a, b)), []
            except ValueError:
                return [], ["rango de IP no valido: " + n]
        if tipo == "interface-subnet":
            i = self.interfaces.get(e.uno("interface").lower())
            if i is not None and i.ip and i.mascara:
                return [_red(i.ip + "/" + i.mascara)], []
            return [], ["interface-subnet sin interfaz con IP: " + n]
        if tipo in ("fqdn", "wildcard-fqdn"):
            return [], ["fqdn: " + n]
        if tipo == "geography":
            return [], ["geography: " + n]
        return [], [tipo + " no soportado: " + n]

    # servicios -> ([(protocolo, dports, sports)], sin_resolver)
    def servicio(self, nombre, en_curso=()):
        if nombre in self._memo_s:
            return self._memo_s[nombre]
        if nombre in en_curso:
            self.ciclos.add(nombre)
            return [], []
        if nombre in self.sgrp:
            ents, malos = [], []
            for m in self.sgrp[nombre].sets.get("member", []):
                e, b = self.servicio(m, tuple(en_curso) + (nombre,))
                ents += e
                malos += b
            res = (ents, malos)
        elif nombre in self.svc:
            res = self._custom(self.svc[nombre])
        elif nombre.upper() in PREDEFINIDOS:
            res = ([(p, tuple(d), ()) for p, d in PREDEFINIDOS[nombre.upper()]], [])
        else:
            res = ([], ["puerto no resuelto: servicio " + nombre])
            self.avisar("servicio no definido ni predefinido conocido: " + nombre)
        self._memo_s[nombre] = res
        return res

    def _custom(self, e):
        proto = e.uno("protocol", "TCP/UDP/SCTP").upper()
        ents, malos = [], []
        if proto == "ICMP":
            return [("icmp", (), ())], []
        if proto == "IP":
            num = e.uno("protocol-number", "0")
            if not num.isdigit():
                return [], ["protocolo IP no valido: " + e.nombre]
            n = int(num)
            return [("all" if n == 0 else _PROTO_NUM.get(n, "ip" + num), (), ())], []
        if proto not in ("TCP/UDP/SCTP", "TCP/UDP"):
            return [], ["protocolo no soportado (" + proto + "): " + e.nombre]
        for clave, p in (("tcp-portrange", "tcp"), ("udp-portrange", "udp"), ("sctp-portrange", "sctp")):
            for tok in e.sets.get(clave, []):
                dst, _, src = tok.partition(":")
                d, s = _rango(dst), (_rango(src) if src else None)
                if d is None or (src and s is None):
                    malos.append("puerto no resuelto: " + tok)
                    continue
                ents.append((p, (d,), (s,) if s else ()))
        return ents, malos


# ---------------------------------------------------------------- construccion del firewall

def _interfaces(nodos, vdom, multi, zonas) -> dict:
    por: dict = {}
    for n in nodos("system interface"):
        for e in n.edits():
            if multi and e.uno("vdom", "root") != vdom:
                continue
            ip, mask = "", ""
            vals = e.sets.get("ip", [])
            if vals:
                r = _red_ip_mascara(vals)
                if r is not None and int(r.network_address) != 0:
                    ip = vals[0].partition("/")[0]
                    mask = str(r.netmask)
            por[e.nombre.lower()] = Interfaz(e.nombre, e.nombre, ip, mask, None,
                                             zonas.get(e.nombre.lower(), e.nombre))
    return por


def _rutas_conectadas(interfaces) -> list:
    out = []
    for i in interfaces.values():
        if i.ip and i.mascara:
            r = _red(i.ip + "/" + i.mascara)
            if r is not None:
                out.append(Ruta(r, i.nombre, "", "conectada", "C"))
    return out


def _rutas_tabla(sueltas, nombres) -> list:
    """Rutas de `get router info routing-table all`; nombres = interfaces del VDOM (None = todas)."""
    out, ultima = [], None
    for ln in sueltas:
        m = _RE_RUTA.match(ln)
        if m:
            ultima = _red(m["red"])
            cod, resto = m["cod"].strip(), m["resto"]
        else:
            mc = _RE_CONT.match(ln)
            if not mc or ultima is None:
                continue
            cod, resto = "", ln
        if ultima is None:
            continue
        ifc = re.search(r"connected,\s*([^\s,)]+)", resto) or re.search(r"via\s+\S+?,\s*([^\s,)]+)", resto)
        if not ifc:
            continue
        iface = ifc[1]
        if nombres is not None and iface.lower() not in nombres:
            continue
        ad = _RE_AD.search(resto)
        via = _RE_VIA.search(resto)
        if "directly connected" in resto and not via:
            tipo = "conectada" if (cod or "C").startswith("C") else "local"
            out.append(Ruta(ultima, iface, "", tipo, cod or "C"))
            continue
        if not cod:
            cod = "S"
        tipo = ("defecto" if ultima.prefixlen == 0 else "estatica") if cod.startswith("S") else "dinamica"
        out.append(Ruta(ultima, iface, via[1] if via else "", tipo, cod,
                        int(ad[1]) if ad else None, int(ad[2]) if ad else None))
    return out


def _rutas_estaticas(nodos, interfaces, conectadas, avisos) -> list:
    out = []
    for n in nodos("router static"):
        for e in n.edits():
            if e.uno("status", "enable") == "disable":
                continue
            red = _red_ip_mascara(e.sets.get("dst")) if e.sets.get("dst") else _ANY
            if red is None:
                avisos.append("ruta estatica " + e.nombre + ": dst no valido, omitida")
                continue
            if "dstaddr" in e.sets:
                avisos.append("ruta estatica " + e.nombre + ": dstaddr no interpretada, omitida")
                continue
            gw = e.uno("gateway")
            ad = e.uno("distance")
            dist = int(ad) if ad.isdigit() else 10
            if e.uno("blackhole", "disable") == "enable":
                avisos.append("ruta blackhole hacia " + str(red) + " (cuenta como interfaz '" + BLACKHOLE + "')")
                out.append(Ruta(red, BLACKHOLE, "", "defecto" if red.prefixlen == 0 else "estatica", "S", dist))
                continue
            dev = e.uno("device")
            if not dev and gw:
                try:
                    g = ipaddress.IPv4Address(gw)
                except ValueError:
                    g = None
                for c in conectadas:
                    if g is not None and g in c.red:
                        dev = c.interfaz
                        break
            if not dev:
                avisos.append("ruta estatica " + e.nombre + ": sin device ni interfaz conectada al gateway, omitida")
                continue
            if dev.lower() in interfaces:
                dev = interfaces[dev.lower()].nombre
            out.append(Ruta(red, dev, gw if gw and gw != _SIN_SALTO else "",
                            "defecto" if red.prefixlen == 0 else "estatica",
                            "S*" if red.prefixlen == 0 else "S", dist))
    return out


def _unicas(rutas) -> list:
    vistos, out = set(), []
    for r in rutas:
        k = (r.red, r.interfaz, r.salto)
        if k not in vistos:
            vistos.add(k)
            out.append(r)
    return out


def _subreglas(ents, orig, dest, zo, zd, linea) -> list:
    """Una subregla por (protocolo, puertos de origen); los puertos de destino se unen dentro de cada una."""
    grupos: dict = {}
    for proto, dports, sports in ents:
        k = (proto, sports)
        if k in grupos and grupos[k] is None:
            continue
        if not dports:
            grupos[k] = None            # todos los puertos
        else:
            grupos.setdefault(k, []).extend(dports)
    subs = []
    for (proto, sports), d in sorted(grupos.items(), key=lambda x: (x[0][0], x[0][1])):
        subs.append(Subregla([] if proto == "all" else [proto], list(orig), list(dest),
                             list(sports), list(_unir(d)) if d else [], list(zo), list(zd), linea))
    return subs


def _politicas(nodos, ctx, interfaces, zonas, avisos) -> list:
    miembros = {z.lower(): m for z, m in zonas.items()}
    reglas = []
    for n in nodos("firewall policy"):
        for e in n.edits():
            malos: list = []

            def lado(clave, malos=malos, e=e):
                vals = e.sets.get(clave, [])
                if not vals or any(v.lower() == "any" for v in vals):
                    return []
                out = []
                for v in vals:
                    if v.lower() in miembros:
                        out += miembros[v.lower()]
                    elif v.lower() in interfaces:
                        out.append(interfaces[v.lower()].nombre)
                    else:
                        out.append(v)
                        malos.append("interfaz o zona no definida: " + v)
                return list(dict.fromkeys(out))

            def redes(clave, malos=malos, e=e):
                nombres = e.sets.get(clave, [])
                if not nombres:
                    malos.append(clave + " vacio")
                    return []
                if e.uno(clave + "-negate", "disable") == "enable":
                    malos.append(clave + "-negate no modelado")
                    return []
                rs, ms = [], []
                for v in nombres:
                    r, m = ctx.direccion(v)
                    rs += r
                    ms += m
                malos.extend(ms)
                return list(dict.fromkeys(rs))

            zo, zd = lado("srcintf"), lado("dstintf")
            orig, dest = redes("srcaddr"), redes("dstaddr")
            if e.uno("internet-service", "disable") == "enable":
                malos.append("internet-service no modelado")
            ents = []
            svc = e.sets.get("service", [])
            if not svc:
                malos.append("service vacio")
            for s in svc:
                es, ms = ctx.servicio(s)
                ents += es
                malos.extend(ms)
            horario = e.uno("schedule", "always")
            if horario.lower() != "always":
                malos.append("horario no evaluado: " + horario)
            accion = e.uno("action", "deny").lower()
            if accion == "accept":
                acc = "permitir"
            elif accion == "deny":
                acc = "bloquear"
            else:
                acc = "permitir"
                malos.append("accion " + accion + " tratada como permitir")
            linea = "policy " + e.nombre
            subs = _subreglas(ents, orig, dest, zo, zd, linea)
            if not subs:
                subs = [Subregla(["no_resuelto"], orig, dest, [], [], zo, zd, linea)]
            todos = any(not s.protocolos for s in subs)
            protos = [] if todos else list(dict.fromkeys(p for s in subs for p in s.protocolos))
            puertos = []
            if not todos and all(s.puertos_destino or s.protocolos[0] in ("icmp", "no_resuelto") for s in subs):
                puertos = list(_unir([p for s in subs for p in s.puertos_destino]))
            reglas.append(Regla(
                e.nombre, e.uno("name"), "", "", acc, protos, orig, dest, puertos, zo, zd,
                e.uno("logtraffic", "utm") != "disable", e.uno("status", "enable") != "disable",
                0, "", "", [linea], ACL, list(dict.fromkeys(malos)), subs))
    reglas.append(Regla("implicit-deny", "Implicit deny", "", "", "bloquear", [], [_ANY], [_ANY], [], [], [],
                        False, True, 0, "", "", ["implicit deny"], ACL, [],
                        [Subregla([], [_ANY], [_ANY], [], [], [], [], "implicit deny")]))
    return reglas


def _zonas(nodos) -> dict:
    zonas = {}
    for n in nodos("system zone"):
        for e in n.edits():
            zonas[e.nombre] = list(e.sets.get("interface", []))
    return zonas


def _construir(nombre_host, nodos, vdom, multi, sueltas) -> Firewall:
    avisos: list = []
    zonas = _zonas(nodos)
    por_ifc = {m.lower(): z for z, ms in zonas.items() for m in ms}
    interfaces = _interfaces(nodos, vdom, multi, por_ifc)
    ctx = _Ctx(nodos, interfaces, avisos)
    conectadas = _rutas_conectadas(interfaces)
    tabla = _rutas_tabla(sueltas, set(interfaces) if multi else None)
    if not tabla:
        avisos.append("sin get router info routing-table all: solo rutas conectadas y estaticas de la configuracion")
    rutas = _unicas(tabla + conectadas + _rutas_estaticas(nodos, interfaces, conectadas, avisos))
    if not interfaces:
        avisos.append("sin config system interface: no hay interfaces")
    reglas = _politicas(nodos, ctx, interfaces, zonas, avisos)
    if len(reglas) == 1:
        avisos.append("sin config firewall policy: solo la denegacion implicita")
    if ctx.vips:
        avisos.append(f"{len(ctx.vips)} objeto(s) firewall vip: NAT/VIP no modelado")
    if ctx.ciclos:
        avisos.append("grupos con referencia circular (se cortan): " + ", ".join(sorted(ctx.ciclos)))
    avisos.append("sin contadores de aciertos (CSV de politicas de la GUI con --firewall-contadores)")
    fw = Firewall(FABRICANTE, nombre_host, list(interfaces.values()), rutas, [], reglas, [], avisos)
    return fw


def analizar_texto(texto: str) -> list:
    """Texto de FortiOS -> [Firewall] (uno por VDOM con configuracion; uno solo sin VDOMs)."""
    raiz, sueltas = _arbol(texto)
    globales = []
    for n in raiz.hijos:
        if n.nombre == "global":
            globales += n.hijos
        elif n.nombre != "vdom":
            globales.append(n)
    host = ""
    for n in globales:
        if n.nombre == "system global":
            host = n.uno("hostname") or host
    if not host:
        for ln in _limpiar(texto):
            m = re.match(r"^([\w.\-]+)(?:\s+\([^)]*\))?\s+[#$]\s", ln)
            if m:
                host = m[1]
                break
    vdoms: dict = {}
    for n in raiz.hijos:
        if n.nombre == "vdom":
            for e in n.edits():
                vdoms.setdefault(e.nombre, []).extend(c for c in e.hijos if not c.es_edit and not c.ignorar)
    vdoms = {k: v for k, v in vdoms.items() if v}
    if not vdoms:
        return [_construir(host, lambda s: [n for n in globales if n.nombre == s], "root", False, sueltas)]
    out = []
    for v, hijos in vdoms.items():
        def nodos(s, hijos=hijos):
            return [n for n in hijos + globales if n.nombre == s]
        out.append(_construir((host + ":" + v) if host else v, nodos, v, True, sueltas))
    return out


# ---------------------------------------------------------------- entrada y contadores

def _archivos(ruta) -> list:
    p = Path(ruta)
    if p.is_dir():
        return sorted(f for f in p.iterdir() if f.is_file() and not f.name.startswith("."))
    return [p] if p.is_file() else []


def detectar(ruta):
    """Texto del archivo (o carpeta) si es de una FortiGate; None si no lo parece."""
    try:
        texto = "\n".join(f.read_text(encoding="utf-8", errors="replace") for f in _archivos(ruta))
    except OSError:
        return None
    if _RE_MARCA_CFG.search(texto):
        return texto
    if _RE_MARCA_RUTAS.search(texto) and not re.search(r"^\s*(?:\S+[#>]\s*)?access-list\s", texto, re.MULTILINE):
        return texto
    return None


def cargar(ruta) -> list:
    texto = detectar(ruta)
    if texto is None:
        raise SystemExit(f"[!] '{ruta}' no parece configuracion de FortiGate")
    return analizar_texto(texto)


_COL_ID = ("id", "policy id", "policyid", "policy_id")
_COL_NOMBRE = ("name", "policy name", "policy")
_COL_HITS = ("hit count", "hits", "hitcount", "hit_count")


def aplicar_contadores(fws, ruta) -> None:
    """Asocia 'Hit Count' del CSV de politicas de la GUI a las reglas (por id o nombre). Bytes no se usa."""
    p = Path(ruta)
    if not p.is_file():
        raise SystemExit(f"[!] no existe '{ruta}'")
    texto = p.read_text(encoding="utf-8-sig", errors="replace")
    try:
        dial = csv.Sniffer().sniff(texto[:2000], delimiters=",;\t")
    except csv.Error:
        dial = csv.excel
    filas = list(csv.DictReader(texto.splitlines(), dialect=dial))
    cab = {(k or "").strip().lower(): k for k in (filas[0] if filas else {})}
    kid = next((cab[c] for c in _COL_ID if c in cab), None)
    kn = next((cab[c] for c in _COL_NOMBRE if c in cab), None)
    kh = next((cab[c] for c in _COL_HITS if c in cab), None)
    if kh is None or (kid is None and kn is None):
        for fw in fws:
            fw.avisos.append("CSV de contadores sin columnas ID/Name y Hit Count: no se usa")
        return
    hits = {}
    for f in filas:
        v = re.sub(r"[,\s]", "", (f.get(kh) or ""))
        if not v.isdigit():
            continue
        for k in (kid, kn):
            if k and (f.get(k) or "").strip():
                hits.setdefault((f[k].strip().lower()), int(v))
    for fw in fws:
        fw.avisos[:] = [a for a in fw.avisos if not a.startswith("sin contadores de aciertos")]
        usados = 0
        for r in fw.reglas:
            h = hits.get(r.id.lower())
            if h is None and r.nombre:
                h = hits.get(r.nombre.lower())
            if h is not None:
                r.aciertos = h
                usados += 1
        if not usados:
            fw.avisos.append("CSV de contadores: ninguna politica coincide por ID ni nombre")
