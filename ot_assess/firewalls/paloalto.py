"""Adaptador de la configuracion de un firewall Palo Alto (PAN-OS 9.x-11.x) al modelo comun de firewall (F3).

Entrada: configuracion en formato `set` (`set cli config-output-format set` + `show config running`, o
`configure` + `show`) o en XML (`show config running` en XML, o el archivo exportado de la GUI); en el mismo
archivo o carpeta pueden venir `show routing route` y `show rule-hit-count ...`. Cada vsys es un Firewall.
Los dos formatos se llevan a un mismo arbol de claves (cada palabra de la ruta es una clave; los valores son
las claves del ultimo nodo), de modo que `set` y XML equivalentes dan el mismo modelo.
SEGURIDAD: solo se leen deviceconfig system hostname, network interface/virtual-router, zone, address,
address-group, service, service-group, rulebase security e import network interface. Todo lo demas
(mgt-config con usuarios y phash, certificados, VPN, perfiles...) se descarta sin copiarse y, dentro de lo
leido, se corta cualquier ruta en una palabra de secreto (phash, password, pre-shared-key, private-key...).
XML: se rechaza un archivo con DOCTYPE o ENTITY (sin expansion de entidades) y se limita el tamano.
NO validado con una muestra real: sintaxis publica de PAN-OS; lo no interpretado queda como aviso.
"""
from __future__ import annotations

import ipaddress
import re
import shlex
import xml.etree.ElementTree as ET  # nosec B405  (se rechaza DOCTYPE/ENTITY antes de analizar; ver _xml_a_rutas)
from pathlib import Path

from . import fortigate as _fg
from .modelo import Firewall, Interfaz, Regla, Ruta, Subregla

FABRICANTE = "Palo Alto PAN-OS"
ACL = "panos-security"
MAX_XML = 100 * 1024 * 1024
BLACKHOLE = "blackhole"
APP_ID = ("app-id: application-default (puertos por defecto de la aplicacion) no se resuelve sin App-ID; "
          "se trata como cualquier puerto y el contraste puede ser mas amplio que la realidad")
_ANY = ipaddress.IPv4Network("0.0.0.0/0")
_COMPARTIDO = "*"

# Servicios predefinidos de PAN-OS (de memoria, NO validados): (protocolo, puertos de destino).
PREDEFINIDOS = {
    "service-http": [("tcp", ((80, 80), (8080, 8080)))],
    "service-https": [("tcp", ((443, 443),))],
}
_OBJETOS = ("zone", "address", "address-group", "service", "service-group")
_SECRETOS = frozenset((
    "phash", "password", "passwd", "pre-shared-key", "secret", "private-key", "privatekey", "api-key",
    "authentication-profile", "certificate", "passphrase", "key", "community", "auth-password", "priv-password"))
_TOP_XML = ("network", "deviceconfig", "vsys", "shared")
_RE_PROMPT = re.compile(r"^\s*\S+@\S+[#>]\s*")
_RE_MARCA_SET = re.compile(r"^\s*(?:\S+@\S+[#>]\s*)?set\s+(?:(?:vsys|shared)\s+(?:\S+\s+)?)?"
                           r"(?:rulebase\s+security|network\s+virtual-router)\b", re.MULTILINE)
_RE_MARCA_XML = re.compile(r"<rulebase>|<devices>")
_RE_PELIGRO_XML = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)", re.IGNORECASE)
_RE_BANDERA = re.compile(r"^[A-Za-z?~][A-Za-z0-9]?$")
_RE_IFC = re.compile(r"^(?:ethernet|ae|tunnel|loopback|vlan)\S*$", re.IGNORECASE)
_RE_FECHA = re.compile(r"\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}")


# ---------------------------------------------------------------- arbol de claves

def _tokens(linea: str) -> list:
    try:
        t = shlex.split(linea)
    except ValueError:
        t = linea.split()
    return t


def _clasificar(ruta):
    """(clave de vsys | None si es global, ruta relativa) de una ruta completa."""
    a = ruta[0]
    if a == "vsys" and len(ruta) > 2:
        return ruta[1], ruta[2:]
    if a == "shared":
        return _COMPARTIDO, ruta[1:]
    if a in ("network", "deviceconfig"):
        return None, ruta
    return "", ruta


def _permitido(glob: bool, rel) -> bool:
    if not rel:
        return False
    if glob:
        return ((rel[0] == "network" and len(rel) > 1 and rel[1] in ("interface", "virtual-router"))
                or tuple(rel[:3]) == ("deviceconfig", "system", "hostname"))
    return (rel[0] in _OBJETOS or (rel[0] == "rulebase" and tuple(rel[1:2]) == ("security",))
            or tuple(rel[:3]) == ("import", "network", "interface"))


class _Cfg:
    """Arboles de claves: global (network, deviceconfig), uno por vsys y el compartido."""

    def __init__(self):
        self.g: dict = {}
        self.v: dict = {}

    def insertar(self, ruta) -> None:
        ruta = [x for x in ruta if x != ""]
        if not ruta:
            return
        v, rel = _clasificar(ruta)
        for i, tok in enumerate(rel):
            if tok.lower() in _SECRETOS:
                rel = rel[:i]
                break
        if not _permitido(v is None, rel):
            return
        nodo = self.g if v is None else self.v.setdefault(v, {})
        for tok in rel:
            nodo = nodo.setdefault(tok, {})


_CLAVES_REGLA = frozenset((
    "from", "to", "source", "destination", "service", "application", "action", "disabled", "negate-source",
    "negate-destination", "source-user", "description", "log-start", "log-end", "category", "source-hip",
    "destination-hip", "profile-setting", "rule-type", "tag", "group-tag", "schedule", "log-setting"))
_CLAVES_RUTA = frozenset(("destination", "nexthop", "interface", "metric", "admin-dist", "bfd", "path-monitor"))


def _trocear(resto, claves) -> list:
    """Divide una linea `set` que trae varios campos (`destination A nexthop ip-address X interface i`)."""
    trozos, cur, prof = [], [], 0
    for tok in resto:
        if tok == "[":
            prof = 1
        elif tok == "]":
            prof = 0
        elif prof == 0 and tok in claves and cur:
            trozos.append(cur)
            cur = []
        cur.append(tok)
    return trozos + [cur] if cur else trozos


def _expandir(t) -> list:
    """Linea `set` (sin la palabra set) -> rutas del arbol: separa campos y abre las listas `[ a b ]`."""
    off = 2 if t[0] == "vsys" and len(t) > 2 else (1 if t[0] == "shared" else 0)
    rel = t[off:]
    n, claves = 0, None
    if tuple(rel[:3]) == ("rulebase", "security", "rules") and len(rel) > 4:
        n, claves = 4, _CLAVES_REGLA
    elif (tuple(rel[:2]) == ("network", "virtual-router") and tuple(rel[3:6]) == ("routing-table", "ip", "static-route")
          and len(rel) > 7):
        n, claves = 7, _CLAVES_RUTA
    trozos = [t]
    if claves is not None:
        cab = t[:off + n]
        trozos = [cab + c for c in _trocear(t[off + n:], claves)]
    out = []
    for c in trozos:
        if "[" in c:       # lista: cada elemento es un valor hermano, no un nivel mas
            i = c.index("[")
            items = [x for x in c[i + 1:] if x != "]"]
            out += [c[:i] + [x] for x in items] or [c[:i]]
        else:
            out.append(c)
    return out


def _desde_set(texto: str, cfg: _Cfg) -> list:
    """Carga las lineas `set` en cfg y devuelve el resto (salida de show routing route, contadores...)."""
    sueltas = []
    for ln in texto.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        ln = _RE_PROMPT.sub("", ln).rstrip()
        t = _tokens(ln)
        if t and t[0].lower() == "set" and len(t) > 1:
            for ruta in _expandir(t[1:]):
                cfg.insertar(ruta)
        elif ln.strip():
            sueltas.append(ln)
    return sueltas


def _xml_a_rutas(texto: str, cfg: _Cfg) -> str:
    """Carga el XML en cfg y devuelve el texto que quedaba fuera del documento."""
    if _RE_PELIGRO_XML.search(texto):
        raise SystemExit("[!] XML de PAN-OS rechazado: contiene DOCTYPE o ENTITY (no se analiza)")
    ini = texto.find("<config")
    fin = texto.find("</config>", ini)
    if ini < 0 or fin < 0:
        raise SystemExit("[!] XML de PAN-OS sin elemento <config> completo")
    resto = texto[:ini] + "\n" + texto[fin + len("</config>"):]
    try:
        # DOCTYPE y ENTITY ya se rechazaron arriba: sin entidades definidas no hay expansion ni acceso externo.
        raiz = ET.fromstring(texto[ini:fin + len("</config>")])  # nosec B314
    except ET.ParseError as e:
        raise SystemExit("[!] XML de PAN-OS mal formado: " + str(e))

    def hojas(el, ruta, nivel):
        for h in el:
            tag = h.tag
            if tag.lower() in _SECRETOS or (nivel == 0 and tag not in _TOP_XML):
                continue
            if tag == "entry":
                tok = h.get("name") or ""
            elif tag == "member":
                tok = (h.text or "").strip()
            else:
                tok = tag
            nueva = ruta + [tok]
            if len(h):
                hojas(h, nueva, nivel + 1)
            else:
                if tag not in ("entry", "member") and (h.text or "").strip():
                    nueva = nueva + [h.text.strip()]
                cfg.insertar(nueva)

    devices = raiz.find("devices")
    if devices is not None:
        for e in devices.findall("entry"):
            hojas(e, [], 0)
    comp = raiz.find("shared")
    if comp is not None:
        hojas(comp, ["shared"], 1)
    return resto


# ---------------------------------------------------------------- navegacion del arbol

def _h(nodo, *ruta) -> dict:
    for k in ruta:
        nodo = nodo.get(k)
        if nodo is None:
            return {}
    return nodo


def _vals(nodo, *ruta) -> list:
    return list(_h(nodo, *ruta).keys())


def _uno(nodo, *ruta, defecto="") -> str:
    v = _vals(nodo, *ruta)
    return v[0] if v else defecto


def _puertos(txt_lista) -> tuple:
    """['443,8080-8090'] -> ((rangos), [malos])."""
    out, malos = [], []
    for txt in txt_lista:
        for p in txt.split(","):
            p = p.strip()
            if not p:
                continue
            r = _fg._rango(p)
            if r is None:
                malos.append("puerto no resuelto: " + p)
            else:
                out.append(r)
    return out, malos


class _Ctx:
    """Resolucion de direcciones y servicios de un vsys (con los objetos compartidos)."""

    def __init__(self, arboles, avisos):
        self.avisos = avisos
        self.dir: dict = {}
        self.grp: dict = {}
        self.svc: dict = {}
        self.sgrp: dict = {}
        self.ciclos: set = set()
        for sec, destino in (("address", self.dir), ("address-group", self.grp), ("service", self.svc),
                             ("service-group", self.sgrp)):
            for a in arboles:
                for nombre, nodo in _h(a, sec).items():
                    destino.setdefault(nombre, nodo)
        self._md: dict = {}
        self._ms: dict = {}

    def avisar(self, txt):
        if txt not in self.avisos:
            self.avisos.append(txt)

    def ip_cruda(self, nombre) -> str:
        """Texto ip/mascara de un objeto address ip-netmask ('' si no lo es)."""
        n = self.dir.get(nombre)
        return _uno(n, "ip-netmask") if n else ""

    def direccion(self, nombre, en_curso=()):
        if nombre in self._md:
            return self._md[nombre]
        if nombre in en_curso:
            self.ciclos.add(nombre)
            return [], []
        if nombre in self.grp:
            g = self.grp[nombre]
            redes, malos = [], []
            if "dynamic" in g:
                malos.append("address-group dinamico no se resuelve: " + nombre)
            for m in _vals(g, "static"):
                r, b = self.direccion(m, tuple(en_curso) + (nombre,))
                redes += r
                malos += b
            res = (list(dict.fromkeys(redes)), list(dict.fromkeys(malos)))
        elif nombre in self.dir:
            res = self._objeto(nombre, self.dir[nombre])
        elif nombre.lower() == "any":
            res = ([_ANY], [])
        elif re.match(r"^\d+\.\d+\.\d+\.\d+(?:/\d+)?$", nombre) and _fg._red(nombre) is not None:
            res = ([_fg._red(nombre)], [])
        else:
            res = ([], ["direccion no definida: " + nombre])
        self._md[nombre] = res
        return res

    def _objeto(self, nombre, n):
        if "ip-netmask" in n:
            r = _fg._red(_uno(n, "ip-netmask"))
            return ([r], []) if r is not None else ([], ["ip-netmask no valido: " + nombre])
        if "ip-range" in n:
            a, _, b = _uno(n, "ip-range").partition("-")
            try:
                return list(ipaddress.summarize_address_range(
                    ipaddress.IPv4Address(a.strip()), ipaddress.IPv4Address(b.strip()))), []
            except ValueError:
                return [], ["rango de IP no valido: " + nombre]
        if "fqdn" in n:
            return [], ["fqdn: " + nombre]
        if "ip-wildcard" in n:
            return [], ["ip-wildcard no soportado: " + nombre]
        return [], ["tipo de direccion no soportado: " + nombre]

    # servicios -> ([(protocolo, dports, sports)], malos, app_default)
    def servicio(self, nombre, en_curso=()):
        if nombre in self._ms:
            return self._ms[nombre]
        if nombre in en_curso:
            self.ciclos.add(nombre)
            return [], [], False
        if nombre in self.sgrp:
            ents, malos, app = [], [], False
            for m in _vals(self.sgrp[nombre], "members"):
                e, b, a = self.servicio(m, tuple(en_curso) + (nombre,))
                ents += e
                malos += b
                app = app or a
            res = (ents, malos, app)
        elif nombre in self.svc:
            res = self._custom(nombre, self.svc[nombre])
        elif nombre == "application-default":
            res = ([("all", (), ())], [], True)
        elif nombre.lower() == "any":
            res = ([("all", (), ())], [], False)
        elif nombre in PREDEFINIDOS:
            res = ([(p, tuple(d), ()) for p, d in PREDEFINIDOS[nombre]], [], False)
        else:
            res = ([], ["puerto no resuelto: servicio " + nombre], False)
            self.avisar("servicio no definido ni predefinido conocido: " + nombre)
        self._ms[nombre] = res
        return res

    def _custom(self, nombre, n):
        ents, malos = [], []
        for proto in ("tcp", "udp", "sctp"):
            p = _h(n, "protocol", proto)
            if not p:
                continue
            d, m1 = _puertos(_vals(p, "port"))
            s, m2 = _puertos(_vals(p, "source-port"))
            malos += m1 + m2
            if not d and not m1:
                malos.append("servicio sin puerto: " + nombre)
            if m1:
                continue
            ents.append((proto, tuple(d), tuple(s)))
        if not ents and not malos:
            malos.append("protocolo no soportado: " + nombre)
        return ents, malos, False


# ---------------------------------------------------------------- interfaces, zonas y rutas

def _red_if(txt):
    r = _fg._red(txt)
    if r is None:
        return "", ""
    return txt.partition("/")[0], str(r.netmask)


def _interfaces(red, ctx, avisos) -> list:
    """Interfaces capa 3 (y subinterfaces) de network interface."""
    out = []

    def anadir(nombre, nodo):
        ips = _vals(nodo, "ip")
        if "dhcp-client" in nodo or "pppoe" in nodo:
            avisos.append("interfaz " + nombre + ": IP por dhcp/pppoe, sin IP conocida")
        ip, mask = "", ""
        for k, cand in enumerate(ips):
            txt = cand if "/" in cand or re.match(r"^\d+\.\d+\.\d+\.\d+$", cand) else ctx.ip_cruda(cand)
            a, m = _red_if(txt) if txt else ("", "")
            if not a:
                avisos.append("interfaz " + nombre + ": IP no resuelta: " + cand)
            elif not ip:
                ip, mask = a, m
            else:
                avisos.append("interfaz " + nombre + ": IP secundaria " + a + " (solo se modela la primera)")
        out.append(Interfaz(nombre, nombre, ip, mask))

    for tipo, nodo in red.items():
        if tipo in ("ethernet", "aggregate-ethernet"):
            for nombre, e in nodo.items():
                l3 = e.get("layer3")
                if l3 is None:
                    continue
                anadir(nombre, l3)
                for sub, s in _h(l3, "units").items():
                    anadir(sub, s)
        elif tipo in ("loopback", "tunnel", "vlan"):
            if "ip" in nodo:
                anadir(tipo, nodo)
            for sub, s in _h(nodo, "units").items():
                anadir(sub, s)
    return out


def _conectadas(interfaces) -> list:
    out = []
    for i in interfaces:
        if i.ip and i.mascara:
            r = _fg._red(i.ip + "/" + i.mascara)
            if r is not None:
                out.append(Ruta(r, i.nombre, "", "conectada", "C"))
    return out


def _estaticas(g, nombres, conectadas, multi, avisos) -> list:
    out = []
    vrs = _h(g, "network", "virtual-router")
    if len(vrs) > 1:
        avisos.append("varios virtual-router (" + ", ".join(vrs) + "): sus rutas se mezclan en una sola tabla")
    for vr, nodo in vrs.items():
        for n, e in _h(nodo, "routing-table", "ip", "static-route").items():
            dest = _fg._red(_uno(e, "destination"))
            if dest is None:
                avisos.append("ruta estatica " + n + " (" + vr + "): destination no valido, omitida")
                continue
            dist = _uno(e, "admin-dist", defecto="10")
            dist = int(dist) if dist.isdigit() else 10
            tipo = "defecto" if dest.prefixlen == 0 else "estatica"
            cod = "S*" if dest.prefixlen == 0 else "S"
            nh = _h(e, "nexthop")
            if "discard" in nh:
                if multi:
                    avisos.append("ruta discard " + n + " omitida (con varios vsys no se sabe de cual es)")
                else:
                    avisos.append("ruta discard hacia " + str(dest) + " (cuenta como interfaz '" + BLACKHOLE + "')")
                    out.append(Ruta(dest, BLACKHOLE, "", tipo, cod, dist))
                continue
            if "next-vr" in nh:
                avisos.append("ruta estatica " + n + ": next-vr no modelado, omitida")
                continue
            gw = _uno(nh, "ip-address")
            ifz = _uno(e, "interface")
            if not ifz and gw:
                try:
                    g_ip = ipaddress.IPv4Address(gw)
                except ValueError:
                    g_ip = None
                ifz = next((c.interfaz for c in conectadas if g_ip is not None and g_ip in c.red), "")
            if not ifz:
                avisos.append("ruta estatica " + n + ": sin interfaz ni red conectada al salto, omitida")
                continue
            if nombres is not None and ifz.lower() not in nombres:
                continue
            out.append(Ruta(dest, _nombre_real(ifz, conectadas), gw, tipo, cod, dist))
    return out


def _nombre_real(ifz, conectadas) -> str:
    for c in conectadas:
        if c.interfaz.lower() == ifz.lower():
            return c.interfaz
    return ifz


def _rutas_tabla(sueltas, nombres) -> list:
    """Rutas de `show routing route` (solo las activas, bandera A); nombres = interfaces del vsys o None."""
    out = []
    for ln in sueltas:
        t = ln.split()
        if len(t) < 4 or not re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", t[0]) or not t[2].isdigit():
            continue
        red = _fg._red(t[0])
        if red is None:
            continue
        i = 3
        banderas = []
        while i < len(t) and _RE_BANDERA.match(t[i]) and not _RE_IFC.match(t[i]):
            banderas.append(t[i])
            i += 1
        if "A" not in banderas:
            continue
        ifz = next((x for x in t[i:] if _RE_IFC.match(x)), "")
        salto = t[1] if re.match(r"^\d+\.\d+\.\d+\.\d+$", t[1]) and t[1] != "0.0.0.0" else ""  # nosec B104
        if not ifz:
            if t[1] == "discard":
                ifz = BLACKHOLE
            else:
                continue
        if nombres is not None and ifz.lower() not in nombres and ifz != BLACKHOLE:
            continue
        otras = [b for b in banderas if b != "A"]
        cod = " ".join(otras)
        if "C" in otras:
            out.append(Ruta(red, ifz, "", "conectada", "C"))
        elif "H" in otras:
            out.append(Ruta(red, ifz, "", "local", "L"))
        elif "S" in otras:
            out.append(Ruta(red, ifz, salto, "defecto" if red.prefixlen == 0 else "estatica",
                            "S*" if red.prefixlen == 0 else "S", None, int(t[2])))
        else:
            out.append(Ruta(red, ifz, salto, "dinamica", cod or "O", None, int(t[2])))
    return out


def _unicas(rutas) -> list:
    vistos, out = set(), []
    for r in rutas:
        k = (r.red, r.interfaz.lower(), r.salto)
        if k not in vistos:
            vistos.add(k)
            out.append(r)
    return out


# ---------------------------------------------------------------- reglas

def _subreglas(ents, orig, dest, zo, zd, linea) -> list:
    """Una subregla por (protocolo, puertos de origen); los puertos de destino se unen dentro de cada una."""
    grupos: dict = {}
    for proto, dports, sports in ents:
        k = (proto, tuple(sports))
        if k in grupos and grupos[k] is None:
            continue
        if not dports:
            grupos[k] = None
        else:
            grupos.setdefault(k, []).extend(dports)
    subs = []
    for (proto, sports), d in sorted(grupos.items(), key=lambda x: (x[0][0], x[0][1])):
        subs.append(Subregla([] if proto == "all" else [proto], list(orig), list(dest), list(sports),
                             list(_fg._unir(d)) if d else [], list(zo), list(zd), linea))
    return subs


def _reglas(arboles, ctx, zonas) -> tuple:
    miembros = {z.lower(): m for z, m in zonas.items()}
    reglas = []
    app_marcada = False
    nodo_reglas = {}
    for a in arboles:
        for n, r in _h(a, "rulebase", "security", "rules").items():
            nodo_reglas.setdefault(n, r)
    for nombre, e in nodo_reglas.items():
        malos: list = []

        def lado(clave, malos=malos, e=e):
            vals = _vals(e, clave)
            if not vals or any(v.lower() == "any" for v in vals):
                return []
            out = []
            for v in vals:
                if v.lower() in miembros:
                    out += miembros[v.lower()] or [v]
                else:
                    out.append(v)
                    malos.append("zona no definida: " + v)
            return list(dict.fromkeys(out))

        def redes(clave, neg, malos=malos, e=e):
            nombres = _vals(e, clave)
            if not nombres:
                malos.append(clave + " vacio")
                return []
            if _uno(e, neg, defecto="no") == "yes":
                malos.append(neg + " no modelado")
                return []
            rs = []
            for v in nombres:
                r, m = ctx.direccion(v)
                rs += r
                malos.extend(m)
            return list(dict.fromkeys(rs))

        zo, zd = lado("from"), lado("to")
        orig, dest = redes("source", "negate-source"), redes("destination", "negate-destination")
        usuarios = [u for u in _vals(e, "source-user") if u.lower() != "any"]
        if usuarios:
            malos.append("source-user no evaluado (el contraste puede ser mas amplio)")
        ents = []
        svc = _vals(e, "service")
        if not svc:
            malos.append("service vacio")
        app = False
        for s in svc:
            es, ms, a = ctx.servicio(s)
            ents += es
            malos.extend(ms)
            app = app or a
        if app:
            malos.append(APP_ID)
            app_marcada = True
        accion = _uno(e, "action", defecto="allow").lower()
        if not _vals(e, "action"):
            malos.append("sin action: se asume allow (valor por defecto de PAN-OS, no validado)")
        if accion == "allow":
            acc = "permitir"
        else:
            acc = "bloquear"
            if accion not in ("deny", "drop", "reset-client", "reset-server", "reset-both"):
                malos.append("accion " + accion + " tratada como bloquear")
        linea = "rule " + nombre
        subs = _subreglas(ents, orig, dest, zo, zd, linea)
        if not subs:
            subs = [Subregla(["no_resuelto"], orig, dest, [], [], zo, zd, linea)]
        todos = any(not s.protocolos for s in subs)
        protos = [] if todos else list(dict.fromkeys(p for s in subs for p in s.protocolos))
        puertos = []
        if not todos and all(s.puertos_destino or s.protocolos[0] in ("icmp", "no_resuelto") for s in subs):
            puertos = list(_fg._unir([p for s in subs for p in s.puertos_destino]))
        lineas = [linea]
        apps = [x for x in _vals(e, "application") if x.lower() != "any"]
        if apps:
            lineas.append("aplicaciones: " + ", ".join(apps))
        reglas.append(Regla(
            nombre, nombre, "", "", acc, protos, orig, dest, puertos, zo, zd,
            _uno(e, "log-end", defecto="yes") != "no", _uno(e, "disabled", defecto="no") != "yes",
            0, "", "", lineas, ACL, list(dict.fromkeys(malos)), subs))
    # reglas por defecto de PAN-OS: dentro de una zona se permite; entre zonas se deniega
    intra = [(z, m) for z, m in zonas.items() if m]
    if intra:
        todas = list(dict.fromkeys(i for _z, m in intra for i in m))
        reglas.append(Regla(
            "intrazone-default", "intrazone-default", "", "", "permitir", [], [_ANY], [_ANY], [], todas, todas,
            False, True, 0, "", "", ["intrazone-default"], ACL, [],
            [Subregla([], [_ANY], [_ANY], [], [], list(m), list(m), "intrazone-default") for _z, m in intra]))
    reglas.append(Regla(
        "interzone-default", "interzone-default", "", "", "bloquear", [], [_ANY], [_ANY], [], [], [],
        False, True, 0, "", "", ["interzone-default"], ACL, [],
        [Subregla([], [_ANY], [_ANY], [], [], [], [], "interzone-default")]))
    return reglas, app_marcada


# ---------------------------------------------------------------- construccion

def _construir(host, cfg, clave, multi, sueltas) -> Firewall:
    avisos: list = []
    g = cfg.g
    vs = cfg.v.get(clave, {})
    arboles = [vs, cfg.v.get(_COMPARTIDO, {})]
    ctx = _Ctx(arboles, avisos)
    zonas = {}
    for z, n in _h(vs, "zone").items():
        zonas[z] = _vals(n, "network", "layer3")
        otros = [k for k in _h(n, "network") if k != "layer3"]
        if otros:
            avisos.append("zona " + z + ": tipo " + "/".join(otros) + " no modelado (solo layer3)")
    por_ifc = {m.lower(): z for z, ms in zonas.items() for m in ms}
    todas = _interfaces(_h(g, "network", "interface"), ctx, avisos)
    if multi:
        propias = set(por_ifc) | {i.lower() for i in _vals(vs, "import", "network", "interface")}
        todas = [i for i in todas if i.nombre.lower() in propias]
    for i in todas:
        i.zona = por_ifc.get(i.nombre.lower(), "")
    nombres = {i.nombre.lower() for i in todas} if multi else None
    conectadas = _conectadas(todas)
    tabla = _rutas_tabla(sueltas, nombres)
    if not tabla:
        avisos.append("sin show routing route: solo rutas conectadas y estaticas de la configuracion")
    rutas = _unicas(tabla + conectadas + _estaticas(g, nombres, conectadas, multi, avisos))
    if not todas:
        avisos.append("sin interfaces capa 3 en network interface")
    reglas, app = _reglas(arboles, ctx, zonas)
    if not _h(vs, "rulebase", "security", "rules") and not _h(cfg.v.get(_COMPARTIDO, {}), "rulebase"):
        avisos.append("sin rulebase security: solo las reglas por defecto de PAN-OS")
    if app:
        avisos.append(APP_ID)
    if ctx.ciclos:
        avisos.append("grupos con referencia circular (se cortan): " + ", ".join(sorted(ctx.ciclos)))
    avisos.append("NAT y App-ID no modelados")
    avisos.append("sin contadores de aciertos (show rule-hit-count ... en el archivo o --firewall-contadores)")
    return Firewall(FABRICANTE, host, todas, rutas, [], reglas, [], avisos)


def analizar_texto(texto: str) -> list:
    """Texto de PAN-OS (set o XML) -> [Firewall] (uno por vsys con configuracion; uno solo sin vsys)."""
    cfg = _Cfg()
    if _RE_MARCA_XML.search(texto) and "<config" in texto:
        if len(texto) > MAX_XML:
            raise SystemExit("[!] XML de PAN-OS mayor de 100 MB: no se analiza")
        resto = _xml_a_rutas(texto, cfg)
        sueltas = _desde_set(resto, cfg)
    else:
        sueltas = _desde_set(texto, cfg)
    host = _uno(cfg.g, "deviceconfig", "system", "hostname")
    claves = [k for k, v in cfg.v.items() if k != _COMPARTIDO and v] or [""]
    multi = len(claves) > 1
    out = []
    for k in claves:
        nombre = (host + ":" + k if host else k) if multi else host
        out.append(_construir(nombre, cfg, k, multi, sueltas))
    for fw in out:
        _contadores_texto(fw, sueltas)
    return out


# ---------------------------------------------------------------- entrada y contadores

def detectar(ruta):
    """Texto del archivo (o carpeta) si es de un PAN-OS; None si no lo parece."""
    try:
        texto = "\n".join(f.read_text(encoding="utf-8", errors="replace") for f in _fg._archivos(ruta))
    except OSError:
        return None
    if _RE_MARCA_SET.search(texto) or (_RE_MARCA_XML.search(texto) and "<config" in texto):
        return texto
    return None


def cargar(ruta) -> list:
    texto = detectar(ruta)
    if texto is None:
        raise SystemExit("[!] '" + str(ruta) + "' no parece configuracion de PAN-OS")
    return analizar_texto(texto)


def leer_contadores(lineas) -> dict:
    """{regla: (aciertos, primer, ultimo)} de la salida de `show rule-hit-count ...` (tolerante)."""
    out = {}
    ultimo_primero = True
    activo = False
    for ln in lineas:
        bajo = ln.lower()
        if "hit count" in bajo:
            activo = True
            if "first hit" in bajo and "last hit" in bajo:
                ultimo_primero = bajo.index("last hit") < bajo.index("first hit")
            continue
        if not activo:
            continue
        t = ln.split()
        if len(t) < 2:
            continue
        n = next((x for x in t[1:] if re.match(r"^\d[\d,]*$", x)), None)
        if n is None:
            continue
        fechas = [f.replace("/", "-").replace("T", " ") for f in _RE_FECHA.findall(ln)]
        fechas += [""] * (2 - len(fechas))
        ult, pri = (fechas[0], fechas[1]) if ultimo_primero else (fechas[1], fechas[0])
        out.setdefault(t[0], (int(n.replace(",", "")), pri, ult))
    return out


def _contadores_texto(fw, lineas) -> None:
    datos = leer_contadores(lineas)
    if not datos:
        return
    fw.avisos[:] = [a for a in fw.avisos if not a.startswith("sin contadores de aciertos")]
    usados = 0
    for r in fw.reglas:
        d = datos.get(r.id)
        if d is not None:
            r.aciertos, r.primer_acierto, r.ultimo_acierto = d
            usados += 1
    if not usados:
        fw.avisos.append("contadores: ninguna regla coincide por nombre")


def aplicar_contadores(fws, ruta) -> None:
    """Asocia el texto de `show rule-hit-count ...` (archivo de --firewall-contadores) a las reglas por nombre."""
    p = Path(ruta)
    if not p.is_file():
        raise SystemExit("[!] no existe '" + str(ruta) + "'")
    lineas = p.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    if not leer_contadores(lineas):
        for fw in fws:
            fw.avisos.append("archivo de contadores sin tabla de Hit Count reconocible: no se usa")
        return
    for fw in fws:
        _contadores_texto(fw, lineas)
