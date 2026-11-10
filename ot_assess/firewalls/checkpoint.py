"""Adaptador de la politica de un firewall Check Point (R80.x/R81.x) al modelo comun de firewall (F4).

Entrada (archivo o carpeta): JSON de `mgmt_cli show access-rulebase name "Network" details-level full
use-object-dictionary true show-hits true limit 500 offset N --format json` (una pagina por archivo; se unen
todos los JSON de la carpeta) y, opcional, texto de Gaia clish del gateway: `show interfaces all`,
`show route` o `netstat -rn` del modo expert. Sin esos textos el contraste no conoce interfaces.
SEGURIDAD: solo se leen los campos de reglas y objetos de red/servicio citados abajo; nada mas se copia
(password, shared-secret, pre-shared-key, secret, certificate, comments... quedan fuera por construccion).
NO validado con una muestra real: formato publico de la Management API y de Gaia; lo no interpretado queda
como aviso. Capas inline, NAT, IPv6, negaciones y objetos dinamicos no se modelan.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone

from .. import json_entrada
from . import fortigate as _fg
from . import paloalto as _pa
from .modelo import Firewall, Interfaz, Regla, Ruta, Subregla

FABRICANTE = "Check Point"
ACL = "checkpoint-access"
MAX_JSON = 100 * 1024 * 1024
_ANY = ipaddress.IPv4Network("0.0.0.0/0")
AVISO_ZONAS = ("security-zone: la zona se usa como interfaz de la regla y no casa con las interfaces del gateway "
               "(el mapeo zona->interfaz esta en el objeto gateway, que no se tiene); --zonas-fw solo "
               "afecta la politica propuesta, no el contraste")
AVISO_SIN_RED = ("sin show interfaces all / show route / netstat -rn del gateway: el contraste no conoce "
                 "interfaces y no puede decir que conductos cruzan el firewall")
_RE_IFC = re.compile(r"^\s*Interface\s+(\S+)", re.IGNORECASE)
_RE_IP_IFC = re.compile(r"^\s*ipv4-address\s+(\d+\.\d+\.\d+\.\d+)(?:/(\d+)|\s+mask-length\s+(\d+))?", re.IGNORECASE)
_RE_SET_IFC = re.compile(r"^\s*set\s+interface\s+(\S+)\s+(ipv4-address\s+\S+(?:\s+mask-length\s+\d+)?|state\s+\S+)",
                         re.IGNORECASE)
_RE_ESTADO = re.compile(r"^\s*state\s+(on|off)\b", re.IGNORECASE)
_RE_VIA = re.compile(r"via\s+(\d+\.\d+\.\d+\.\d+)\s*,\s*([^\s,]+)")
_RE_DIRECTA = re.compile(r"directly connected\s*,\s*([^\s,]+)", re.IGNORECASE)
_RE_COSTO = re.compile(r"cost\s+(\d+)")
_RE_NETSTAT = re.compile(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+.*?(\S+)\s*$")
_RE_CODIGO = re.compile(r"^[A-Za-z]{1,2}\d?[*>]*$")
_RE_IP = re.compile(r"^\d+\.\d+\.\d+\.\d+(?:/\d+)?$")
_RE_PROMPT = re.compile(r"^\s*(?:\[\S+@)?([A-Za-z][\w.-]*)[>:]\S*\s*(?:#\s*)?(?:show|set|netstat)\b", re.MULTILINE)
_RE_FECHA = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})(?::(\d{2}))?\s*([+-]\d{4})?")


def _lista(x) -> list:
    return x if isinstance(x, list) else ([] if x is None else [x])


def _texto(x) -> str:
    return x if isinstance(x, str) else ""


# ---------------------------------------------------------------- lectura de archivos

def _paginas(dato) -> list:
    """Paginas de politica dentro de un JSON ya leido (objeto, o lista de objetos)."""
    out = []
    for d in (dato if isinstance(dato, list) else [dato]):
        if isinstance(d, dict) and isinstance(d.get("rulebase"), list) and "objects-dictionary" in d:
            out.append(d)
    return out


def detectar(ruta):
    """([paginas JSON], texto de clish) del archivo o carpeta si trae una politica de Check Point; None si no."""
    paginas, textos = [], []
    for f in _fg._archivos(ruta):
        try:
            if f.stat().st_size > MAX_JSON:
                raise SystemExit("[!] archivo de Check Point mayor de 100 MB: no se analiza")
            txt = f.read_text(encoding="utf-8-sig", errors="replace")
        except OSError:
            return None
        if txt.lstrip()[:1] in ("{", "["):
            try:
                pg = _paginas(json_entrada.cargar(txt))
            except ValueError:
                pg = []
            if pg:
                paginas.extend(pg)
                continue
        textos.append(txt)
    if not paginas:
        return None
    return paginas, "\n".join(textos)


# ---------------------------------------------------------------- objetos

def _puerto(txt):
    """'443', '8080-8090', '>1023', '<1024' -> (ini, fin) o None."""
    t = str(txt).strip().replace(" ", "")
    if t and t[0] in "<>":
        ig = t[1:2] == "="
        n = t[2:] if ig else t[1:]
        if not n.isdigit():
            return None
        n = int(n)
        if t[0] == ">":
            r = (n if ig else n + 1, 65535)
        else:
            r = (1, n if ig else n - 1)
        return r if 0 <= r[0] <= r[1] <= 65535 else None
    return _fg._rango(t)


def _rangos(txt) -> tuple:
    """Texto de puerto -> ((rangos), [malos])."""
    if txt in (None, ""):
        return [], []
    r = _puerto(txt)
    return ([r], []) if r else ([], ["puerto no resuelto: " + str(txt)])


class _Ctx:
    """Resolucion de objetos del diccionario (por uid) de una politica."""

    def __init__(self, paginas, avisos):
        self.avisos = avisos
        self.uid: dict = {}
        self.nombre: dict = {}
        for p in paginas:
            for o in _lista(p.get("objects-dictionary")):
                if isinstance(o, dict):
                    if o.get("uid"):
                        self.uid.setdefault(o["uid"], o)
                    if o.get("name"):
                        self.nombre.setdefault(o["name"], o)
        self.ciclos: set = set()
        self.zonas_vistas = False
        self._md: dict = {}
        self._ms: dict = {}
        self._vueltas = 0

    def obj(self, ref):
        """Objeto del diccionario para un uid, un nombre o un objeto en linea; None si no esta."""
        if isinstance(ref, dict):
            if ref.get("type") or ref.get("name"):
                return ref
            ref = ref.get("uid")
        if isinstance(ref, str):
            return self.uid.get(ref) or self.nombre.get(ref)
        return None

    @staticmethod
    def tipo(o) -> str:
        return _texto(o.get("type")).lower()

    def _memo(self, cache, clave, calcular):
        if clave in cache:
            return cache[clave]
        antes = self._vueltas
        res = calcular()
        if self._vueltas == antes:      # un resultado calculado cortando un ciclo puede estar incompleto
            cache[clave] = res
        return res

    def direccion(self, ref, en_curso=()):
        """Redes de un objeto de direccion -> ([IPv4Network], [malos])."""
        o = self.obj(ref)
        if o is None:
            return [], ["objeto no encontrado en objects-dictionary: " + str(ref)[:36]]
        n, t = _texto(o.get("name")), self.tipo(o)
        if t == "cpmianyobject":
            return [_ANY], []
        uid = _texto(o.get("uid")) or n
        if uid in en_curso:
            self.ciclos.add(n)
            self._vueltas += 1
            return [], []
        return self._memo(self._md, uid, lambda: self._direccion(o, n, t, tuple(en_curso) + (uid,)))

    def _direccion(self, o, n, t, camino):
        if t == "group":
            redes, malos = [], []
            for m in _lista(o.get("members")):
                r, b = self.direccion(m, camino)
                redes += r
                malos += b
            return list(dict.fromkeys(redes)), list(dict.fromkeys(malos))
        if t == "host" and o.get("ipv4-address"):
            r = _fg._red(_texto(o["ipv4-address"]) + "/32")
            return ([r], []) if r else ([], ["direccion no resuelta: " + n])
        if t == "network" and o.get("subnet4"):
            if o.get("mask-length4") not in (None, ""):
                r = _fg._red(_texto(o["subnet4"]) + "/" + str(o["mask-length4"]))
            else:
                r = _fg._red(_texto(o["subnet4"]) + "/" + _texto(o.get("subnet-mask")))
            return ([r], []) if r else ([], ["direccion no resuelta: " + n])
        if t == "address-range" and o.get("ipv4-address-first") and o.get("ipv4-address-last"):
            try:
                return list(ipaddress.summarize_address_range(
                    ipaddress.IPv4Address(o["ipv4-address-first"]),
                    ipaddress.IPv4Address(o["ipv4-address-last"]))), []
            except (ValueError, TypeError):
                return [], ["rango no resuelto: " + n]
        if t in ("host", "network", "address-range"):
            return [], ["IPv6 u otro dato no modelado en " + t + ": " + n]
        return [], ["objeto de tipo " + (t or "desconocido") + " no resuelto: " + n]

    def servicio(self, ref, en_curso=()):
        """Servicio -> ([(proto, dports, sports)], [malos]); proto 'all' = cualquiera."""
        o = self.obj(ref)
        if o is None:
            return [], ["servicio no encontrado en objects-dictionary: " + str(ref)[:36]]
        n, t = _texto(o.get("name")), self.tipo(o)
        if t == "cpmianyobject":
            return [("all", [], [])], []
        uid = _texto(o.get("uid")) or n
        if uid in en_curso:
            self.ciclos.add(n)
            self._vueltas += 1
            return [], []
        return self._memo(self._ms, uid, lambda: self._servicio(o, n, t, tuple(en_curso) + (uid,)))

    def _servicio(self, o, n, t, camino):
        if t == "service-group":
            ents, malos = [], []
            for m in _lista(o.get("members")):
                e, b = self.servicio(m, camino)
                ents += e
                malos += b
            return ents, list(dict.fromkeys(malos))
        if t in ("service-tcp", "service-udp"):
            proto = t[-3:]
            d, m1 = _rangos(o.get("port"))
            s, m2 = _rangos(o.get("source-port"))
            malos = m1 + m2
            if o.get("port") in (None, ""):
                malos.append("servicio " + n + " sin puerto: se toma cualquier puerto")
            return [(proto, d, s)], malos
        if t == "service-icmp":
            return [("icmp", [], [])], []
        return [], ["servicio de tipo " + (t or "desconocido") + " no resuelto: " + n]


# ---------------------------------------------------------------- reglas

def _fecha(d) -> str:
    """{'posix': ms, 'iso-8601': ...} -> 'AAAA-MM-DD HH:MM:SS' en UTC ('' si no se puede)."""
    if not isinstance(d, dict):
        return ""
    p = d.get("posix")
    if isinstance(p, (int, float)) and not isinstance(p, bool) and p > 0:
        try:
            return datetime.fromtimestamp(p / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        except (OverflowError, OSError, ValueError):
            return ""
    m = _RE_FECHA.match(_texto(d.get("iso-8601")))
    if not m:
        return ""
    t = datetime.strptime(m.group(1) + " " + m.group(2) + ":" + (m.group(3) or "00"), "%Y-%m-%d %H:%M:%S")
    if m.group(4):
        sg = 1 if m.group(4)[0] == "+" else -1
        t -= sg * timedelta(hours=int(m.group(4)[1:3]), minutes=int(m.group(4)[3:5]))
    return t.strftime("%Y-%m-%d %H:%M:%S")


def _aplanar(paginas) -> list:
    """[(capa, seccion, regla)] sin repetidas por uid y en orden de rule-number dentro de cada capa."""
    capas: dict = {}
    vistos: set = set()
    seq = [0]

    def recorrer(items, capa, seccion):
        for it in _lista(items):
            if not isinstance(it, dict):
                continue
            if isinstance(it.get("rulebase"), list):
                recorrer(it["rulebase"], capa, _texto(it.get("name")) or seccion)
                continue
            if "action" not in it and "source" not in it:
                continue
            uid = _texto(it.get("uid"))
            if uid and (capa, uid) in vistos:
                continue
            vistos.add((capa, uid))
            seq[0] += 1
            n = it.get("rule-number")
            clave = n if isinstance(n, int) and not isinstance(n, bool) else 10 ** 9
            capas.setdefault(capa, []).append((clave, seq[0], seccion, it))

    for p in paginas:
        recorrer(p["rulebase"], _texto(p.get("name")) or "Network", "")
    out = []
    for capa, rs in capas.items():
        out += [(capa, sec, r) for _k, _s, sec, r in sorted(rs, key=lambda x: (x[0], x[1]))]
    return out


def _nombre_obj(ctx, ref) -> str:
    o = ctx.obj(ref)
    return _texto(o.get("name")) if o else (ref if isinstance(ref, str) else "")


def _regla(it, capa, seccion, idx, ctx, multi, con_hits):
    malos: list = []
    zonas = {"source": [], "destination": []}

    def lado(clave, neg):
        refs = _lista(it.get(clave))
        if not refs:
            malos.append(clave + " vacio")
            return [], False
        if it.get(neg) is True:
            malos.append(neg + " no modelado")
            return [], False
        redes, solo_zonas = [], True
        for ref in refs:
            o = ctx.obj(ref)
            if o is not None and ctx.tipo(o) == "security-zone":
                zonas[clave].append(_texto(o.get("name")))
                ctx.zonas_vistas = True
                continue
            solo_zonas = False
            r, m = ctx.direccion(ref)
            redes += r
            malos.extend(m)
        if zonas[clave] and not solo_zonas:
            malos.append("zona junto a redes en " + clave + ": se aplican las dos (la regla real es una union)")
        if zonas[clave] and solo_zonas:
            redes = [_ANY]
        return list(dict.fromkeys(redes)), any(r.prefixlen == 0 for r in redes)

    orig, o_any = lado("source", "source-negate")
    dest, d_any = lado("destination", "destination-negate")
    ents, s_any = [], False
    refs = _lista(it.get("service"))
    if not refs:
        malos.append("service vacio")
    if it.get("service-negate") is True:
        malos.append("service-negate no modelado")
        refs = []
    for ref in refs:
        e, m = ctx.servicio(ref)
        ents += e
        malos.extend(m)
        s_any = s_any or any(x[0] == "all" for x in e)
    zo, zd = list(dict.fromkeys(zonas["source"])), list(dict.fromkeys(zonas["destination"]))
    accion_obj = it.get("action")
    nombre_acc = _nombre_obj(ctx, accion_obj).lower()
    capa_inline = it.get("inline-layer")
    if capa_inline:
        malos.append("inline-layer " + _nombre_obj(ctx, capa_inline) + " no se expande: el resultado de esta regla "
                     "no es confiable")
        acc = "bloquear"
    elif nombre_acc == "accept":
        acc = "permitir"
    else:
        acc = "bloquear"
        if nombre_acc not in ("drop", "reject"):
            malos.append("accion " + (nombre_acc or "desconocida") + " tratada como bloquear")
    inst = [n for n in (_nombre_obj(ctx, x) for x in _lista(it.get("install-on")))
            if n and n.lower() not in ("policy targets", "any")]
    if inst:
        malos.append("install-on " + ", ".join(inst) + ": puede no aplicar a este gateway")
    numero = it.get("rule-number")
    rid = (str(numero) if numero is not None else "r" + str(idx))
    if multi:
        rid = capa + ":" + rid
    nombre = _texto(it.get("name")) or rid
    linea = "rule " + rid
    subs = _pa._subreglas(ents, orig, dest, zo, zd, linea)
    if not subs:
        subs = [Subregla(["no_resuelto"], orig, dest, [], [], zo, zd, linea)]
    todos = any(not s.protocolos for s in subs)
    protos = [] if todos else list(dict.fromkeys(p for s in subs for p in s.protocolos))
    puertos = []
    if not todos and all(s.puertos_destino or s.protocolos[0] in ("icmp", "no_resuelto") for s in subs):
        puertos = list(_fg._unir([p for s in subs for p in s.puertos_destino]))
    tr = it.get("track")
    tr = tr.get("type") if isinstance(tr, dict) and "type" in tr else tr
    registro = _nombre_obj(ctx, tr).lower() not in ("", "none")
    aciertos, primero, ultimo = 0, "", ""
    h = it.get("hits")
    if isinstance(h, dict):
        v = h.get("value")
        aciertos = v if isinstance(v, int) and not isinstance(v, bool) and v > 0 else 0
        primero, ultimo = _fecha(h.get("first-date")), _fecha(h.get("last-date"))
        con_hits.append(1)
    r = Regla(
        id=rid, nombre=nombre, politica=capa, seccion=seccion, accion=acc, protocolos=protos, origen=orig,
        destino=dest, puertos=puertos, zonas_origen=zo, zonas_destino=zd, registro=registro,
        activa=it.get("enabled") is not False, aciertos=aciertos, primer_acierto=primero,
        ultimo_acierto=ultimo, lineas=[linea], acl=ACL, no_resuelto=list(dict.fromkeys(malos)), subreglas=subs)
    return r, o_any and d_any and s_any


def _reglas(paginas, ctx):
    lista = _aplanar(paginas)
    multi = len({c for c, _s, _r in lista}) > 1
    con_hits: list = []
    reglas, ultima_cleanup = [], False
    for i, (capa, sec, it) in enumerate(lista, 1):
        r, todo_any = _regla(it, capa, sec, i, ctx, multi, con_hits)
        reglas.append(r)
        # regla final explicita: cualquier origen, destino y servicio, y bloquear
        ultima_cleanup = r.activa and (r.accion == "bloquear" and todo_any
                                          and not r.zonas_origen and not r.zonas_destino)
    if not ultima_cleanup:
        reglas.append(Regla(
            id="cleanup-implicita", nombre="Cleanup rule (implicita)", politica="", seccion="", accion="bloquear",
            origen=[_ANY], destino=[_ANY], lineas=["cleanup implicita"], acl=ACL,
            subreglas=[Subregla([], [_ANY], [_ANY], [], [], [], [], "cleanup implicita")]))
    return reglas, bool(con_hits), multi


# ---------------------------------------------------------------- gateway (Gaia clish)

def _mascara(n) -> str:
    return str(ipaddress.IPv4Network("0.0.0.0/" + str(n)).netmask)


def _interfaces(texto, avisos) -> list:
    """Interfaces con IPv4 de `show interfaces all` (bloques `Interface X`) o `set interface X ...`."""
    por: dict = {}
    actual = None
    for ln in texto.splitlines():
        m = _RE_IFC.match(ln)
        if m:
            actual = m.group(1)
            por.setdefault(actual, {})
            continue
        m = _RE_SET_IFC.match(ln)
        if m:
            d = por.setdefault(m.group(1), {})
            t = m.group(2).split()
            if t[0].lower() == "state":
                d["estado"] = t[1].lower()
            else:
                d["ip"] = (t[1], t[3] if len(t) > 3 else "")
            continue
        if actual is None:
            continue
        m = _RE_IP_IFC.match(ln)
        if m:
            por[actual]["ip"] = (m.group(1), m.group(2) or m.group(3) or "")
            continue
        m = _RE_ESTADO.match(ln)
        if m:
            por[actual]["estado"] = m.group(1).lower()
    out = []
    for nombre, d in por.items():
        ip = d.get("ip")
        if not ip or not ip[1].isdigit() or not 0 < int(ip[1]) <= 32:
            continue
        if d.get("estado") == "off":
            avisos.append("interfaz " + nombre + " con state off: no se usa")
            continue
        out.append(Interfaz(nombre, nombre, ip[0], _mascara(ip[1])))
    return out


def _tipo_ruta(codigo, red) -> str:
    c = codigo.upper().rstrip("*>")
    if c == "C":
        return "conectada"
    if c == "L":
        return "local"
    if c == "S":
        return "defecto" if red.prefixlen == 0 else "estatica"
    return "dinamica"


def _rutas_texto(texto) -> list:
    """Rutas de `show route` (clish) o `netstat -rn` (expert)."""
    out = []
    for ln in texto.splitlines():
        t = ln.split()
        k = 0
        while k < len(t) and k < 2 and _RE_CODIGO.match(t[k]) and not _RE_IP.match(t[k]):
            k += 1
        if k and k < len(t) and _RE_IP.match(t[k]):
            red = _fg._red(t[k] if "/" in t[k] else t[k] + "/32")
            via, directa = _RE_VIA.search(ln), _RE_DIRECTA.search(ln)
            if red is None or not (via or directa):
                continue
            costo = _RE_COSTO.search(ln)
            codigo = " ".join(t[:k])
            out.append(Ruta(red, via.group(2) if via else directa.group(1), via.group(1) if via else "",
                            _tipo_ruta(t[0], red), codigo, None, int(costo.group(1)) if costo else None))
            continue
        m = _RE_NETSTAT.match(ln)
        if m:
            try:
                red = ipaddress.IPv4Network(m.group(1) + "/" + m.group(3), strict=False)
            except ValueError:
                continue
            via = m.group(2) if "G" in m.group(4) and m.group(2) != "0.0.0.0" else ""  # nosec B104 - texto de netstat -rn (gateway 0.0.0.0 = conectada), no es un bind
            if via:
                tipo, codigo = ("defecto", "S*") if red.prefixlen == 0 else ("estatica", "S")
            else:
                tipo, codigo = "conectada", "C"
            out.append(Ruta(red, m.group(5), via, tipo, codigo))
    return out


def _unicas(rutas) -> list:
    vistos, out = set(), []
    for r in rutas:
        k = (r.red, r.interfaz, r.salto)
        if k not in vistos:
            vistos.add(k)
            out.append(r)
    return out


# ---------------------------------------------------------------- construccion

def analizar(paginas, texto="") -> Firewall:
    """([paginas JSON de mgmt_cli], texto de clish) -> Firewall."""
    avisos: list = []
    ctx = _Ctx(paginas, avisos)
    reglas, con_hits, multi = _reglas(paginas, ctx)
    interfaces = _interfaces(texto, avisos)
    tabla = _rutas_texto(texto)
    conectadas = [Ruta(ipaddress.IPv4Network(i.ip + "/" + i.mascara, strict=False), i.nombre, "", "conectada", "C")
                  for i in interfaces]
    rutas = _unicas(tabla + conectadas)
    if not interfaces and not rutas:
        avisos.append(AVISO_SIN_RED)
    elif not tabla:
        avisos.append("sin show route / netstat -rn: solo rutas conectadas de las interfaces")
    if multi:
        avisos.append("varias capas de politica: se evaluan en el orden de los archivos; no se encadenan capas")
    if ctx.zonas_vistas:
        avisos.append(AVISO_ZONAS)
    if ctx.ciclos:
        avisos.append("grupos con referencia circular (se cortan): " + ", ".join(sorted(ctx.ciclos)))
    if not con_hits:
        avisos.append("sin contadores de aciertos (show-hits true en mgmt_cli)")
    avisos.append("NAT, capas inline e IPv6 no modelados")
    m = _RE_PROMPT.search(texto)
    return Firewall(FABRICANTE, m.group(1) if m else "", interfaces, rutas, [], reglas, [], avisos)


def cargar(ruta) -> Firewall:
    r = detectar(ruta)
    if r is None:
        raise SystemExit("[!] '" + str(ruta) + "' no parece politica de Check Point (JSON de mgmt_cli)")
    return analizar(*r)
