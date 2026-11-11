"""Adaptador de la CLI de Cisco FTD / ASA (sintaxis LINA) al modelo comun de firewall.

Entrada: sesion de terminal pegada (prompts `host# show ...`) o carpeta con un archivo por comando.
SEGURIDAD: solo se interpretan show route, show arp, nameif, interface ip brief, zone, access-list, object,
object-group, nat y contadores (rule hits / show access-list). F6b: `show nat detail` (redes ya resueltas y
translate_hits / untranslate_hits por regla; formato segun la documentacion de Cisco ASA/FTD, NO validado con
un equipo real). F6c: varias tomas de `show nat detail` (una por seccion, en orden de aparicion; en una
carpeta, por nombre de archivo): cada una se empareja por separado, el contador de la regla es el maximo y
se detecta el reinicio (un contador que baja entre dos tomas seguidas). Cualquier otra seccion, y toda linea
de un running-config que no sea de esos tipos (usuarios, comunidades SNMP, crypto...), se descarta
sin copiarse a ningun campo del modelo.
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path

from .modelo import Arp, Firewall, Interfaz, Nat, Objeto, Regla, Ruta, Subregla

FABRICANTE = "Cisco FTD/ASA"
_ANY = ipaddress.IPv4Network("0.0.0.0/0")
_V6 = object()                      # direccion IPv6: la linea se omite (el modelo es IPv4)

# Nombres de puerto de Cisco. Tabla pequena escrita de memoria, NO validada contra la documentacion
# del fabricante: un nombre fuera de ella queda como aviso y la regla como "puerto no resuelto".
PUERTOS = {
    "www": 80, "http": 80, "https": 443, "ssh": 22, "telnet": 23, "domain": 53, "snmp": 161,
    "snmptrap": 162, "ntp": 123, "ftp": 21, "ftp-data": 20, "smtp": 25, "ldap": 389, "ldaps": 636,
    "netbios-ssn": 139, "netbios-ns": 137, "netbios-dgm": 138, "sqlnet": 1521, "rdp": 3389,
    "pop3": 110, "imap4": 143, "tftp": 69, "syslog": 514, "bgp": 179, "sunrpc": 111, "nfs": 2049,
    "tacacs": 49, "sip": 5060, "pptp": 1723, "h323": 1720, "bootps": 67, "bootpc": 68,
    "isakmp": 500, "echo": 7, "citrix-ica": 1494, "lpd": 515, "whois": 43, "time": 37,
}
_OPS = ("eq", "range", "gt", "lt", "neq")
_ACCIONES = {"permit": "permitir", "deny": "bloquear", "trust": "confiar"}
_MESES = {m: i for i, m in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1)}
_KW_NAT = ("destination", "service", "source", "description", "dns", "net-to-net", "no-proxy-arp",
           "route-lookup", "unidirectional", "inactive", "interface", "any", "pat-pool", "extended",
           "flat", "include-reserve", "round-robin")

_RE_PROMPT = re.compile(r"^(?P<host>[\w.\-/]*)(?:\([^)]*\))?[#>]\s*(?P<cmd>.*)$")
_RE_MORE = re.compile(r"(?:<-+\s*More\s*-+>|-+\s*More\s*-+)\s*")
_RE_RUTA = re.compile(
    r"^(?P<cod>[A-Za-z]{1,2}\*?(?:\s+[A-Za-z]{1,2}\d?)?\*?)\s+(?P<red>\d+\.\d+\.\d+\.\d+)"
    r"(?:/(?P<pref>\d+)|\s+(?P<mask>\d+\.\d+\.\d+\.\d+))\s+(?P<resto>\S.*)$")
_RE_VIA = re.compile(r"^\[(?P<ad>\d+)/(?P<met>\d+)\]\s+via\s+(?P<gw>[^,\s]+),?\s*(?P<resto>.*)$")
_RE_CONT = re.compile(r"^\[(?P<ad>\d+)/(?P<met>\d+)\]\s+via\s+")
_RE_NAMEIF = re.compile(r"^(\S+)\s+(\S+)\s+(\d+)\s*$")
_RE_HIT = re.compile(r"^(\d+)\s+(\d+)(?:\s+(.*))?$")
_RE_FECHA = re.compile(r"(\d{1,2}):(\d{2}):(\d{2})\s+([A-Za-z]{3})\s+(\d{1,2})\s+(\d{4})")
_RE_HITCNT = re.compile(r"\(hitcnt=(\d+)\)")
_RE_REMARK = re.compile(r"^access-list\s+(\S+)\s+(?:line\s+\d+\s+)?remark\s+rule-id\s+(\d+):\s*(.*)$")
_RE_NAT = re.compile(r"^nat\s*\((?P<i>[^,)]*),(?P<o>[^)]*)\)\s*(?P<resto>.*)$")
# F6b: show nat detail
_RE_ND_SEC = re.compile(r"^(?:Manual|Auto)\s+NAT\s+Policies\s*\(Section\s+(\d+)\)", re.IGNORECASE)
_RE_ND_REGLA = re.compile(r"^(\d+)\s+\((?P<r>[^)]*)\)\s+to\s+\((?P<m>[^)]*)\)\s*(?P<resto>.*)$")
_RE_ND_HITS = re.compile(r"translate_hits\s*=\s*(\d+)\s*,\s*untranslate_hits\s*=\s*(\d+)", re.IGNORECASE)
_RE_ND_RED = re.compile(r"^(Source|Destination)\s*-\s*Origin:\s*(?P<o>.*?)\s*,?\s*Translated:\s*(?P<t>.*)$",
                        re.IGNORECASE)


def _limpiar(texto: str) -> list[str]:
    texto = texto.replace("\x08", "").replace("\r\n", "\n").replace("\r", "\n")
    return [_RE_MORE.sub("", ln).rstrip() for ln in texto.split("\n")]


def _secciones(lineas: list[str]):
    """([(comando, lineas)], hostnames, hubo_prompt). Lo anterior al primer prompt se descarta."""
    secs, hosts, actual, hubo = [], [], None, False
    for ln in lineas:
        m = _RE_PROMPT.match(ln)
        if m:
            hubo = True
            if m["host"]:
                hosts.append(m["host"].split("/")[0])
            cmd = m["cmd"].strip()
            actual = [cmd, []] if cmd else None
            if actual:
                secs.append(actual)
        elif actual is not None:
            actual[1].append(ln)
    return secs, hosts, hubo


def _clase(cmd: str) -> str | None:
    """Clase de parser de un comando; None = se ignora."""
    c = " ".join(cmd.lower().split())
    if c.startswith("sh "):
        c = "show " + c[3:]
    p = c.split()
    if c.startswith("show route"):
        return "ruta"
    if p == ["show", "arp"]:
        return "arp"
    if c.startswith("show nameif"):
        return "nameif"
    if c.startswith("show interface ip brief"):
        return "brief"
    if c.startswith("show zone"):
        return "zona"
    if c.startswith(("show rule hits", "show access-list")):
        return "hits"
    if p[:2] == ["show", "nat"] and "detail" in p[2:]:
        return "natdet"
    if (len(p) >= 2 and p[0] == "show" and len(p[1]) >= 3 and "running-config".startswith(p[1])
            and (len(p) == 2 or p[2] in ("access-list", "object", "object-group", "nat", "all"))):
        return "config"
    return None


def _problema(lineas: list[str]) -> str:
    utiles = [ln for ln in lineas if ln.strip()]
    if not utiles:
        return "salida vacia"
    for ln in utiles[:3]:
        bajo = ln.strip().lower()
        if bajo.startswith("error") or "invalid input" in bajo:
            return "el equipo devolvio error"
    return ""


def _ip4(txt):
    try:
        return ipaddress.IPv4Address(txt)
    except ValueError:
        return None


def _unicos(seq):
    return list(dict.fromkeys(seq))


def _operando_nat(tk, i):
    """(operando, i siguiente): `any`, `interface`, `pat-pool NOMBRE`, un objeto o una IP."""
    if i >= len(tk):
        return "", i
    if tk[i] == "pat-pool" and i + 1 < len(tk):
        return "pat-pool " + tk[i + 1], i + 2
    return tk[i], i + 1


def _red_literal(txt):
    try:
        return ipaddress.IPv4Network(txt, strict=False)
    except ValueError:
        return None


def _redes_detalle(txt):
    """Redes de un lado Origin/Translated de show nat detail (a.b.c.d/nn, rango, lista con comas): lista de
    IPv4Network, None = cualquiera, False = no se entiende (IPv6, texto raro)."""
    txt = txt.strip()
    if txt.lower() in ("any", "any4"):
        return None
    out = []
    for parte in (p.strip() for p in txt.split(",")):
        if not parte:
            continue
        if "-" in parte and "/" not in parte:
            a, b = (_ip4(x.strip()) for x in parte.split("-", 1))
            if a is None or b is None or b < a:
                return False
            out.extend(ipaddress.summarize_address_range(a, b))
        else:
            r = _red_literal(parte)
            if r is None:
                return False
            out.append(r)
    return out or False


def _casa_detalle(n, e) -> bool:
    """F6b: la regla de show nat detail `e` es la regla `n` de la configuracion (interfaces, tipo y objetos)."""
    if [x.strip() for x in n.interfaces] != e["ifc"] or n.tipo not in e["tokens"]:
        return False
    nombres = [n.origen_real, n.origen_mapeado] + ([n.destino_mapeado, n.destino_real] if n.destino else [])
    return all(p in e["tokens"] for nom in nombres for p in nom.split())


def _tamano(redes):
    return None if redes is None else sum(r.num_addresses for r in redes)


def _motivo_tamanos(n) -> str:
    """Motivo por el que la regla no se puede invertir ('' si se puede)."""
    if n.modo == "dynamic" and (n.red_origen_mapeado is None or not n.red_origen_mapeado):
        return "el origen mapeado es cualquiera"
    if n.modo != "static":
        return ""
    pares = [("origen", n.red_origen_real, n.red_origen_mapeado)]
    if n.destino:
        pares.append(("destino", n.red_destino_real, n.red_destino_mapeado))
    for lado, real, mapeado in pares:
        if (real is None) != (mapeado is None):
            return f"{lado}: cualquiera en un solo lado"
        if real is not None and _tamano(real) != _tamano(mapeado):
            return f"{lado}: tamanos distintos (real {_tamano(real)}, mapeado {_tamano(mapeado)})"
    return ""


def _fecha(txt: str) -> str:
    m = _RE_FECHA.search(txt or "")
    if not m or m.group(4).lower() not in _MESES:
        return ""
    h, mi, s, mes, d, a = m.groups()
    return f"{a}-{_MESES[mes.lower()]:02d}-{int(d):02d} {int(h):02d}:{mi}:{s}"


class _Acum:
    """Una regla en construccion: las lineas con el mismo rule-id se unen."""

    def __init__(self, id_, acl, accion):
        self.id, self.acl, self.accion = id_, acl, accion
        self.protos: dict[str, None] = {}
        self.todos_proto = False
        self.todos_puertos = False
        self.puertos: dict[tuple, None] = {}
        self.origen: dict = {}
        self.destino: dict = {}
        self.zo: dict[str, None] = {}
        self.zd: dict[str, None] = {}
        self.registro = False
        self.activa = False
        self.lineas: list[str] = []
        self.malos: dict[str, None] = {}
        self.hit_show = None
        self.subs: list[Subregla] = []


class _Analisis:
    def __init__(self):
        self.avisos: list[str] = []
        self.raw = {"red": {}, "servicio": {}, "protocolo": {}}
        self.memo = {"red": {}, "servicio": {}, "protocolo": {}}
        self.nat: list[Nat] = []
        self.acl_cfg: list[str] = []
        self.acl_show: list[str] = []
        self.hits_tabla: dict[str, tuple] = {}
        self.nat_tomas: list[list] = []      # F6c: reglas de cada show nat detail (una lista por toma, en orden)
        self.nombres_tomas: list[str] = []   # F6c: archivo de cada toma ('' si viene de una sesion pegada)
        self.nat_detalle: dict = {}
        self.hostname = ""
        self.v6 = 0

    def avisar(self, msg: str):
        if msg not in self.avisos:
            self.avisos.append(msg)

    # ---- rutas ------------------------------------------------------------------------------
    def rutas(self, lineas) -> list[Ruta]:
        out, previa = [], None
        for ln in lineas:
            s = ln.strip()
            if not s:
                continue
            if _RE_CONT.match(s) and previa is not None:
                v = _RE_VIA.match(s)
                if v:
                    previa = Ruta(previa.red, v["resto"].split(",")[-1].strip() if v["resto"] else "",
                                  v["gw"], previa.tipo, previa.codigo, int(v["ad"]), int(v["met"]))
                    out.append(previa)
                continue
            m = _RE_RUTA.match(s)
            if not m:
                continue
            resto = m["resto"]
            v = _RE_VIA.match(resto)
            if v:
                ad, met, gw = int(v["ad"]), int(v["met"]), v["gw"]
                nif = v["resto"].split(",")[-1].strip()
            elif "directly connected," in resto:
                ad = met = None
                gw = ""
                nif = resto.rsplit(",", 1)[-1].strip()
            else:
                continue
            try:
                red = ipaddress.IPv4Network(
                    "{}/{}".format(m["red"], m["pref"] or m["mask"]), strict=False)
            except ValueError:
                self.avisar("linea de ruta con mascara invalida omitida: " + s[:60])
                continue
            cod = m["cod"].replace("*", " ").split()[0]
            tipo = ("defecto" if red.prefixlen == 0 else "conectada" if cod == "C"
                    else "local" if cod == "L" else "estatica" if cod == "S" else "dinamica")
            previa = Ruta(red, nif, gw, tipo, m["cod"].strip(), ad, met)
            out.append(previa)
        return out

    # ---- interfaces -------------------------------------------------------------------------
    def nameif(self, lineas):
        vistos, filas = False, []
        for ln in lineas:
            s = ln.strip()
            if re.match(r"^Interface\s+Name\s+Security", s, re.IGNORECASE):
                vistos = True
                continue
            m = _RE_NAMEIF.match(s) if vistos else None
            if m:
                filas.append((m[1], m[2], int(m[3])))
        return filas

    def brief(self, lineas):
        vistos, filas = False, []
        for ln in lineas:
            p = ln.split()
            if len(p) >= 2 and p[0].lower() == "interface" and "ip-address" in p[1].lower():
                vistos = True
                continue
            if vistos and len(p) >= 2:
                filas.append((p[0], "" if p[1].lower() == "unassigned" else p[1]))
        return filas

    def zonas(self, lineas) -> dict[str, list[str]]:
        zonas, actual = {}, None
        for ln in lineas:
            m = re.match(r"^\s*Zone:\s*(\S+)", ln)
            if m:
                actual = zonas.setdefault(m[1], [])
            elif actual is not None:
                actual.extend(t for t in re.split(r"[\s,]+", ln.strip()) if t)
        return zonas

    # ---- configuracion: objetos, grupos, nat, access-list ------------------------------------
    def config(self, lineas):
        bloque = None
        for raw in lineas:
            if not raw.strip():
                continue
            if raw[0] in " \t":
                if bloque:
                    self._en_bloque(bloque, raw.split())
                continue
            bloque = None
            s = raw.strip()
            t = s.split()
            k = t[0]
            if k == "object" and len(t) >= 3 and t[1] in ("network", "service"):
                tipo = "red" if t[1] == "network" else "servicio"
                self.raw[tipo].setdefault(t[2], [])
                bloque = ("obj", tipo, t[2], "")
            elif k == "object-group" and len(t) >= 3 and t[1] in ("network", "service", "protocol"):
                tipo = {"network": "red", "service": "servicio", "protocol": "protocolo"}[t[1]]
                self.raw[tipo].setdefault(t[2], [])
                bloque = ("grp", tipo, t[2], t[3] if len(t) > 3 else "")
            elif k == "access-list":
                self.acl_cfg.append(s)
            elif k == "nat":
                self._nat(s, None)
            elif k == "hostname" and len(t) > 1 and not self.hostname:
                self.hostname = t[1]

    def _nat(self, s, objeto):
        m = _RE_NAT.match(s)
        if not m:
            return
        tk = m["resto"].split()
        desc = ""
        if "description" in tk:
            j = tk.index("description")
            desc = " ".join(tk[j + 1:])
            tk = tk[:j]
        n = Nat([m["i"], m["o"]], "", [], desc, s)
        n.linea = len(self.nat) + 1
        n.clase = "objeto" if objeto else "twice"
        n.seccion = 2 if objeto else 1
        n.inactiva = "inactive" in tk
        n.unidireccional = "unidirectional" in tk
        while tk and (tk[0] == "after-auto" or tk[0].isdigit() or (tk[0] == "line" and len(tk) > 1)):
            if tk[0] == "after-auto":
                n.seccion = 3
            tk = tk[2:] if tk[0] == "line" else tk[1:]
        if objeto:
            n.tipo = tk[0] if tk else ""
            n.objetos = [objeto]
            n.origen_real = objeto
            n.origen_mapeado, _ = _operando_nat(tk, 1)
        else:
            i = 0
            while i < len(tk):
                w = tk[i]
                if w == "source" and i + 1 < len(tk) and tk[i + 1] in ("static", "dynamic"):
                    n.tipo = tk[i + 1]
                    n.origen_real, i = _operando_nat(tk, i + 2)
                    n.origen_mapeado, i = _operando_nat(tk, i)
                elif w == "destination" and i + 1 < len(tk) and tk[i + 1] == "static":
                    n.destino = True
                    n.destino_mapeado, i = _operando_nat(tk, i + 2)     # primero el MAPEADO, despues el REAL
                    n.destino_real, i = _operando_nat(tk, i)
                elif w == "service":
                    n.con_servicio = True
                    i += 3
                else:
                    i += 1
            n.objetos = [x for x in (n.origen_real, n.origen_mapeado, n.destino_mapeado, n.destino_real)
                         if x and x not in ("any", "any4", "interface") and not x.startswith("pat-pool ")
                         and _red_literal(x) is None]
        n.modo = "static" if n.tipo == "static" else "dynamic"
        if n.con_servicio:
            self.avisar(f"NAT linea {n.linea} usa service (traduccion de puertos): se aplica solo a las IP")
        self.nat.append(n)

    def resolver_nat(self, interfaces):
        """D70: resuelve los operandos de cada regla nat con los objetos y deja el orden de evaluacion
        (twice NAT, object NAT, twice NAT after-auto; dentro de cada seccion, el orden del archivo)."""
        self._emparejar_nat()
        for n in self.nat:
            n.red_origen_real, e1 = self._o_detalle(n, "origen_real", *self._red_nat(n.origen_real, n, interfaces))
            n.red_origen_mapeado, e2 = self._o_detalle(
                n, "origen_mapeado", *self._red_nat(n.origen_mapeado, n, interfaces))
            if n.destino:
                n.red_destino_mapeado, e3 = self._o_detalle(
                    n, "destino_mapeado", *self._red_nat(n.destino_mapeado, n, interfaces))
                n.red_destino_real, e4 = self._o_detalle(
                    n, "destino_real", *self._red_nat(n.destino_real, n, interfaces))
            else:
                e3 = e4 = ""
            n.motivo = next((e for e in (e1, e2, e3, e4) if e), "")
            if not n.motivo and n.tipo not in ("static", "dynamic"):
                n.motivo = "tipo de NAT no reconocido"
            if not n.motivo:
                n.motivo = _motivo_tamanos(n)
            n.modelable = not n.motivo
            if not n.modelable:
                n.desde_detalle = False
            elif n.desde_detalle:
                self.avisar(f"NAT linea {n.linea}: redes tomadas de show nat detail (falta un objeto en la configuracion)")
            if n.modelable and n.modo == "dynamic" and (
                    n.origen_mapeado == "interface" or n.origen_mapeado.startswith("pat-pool ")
                    or _tamano(n.red_origen_mapeado) == 1):
                n.modo = "pat"
            if not n.modelable and not n.inactiva:
                self.avisar(f"NAT linea {n.linea} no modelable: {n.motivo}")
        self.nat.sort(key=lambda x: x.seccion)
        if self.nat_detalle:
            self.nat_detalle["modeladas_con_detalle"] = sum(1 for n in self.nat if n.desde_detalle)

    def natdet(self, tomas):
        """F6b/F6c: cada toma de `show nat detail` (lineas, nombre de archivo), en orden de aparicion. Una
        toma sin reglas no cuenta."""
        for lineas, nombre in tomas:
            reglas = self._leer_natdet(lineas)
            if reglas:
                self.nat_tomas.append(reglas)
                self.nombres_tomas.append(nombre)

    @staticmethod
    def _leer_natdet(lineas) -> list:
        """Reglas de una toma (seccion, interfaces, encabezado, contadores y redes)."""
        out, sec, act = [], 0, None
        for ln in lineas:
            s = ln.strip()
            m = _RE_ND_SEC.match(s)
            if m:
                sec, act = int(m[1]), None
                continue
            m = _RE_ND_REGLA.match(s)
            if m and sec:
                act = {"seccion": sec, "ifc": [m["r"].strip(), m["m"].strip()], "tokens": m["resto"].split(),
                       "hits": None, "redes": {}}
                out.append(act)
                continue
            if act is None:
                continue
            m = _RE_ND_HITS.search(s)
            if m:
                act["hits"] = (int(m[1]), int(m[2]))
                continue
            m = _RE_ND_RED.match(s)
            if m:
                origen = m[1].lower() == "source"
                # destination static MAPEADO REAL: `Origin` es el mapeado y `Translated` el real
                for claves, txt in ((("origen_real", "destino_mapeado"), m["o"]),
                                    (("origen_mapeado", "destino_real"), m["t"])):
                    r = _redes_detalle(txt)
                    if r is not False:
                        act["redes"][claves[0] if origen else claves[1]] = r
        return out

    def _emparejar_nat(self):
        """F6b/F6c: cada regla de cada toma de show nat detail con una de la configuracion de su seccion (en
        orden), comprobando interfaces y objetos; cada toma por separado. Lo que no empareja no se inventa: se
        cuenta. Por regla: maximo de los contadores de las tomas que la emparejaron."""
        if not self.nat_tomas:
            return
        for n in self.nat:
            n.hits_por_toma = []
        avisos, sin_t, tot_t = [], [], []
        usados_any: set = set()
        for k, reglas in enumerate(self.nat_tomas, 1):
            usados, sin = set(), 0
            for e in reglas:
                for n in self.nat:
                    if id(n) not in usados and n.seccion == e["seccion"] and _casa_detalle(n, e):
                        usados.add(id(n))
                        n.hits_por_toma.append(e["hits"] or (None, None))
                        n.redes_detalle = e["redes"]
                        break
                else:
                    sin += 1
            for n in self.nat:
                if id(n) not in usados:
                    n.hits_por_toma.append(None)
            usados_any |= usados
            sin_t.append(sin)
            tot_t.append(len(reglas))
            txt = (f"{sin} de {len(reglas)} reglas sin emparejar con la configuracion y "
                   f"{len(self.nat) - len(usados)} de {len(self.nat)} reglas de la configuracion sin contadores")
            avisos.append((k, txt))
        reinicios = set()
        for n in self.nat:
            vistos = [h for h in n.hits_por_toma if h and h[0] is not None]
            n.hits_traducidos = max((h[0] for h in vistos), default=None)
            n.hits_inversos = max((h[1] for h in vistos), default=None)
            reinicios.update(n.bajadas())
        self.nat_detalle = {"reglas_detalle": max(tot_t), "sin_emparejar": max(sin_t),
                            "config_sin_contador": len(self.nat) - len(usados_any),
                            "tomas": len(self.nat_tomas), "reinicios": [[k, k + 1] for k in sorted(reinicios)],
                            "nombres": list(self.nombres_tomas)}
        if len(self.nat_tomas) == 1:
            if sin_t[0] or len(usados_any) < len(self.nat):
                self.avisar("show nat detail: " + avisos[0][1])
        elif any(sin_t):
            for k, txt in avisos:
                self.avisar(f"show nat detail, toma {k}: {txt}")

    def _o_detalle(self, n, clave, red, err):
        """Si falto un objeto y show nat detail trae la red de ese operando, se usa."""
        if err and clave in n.redes_detalle:
            n.desde_detalle = True
            return n.redes_detalle[clave], ""
        return red, err

    def _red_nat(self, nombre, n, interfaces):
        """(redes | None si es cualquiera, motivo si no se pudo resolver)."""
        if nombre in ("any", "any4"):
            return None, ""
        if not nombre:
            return [], "operando ausente"
        if nombre == "interface":
            ifc = next((i for i in interfaces if i.nombre == n.interfaces[1] and i.ip), None)
            if ifc is None:
                return [], f"interfaz {n.interfaces[1]} sin IP conocida"
            return [ipaddress.IPv4Network(ifc.ip + "/32")], ""
        if nombre.startswith("pat-pool "):
            nombre = nombre[9:]
        if nombre in self.raw["red"]:
            v, malos, _ = self.resolver("red", nombre)
            if malos or not v:
                return [], "objeto sin resolver: " + nombre
            return v, ""
        lit = _red_literal(nombre)
        if lit is not None:
            return [lit], ""
        return [], "objeto no definido: " + nombre

    def _puerto(self, tok):
        if tok.isdigit():
            return int(tok)
        if tok in PUERTOS:
            return PUERTOS[tok]
        self.avisar("puerto con nombre desconocido: " + tok)
        return None

    def _ops(self, t, j, malos):
        """Interpreta eq|range|gt|lt|neq en t[j]; devuelve (rangos, j siguiente)."""
        op = t[j]
        if op == "range":
            a, b = self._puerto(t[j + 1]), self._puerto(t[j + 2])
            if a is None or b is None:
                malos.extend("puerto no resuelto: " + x for x, v in ((t[j + 1], a), (t[j + 2], b)) if v is None)
                return [], j + 3
            return [(a, b)], j + 3
        p = self._puerto(t[j + 1])
        if p is None:
            malos.append("puerto no resuelto: " + t[j + 1])
            return [], j + 2
        if op == "eq":
            return [(p, p)], j + 2
        if op == "gt":
            return [(p + 1, 65535)], j + 2
        if op == "lt":
            return [(0, p - 1)], j + 2
        return [r for r in ((0, p - 1), (p + 1, 65535)) if r[0] <= r[1]], j + 2    # neq

    def _en_bloque(self, bloque, t):
        clase, tipo, nombre, proto = bloque
        items = self.raw[tipo][nombre]
        k = t[0]
        if k == "nat" and clase == "obj" and tipo == "red":
            self._nat(" ".join(t), nombre)
            return
        try:
            if tipo == "red":
                self._item_red(items, nombre, t)
            elif tipo == "servicio":
                self._item_svc(items, t, clase, proto)
            elif k == "protocol-object":
                items.append(("proto", t[1]))
            elif k == "group-object":
                items.append(("ref", t[1]))
        except (IndexError, ValueError):
            self.avisar("linea de objeto no interpretada en {}: {}".format(nombre, " ".join(t)[:60]))

    def _item_red(self, items, nombre, t):
        k, a = t[0], t[1:]
        if k == "network-object":
            if a[0] == "object":
                items.append(("ref", a[1]))
                return
            if a[0] == "host":
                k, a = "host", a[1:]
            else:
                k = "subnet"
        elif k == "group-object":
            items.append(("ref", a[0]))
            return
        if k == "host" or k == "subnet" or k == "range" or k == "fqdn":
            if k == "fqdn":
                host = a[-1]
                items.append(("fqdn", host))
                self.avisar(f"objeto {nombre} usa fqdn {host}: no se puede resolver")
                return
            if any(":" in x for x in a):
                return
            if k == "host":
                items.append(("net", ipaddress.IPv4Network(a[0] + "/32")))
            elif k == "subnet":
                items.append(("net", ipaddress.IPv4Network(f"{a[0]}/{a[1]}", strict=False)))
            else:
                for n in ipaddress.summarize_address_range(
                        ipaddress.IPv4Address(a[0]), ipaddress.IPv4Address(a[1])):
                    items.append(("net", n))

    def _item_svc(self, items, t, clase, proto_grupo):
        k = t[0]
        if k == "group-object":
            items.append(("ref", t[1]))
            return
        if k == "port-object":
            protos = ("tcp", "udp") if proto_grupo == "tcp-udp" else (proto_grupo or "tcp",)
            malos: list[str] = []
            rangos, _ = self._ops(t, 1, malos)
            items.extend(("bad", m) for m in malos)
            for p in protos:
                items.extend(("svc", p, a, b) for a, b in rangos)
            return
        if k == "service-object" or k == "service":
            if t[1] == "object":
                items.append(("ref", t[2]))
                return
            proto = t[1]
            protos = ("tcp", "udp") if proto == "tcp-udp" else (proto,)
            rangos, malos, i = [], [], 2
            while i < len(t):
                if t[i] == "source" and i + 1 < len(t) and t[i + 1] in _OPS:
                    _, i = self._ops(t, i + 1, [])
                elif t[i] == "destination" and i + 1 < len(t) and t[i + 1] in _OPS:
                    r, i = self._ops(t, i + 1, malos)
                    rangos += r
                elif t[i] in _OPS and proto in ("tcp", "udp", "tcp-udp"):
                    r, i = self._ops(t, i, malos)
                    rangos += r
                else:
                    i += 1
            items.extend(("bad", m) for m in malos)
            for p in protos:
                if rangos:
                    items.extend(("svc", p, a, b) for a, b in rangos)
                elif not malos:
                    items.append(("svc", p, None, None))

    # ---- resolucion de objetos y grupos -------------------------------------------------------
    def resolver(self, tipo, nombre, vis=frozenset()):
        """(valores, sin_resolver, hubo_ciclo). Memoiza solo lo que no toco un ciclo."""
        memo = self.memo[tipo]
        if nombre in memo:
            return memo[nombre][0], memo[nombre][1], False
        items = self.raw[tipo].get(nombre)
        if items is None:
            self.avisar(f"objeto {tipo} no definido: {nombre}")
            return [], ["objeto no definido: " + nombre], False
        if nombre in vis:
            self.avisar(f"ciclo en grupos de {tipo}: {nombre}")
            return [], [], True
        vis = vis | {nombre}
        vals, malos, ciclo = [], [], False
        for it in items:
            k = it[0]
            if k == "ref":
                v, b, c = self.resolver(tipo, it[1], vis)
                vals += v
                malos += b
                ciclo = ciclo or c
            elif k == "bad":
                malos.append(it[1])
            elif k == "fqdn":
                malos.append("fqdn: " + it[1])
            else:
                vals.append(it[1] if k in ("net", "proto") else it[1:])
        vals, malos = _unicos(vals), _unicos(malos)
        if not ciclo:
            memo[nombre] = (vals, malos)
        return vals, malos, ciclo

    def objetos(self) -> list[Objeto]:
        out = []
        for tipo in ("red", "servicio", "protocolo"):
            for nombre in self.raw[tipo]:
                v, b, _ = self.resolver(tipo, nombre)
                out.append(Objeto(nombre, tipo, v, b))
        return out

    # ---- access-list ----------------------------------------------------------------------
    def _direccion(self, t, j, malos, interfaces):
        """(redes | _V6 | None, ifc, j siguiente)."""
        ifc = None
        if t[j] == "ifc":
            ifc = t[j + 1]
            j += 2
        w = t[j]
        if w in ("any", "any4"):
            return [_ANY], ifc, j + 1
        if w == "any6":
            return _V6, ifc, j + 1
        if w == "host":
            if ":" in t[j + 1]:
                return _V6, ifc, j + 2
            return [ipaddress.IPv4Network(t[j + 1] + "/32")], ifc, j + 2
        if w == "interface":
            ip = next((i.ip for i in interfaces if i.nombre == t[j + 1] and i.ip), "")
            if not ip:
                malos.append("direccion de interfaz sin resolver: " + t[j + 1])
                return [], ifc, j + 2
            return [ipaddress.IPv4Network(ip + "/32")], ifc, j + 2
        if w in ("object", "object-group"):
            v, b, _ = self.resolver("red", t[j + 1])
            malos.extend(b)
            return list(v), ifc, j + 2
        if ":" in w:
            return _V6, ifc, j + 1
        if "/" in w:
            return [ipaddress.IPv4Network(w, strict=False)], ifc, j + 1
        if _ip4(w) is not None and j + 1 < len(t) and _ip4(t[j + 1]) is not None:
            return [ipaddress.IPv4Network(f"{w}/{t[j + 1]}", strict=False)], ifc, j + 2
        raise ValueError(w)

    def _acl_linea(self, s, n_auto, interfaces, accs, crear, hit):
        t = s.split()
        acl, j = t[1], 2
        n = n_auto
        if t[j] == "line":
            n = int(t[j + 1])
            j += 2
        if t[j] in ("extended", "advanced"):
            j += 1
        accion = _ACCIONES.get(t[j])
        if accion is None:
            return
        j += 1
        malos: list[str] = []
        protos, rangos, todos_p, todos_proto = [], [], False, False
        w = t[j]
        if w in ("object-group", "object"):
            tipos = ("protocolo", "servicio") if w == "object-group" else ("servicio",)
            tipo = next((x for x in tipos if t[j + 1] in self.raw[x]), tipos[-1])
            v, b, _ = self.resolver(tipo, t[j + 1])
            malos.extend(b)
            for x in v:
                p = x if tipo == "protocolo" else x[0]
                if p == "ip":
                    todos_proto = todos_p = True
                protos.append(p)
                if tipo == "servicio" and p in ("tcp", "udp"):
                    if x[1] is None:
                        todos_p = True
                    else:
                        rangos.append((x[1], x[2]))
            j += 2
            proto_puertos = False
        else:
            proto = w
            j += 1
            if proto == "ip":
                todos_proto = todos_p = True
            else:
                protos.append(proto)
            proto_puertos = proto in ("tcp", "udp")
        orig, ifo, j = self._direccion(t, j, malos, interfaces)
        pto: list[tuple[int, int]] = []                 # puertos de ORIGEN de esta linea
        if j < len(t) and t[j] in _OPS:
            m0 = len(malos)
            pto, j = self._ops(t, j, malos)
            if not pto and len(malos) > m0:
                pto = [(0, -1)]                          # sin resolver: restringido, no casa con nada
        elif (j + 1 < len(t) and t[j] == "object-group" and t[j + 1] in self.raw["servicio"]
              and t[j + 1] not in self.raw["red"]):
            v, b, _ = self.resolver("servicio", t[j + 1])
            malos.extend(b)
            j += 2
            pto = [] if any(x[1] is None for x in v) else [(x[1], x[2]) for x in v]
        dest, ifd, j = self._direccion(t, j, malos, interfaces)
        if orig is _V6 or dest is _V6:
            self.v6 += 1
            return
        if proto_puertos:
            if j < len(t) and t[j] in _OPS:
                r, j = self._ops(t, j, malos)
                rangos += r
                if not r and not malos:
                    todos_p = True
            elif j < len(t) and t[j] == "object-group":
                v, b, _ = self.resolver("servicio", t[j + 1])
                malos.extend(b)
                j += 2
                for x in v:
                    if x[1] is None:
                        todos_p = True
                    else:
                        rangos.append((x[1], x[2]))
            else:
                todos_p = True
        rid, reg, activa = None, False, True
        while j < len(t):
            w = t[j]
            if w == "rule-id" and j + 1 < len(t):
                rid = t[j + 1]
                j += 2
                continue
            if w in ("log", "event-log"):
                reg = not (j + 1 < len(t) and t[j + 1] == "disable")
            elif w == "inactive":
                activa = False
            j += 1
        clave = (acl, rid if rid else n)
        a = accs.get(clave)
        if a is None:
            if not crear:
                return
            a = accs[clave] = _Acum(rid if rid else f"{acl}:{n}", acl, accion)
        if hit is not None:
            a.hit_show = (a.hit_show or 0) + hit
        if not crear and a.lineas:
            return
        a.lineas.append(s.split(" (hitcnt=")[0])
        a.subs.append(Subregla([] if todos_proto else list(dict.fromkeys(protos)), list(orig), list(dest),
                               _unir(pto), [] if todos_p else _unir(rangos),
                               [ifo] if ifo else [], [ifd] if ifd else [], a.lineas[-1]))
        a.protos.update(dict.fromkeys(protos))
        a.todos_proto = a.todos_proto or todos_proto
        a.todos_puertos = a.todos_puertos or todos_p
        a.puertos.update(dict.fromkeys(rangos))
        a.origen.update(dict.fromkeys(orig))
        a.destino.update(dict.fromkeys(dest))
        if ifo:
            a.zo[ifo] = None
        if ifd:
            a.zd[ifd] = None
        a.registro = a.registro or reg
        a.activa = a.activa or activa
        a.malos.update(dict.fromkeys(malos))

    def reglas(self, interfaces) -> list[Regla]:
        remarks: dict[tuple, dict] = {}
        for s in self.acl_cfg + self.acl_show:
            m = _RE_REMARK.match(s)
            if not m:
                continue
            r = remarks.setdefault((m[1], m[2]), {})
            txt = m[3].strip()
            mm = re.match(r"(?:ACCESS|PREFILTER) POLICY:\s*(.*)$", txt)
            if mm:
                pol, sep, sec = mm[1].rpartition(" - ")
                r["politica"], r["seccion"] = (pol, sec) if sep else (mm[1], "")
                continue
            mm = re.match(r"(?:L[47] )?RULE:\s*(.*)$", txt)   # prefiltro de FTD: "RULE: <nombre>"
            if mm:
                r["nombre"] = mm[1].strip()
        accs: dict[tuple, _Acum] = {}
        en_cfg = {s.split()[1] for s in self.acl_cfg if len(s.split()) > 1}
        for fuente, crear in ((self.acl_cfg, True), (self.acl_show, False)):
            cont: dict[str, int] = {}
            for s in fuente:
                t = s.split()
                if len(t) < 3:
                    continue
                if crear:
                    cont[t[1]] = cont.get(t[1], 0) + 1
                    if t[2] == "remark":
                        continue
                elif t[1] not in en_cfg:
                    cont[t[1]] = cont.get(t[1], 0) + 1
                hit = None
                if not crear:
                    mh = _RE_HITCNT.search(s)
                    hit = int(mh[1]) if mh else None
                try:
                    self._acl_linea(s, cont.get(t[1], 0), interfaces, accs,
                                    crear or t[1] not in en_cfg, hit)
                except (IndexError, ValueError):
                    self.avisar("linea ACL no interpretada: " + s[:80])
        out = []
        for (acl, _), a in accs.items():
            rem = remarks.get((acl, a.id), {})
            tabla = self.hits_tabla.get(a.id)
            ftd = acl.startswith("CSM_FW_ACL_")
            r = Regla(a.id, rem.get("nombre", ""), rem.get("politica", ""),
                      rem.get("seccion", "" if ftd else acl), a.accion,
                      [] if a.todos_proto else list(a.protos), list(a.origen), list(a.destino),
                      [] if a.todos_puertos else _unir(a.puertos), list(a.zo), list(a.zd),
                      a.registro, a.activa, 0, "", "", a.lineas, acl, list(a.malos), a.subs)
            if tabla:
                r.aciertos, r.primer_acierto, r.ultimo_acierto = tabla
            elif a.hit_show is not None:
                r.aciertos = a.hit_show
            out.append(r)
        if self.v6:
            self.avisar(f"{self.v6} linea(s) ACL con direcciones IPv6 omitidas (modelo solo IPv4)")
        return out

    def hits(self, lineas):
        tabla = False
        for ln in lineas:
            s = ln.strip()
            if re.match(r"^Rule\s*ID\b", s, re.IGNORECASE):
                tabla = True
                continue
            if s.startswith("access-list ") and "(hitcnt=" in s:
                self.acl_show.append(s)
                continue
            m = _RE_HIT.match(s) if tabla else None
            if m:
                f = [_fecha(x.group(0)) for x in _RE_FECHA.finditer(m[3] or "")]
                self.hits_tabla[m[1]] = (int(m[2]), f[0] if f else "", f[-1] if f else "")


def _unir(puertos) -> list:
    out = []
    for a, b in sorted(puertos):
        if out and a <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return out


def analizar_texto(texto: str, nombre: str = "") -> Firewall:
    """Analiza una sesion de terminal pegada (o, si no hay prompts, un unico bloque; `nombre` da el
    comando si el archivo se llama como el, p. ej. show_route.txt)."""
    return _analizar([(nombre, texto)])


def _comando_de_archivo(nombre: str) -> str:
    return Path(nombre).stem.replace("_", " ").replace("-", " ") if nombre else ""


def _analizar(entradas) -> Firewall:
    an = _Analisis()
    por_clase: dict[str, list[str]] = {c: [] for c in ("ruta", "nameif", "brief", "zona", "config", "hits", "arp")}
    tomas: list = []                         # F6c: (lineas, archivo) de cada show nat detail, en orden
    hosts: list[str] = []
    for nombre, texto in entradas:
        secs, hs, hubo = _secciones(_limpiar(texto))
        hosts += hs
        if not hubo:
            cmd = _comando_de_archivo(nombre)
            secs = [[cmd, _limpiar(texto)]]
            cls = _clase(cmd)
            if cls is None:                          # sin prompt ni nombre util: lo ofrece a todos
                for lst in por_clase.values():
                    lst.extend(secs[0][1] + ["!"])
                tomas.append((secs[0][1] + ["!"], nombre))
                continue
        for cmd, lineas in secs:
            cls = _clase(cmd)
            if cls is None:
                continue
            prob = _problema(lineas)
            if prob:
                an.avisar(f"comando '{cmd[:60]}': {prob}")
                continue
            if cls == "natdet":
                tomas.append((lineas + ["!"], "" if hubo else nombre))
            else:
                por_clase[cls].extend(lineas + ["!"])
    if hosts:
        an.hostname = hosts[0]
        if len(set(hosts)) > 1:
            an.avisar("varios hostnames en la entrada ({}): se usa {}".format(", ".join(_unicos(hosts)), hosts[0]))
    an.config(por_clase["config"])
    an.hits(por_clase["hits"])
    an.natdet(tomas)
    rutas = _unicos_rutas(an.rutas(por_clase["ruta"]))
    interfaces = _interfaces(an, por_clase, rutas)
    arp = _arp(por_clase["arp"])
    an.resolver_nat(interfaces)
    if not arp:
        an.avisar("sin show arp: no se valida el salto")
    reglas = an.reglas(interfaces)
    objetos = an.objetos()
    for cond, msg in ((rutas, "sin show route: no hay rutas"),
                      (an.acl_cfg or an.acl_show, "sin access-list: no hay reglas"),
                      (an.hits_tabla or any("(hitcnt=" in s for s in an.acl_show),
                       "sin contadores de aciertos (show rule hits / show access-list)")):
        if not cond:
            an.avisar(msg)
    return Firewall(FABRICANTE, an.hostname, interfaces, rutas, objetos, reglas, an.nat, an.avisos, arp,
                    an.nat_detalle)


_RE_ARP = re.compile(r"^(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})(?:\s+(\S+))?$")


def _arp(lineas) -> list[Arp]:
    """show arp: `<nameif> <IP> <MAC> <edad>`; la edad puede ser `-` o `alias` (queda None)."""
    out = []
    for ln in lineas:
        m = _RE_ARP.match(ln.strip())
        if m:
            e = m[4] or ""
            out.append(Arp(m[1], m[2], m[3].lower(), int(e) if e.isdigit() else None))
    return out


def _unicos_rutas(rutas):
    vistos, out = set(), []
    for r in rutas:
        k = (r.red, r.interfaz, r.salto)
        if k not in vistos:
            vistos.add(k)
            out.append(r)
    return out


def _interfaces(an, por_clase, rutas) -> list[Interfaz]:
    por: dict[str, Interfaz] = {}
    filas = an.nameif(por_clase["nameif"])
    if not filas:
        an.avisar("sin show nameif: no hay nombres ni niveles de seguridad")
    for fis, nom, sec in filas:
        por[fis.lower()] = Interfaz(fis, nom, seguridad=sec)
    brief = an.brief(por_clase["brief"])
    if not brief:
        an.avisar("sin show interface ip brief: no hay direcciones IP de interfaz")
    for fis, ip in brief:
        i = por.setdefault(fis.lower(), Interfaz(fis))
        i.ip = ip
    for i in por.values():
        if i.ip and not i.mascara:
            for r in rutas:
                if r.tipo == "conectada" and r.interfaz == i.nombre and _ip4(i.ip) in r.red:
                    i.mascara = str(r.red.netmask)
                    break
    zonas = an.zonas(por_clase["zona"])
    asignado = False
    for z, miembros in zonas.items():
        ms = {m.lower() for m in miembros}
        for i in por.values():
            if i.zona == "" and (i.fisica.lower() in ms or (i.nombre and i.nombre.lower() in ms)):
                i.zona = z
                asignado = True
    if not asignado:
        an.avisar("zonas tomadas del nameif (sin show zone)")
    for i in por.values():
        i.zona = i.zona or i.nombre
    return list(por.values())


def cargar(ruta) -> Firewall:
    """Archivo de texto (sesion pegada) o carpeta con un archivo por comando."""
    p = Path(ruta)
    if p.is_dir():
        archivos = sorted(f for f in p.iterdir() if f.is_file() and not f.name.startswith("."))
    elif p.is_file():
        archivos = [p]
    else:
        raise SystemExit(f"[!] no existe '{ruta}'")
    return _analizar([(f.name, f.read_text(encoding="utf-8", errors="replace")) for f in archivos])
