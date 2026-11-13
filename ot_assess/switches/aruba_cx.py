"""AR1 (D98): lector de la CLI de Aruba AOS-CX (salidas `show` de estado) como fuente de switch.

Lee la sesion de terminal que el analista ya guardo; NO consulta el switch. Produce el mismo `modelo.Switch`
que el lector de Cisco: puertos, VLAN, tabla MAC, LLDP/CDP, espejo, contadores y STP. AR2 (D99) lee tambien la
running-config (`config=True`): puertos, VLAN, espejo, gestion, AAA, NTP y STP global.

Seguridad: de la sesion solo se extraen campos con patrones estrictos; ninguna linea se copia tal cual ni se
cita en un aviso (la running-config trae `password ciphertext`, `key ciphertext` y la comunidad SNMP en claro:
de ellas solo se cuenta cuantas hay, jamas el valor ni el usuario).
Nada usa columnas fijas: los anchos cambian entre versiones.
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path

from .cisco_ios import mac_norm, rango_vlans
from .modelo import (
    CambioStp,
    Contador,
    Puerto,
    SesionSpan,
    Svi,
    Switch,
    Vecino,
    destino_syslog,
    nivel_syslog,
)

_RE_IP = re.compile(r"(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]*:[0-9A-Fa-f:.]*)")

MAX_PLATAFORMA = 80
_RE_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_RE_PAGINADOR = re.compile(r"-- MORE --, next page: Space, next line: Enter, quit: q", re.I)
_RE_PROMPT = re.compile(r"^([A-Za-z0-9][\w.\-]*)(?:\([^)]*\))?[#>]\s*(.*)$")
_RE_CONFIG = re.compile(r"^(?:Current configuration:|!Version\s)")
_RE_CFG_VERSION = re.compile(r"^!Version\s+(?:ArubaOS-CX|AOS-CX)\s+(\S+)")
_RE_PUERTO = re.compile(r"^(?:\d+/\d+/\d+(?:\.\d+)?|lag\d+)$", re.I)
_RE_MACLIN = re.compile(r"^([0-9a-f]{2}(?::[0-9a-f]{2}){5})\s+(\d+)\s+(.*)$", re.I)
_RE_BLOQUE_IF = re.compile(r"^(?:Interface|Aggregate)\s+(\S+)\s+is\s+(\w+)\s*(.*)$", re.I)
_RE_HR = re.compile(r"^(?:<|[\d.]+[KMGTP]$)", re.I)
_RE_STAT = re.compile(r"^(Statistics?)\s+RX\s+TX", re.I)
_RE_RATE = re.compile(r"^Rates?\s+RX\s+TX", re.I)
_RE_VALORES = re.compile(r"<\s*\d+|\S+")
_RE_DETECTA = (
    re.compile(r"^!Version\s+(?:ArubaOS-CX|AOS-CX)", re.M),
    re.compile(r"^\s*(?:ArubaOS-CX|AOS-CX)\s*$", re.M),
    re.compile(r"^\s*(?:ArubaOS-CX|AOS-CX)\s+Version\s*:", re.M),
    re.compile(r"^\s*MAC age-time\s*:", re.M),
)   # el comando `show mac-address-table` solo no basta: IOS 12.x antiguo usa el mismo
_RE_LLDP_CAMPO = (
    ("nombre", re.compile(r"^Neighbor\s+(?:System|Chassis)-Name\s*:\s*(.*)$", re.I)),
    ("desc", re.compile(r"^Neighbor\s+(?:System|Chassis)-Description\s*:\s*(.*)$", re.I)),
    ("chasis", re.compile(r"^Neighbor\s+Chassis-ID\s*:\s*(.*)$", re.I)),
    ("ip", re.compile(r"^Neighbor\s+Management-Address\s*:\s*(.*)$", re.I)),
    ("puerto", re.compile(r"^Neighbor\s+Port-ID\s*:\s*(.*)$", re.I)),
)


def es_aoscx(ruta) -> bool:
    """True si el archivo trae alguna huella de AOS-CX (version, show system o la cabecera de la tabla MAC)."""
    texto = Path(ruta).read_text(encoding="utf-8", errors="replace").replace("\r", "")
    return any(r.search(texto) for r in _RE_DETECTA)


def _limpiar(texto: str) -> list:
    texto = _RE_ANSI.sub("", texto.replace("\x08", "")).replace("\r\n", "\n").replace("\r", "\n")
    return [_RE_PAGINADOR.sub("", ln).rstrip() for ln in texto.split("\n")]


def _secciones(lineas: list) -> tuple:
    """([(comando, lineas)], hostnames, hubo_prompt). La running-config pegada sin prompt abre una seccion
    `show running-config`; la que ya abrio un prompt sigue en la misma seccion."""
    secs, hosts, actual, hubo = [], [], None, False
    for ln in lineas:
        m = _RE_PROMPT.match(ln)
        if m:
            hubo = True
            hosts.append(m.group(1))
            cmd = m.group(2).strip()
            actual = [cmd, []] if cmd else None
            if actual:
                secs.append(actual)
        elif _RE_CONFIG.match(ln.strip()):
            if actual is None or _clase(actual[0]) != "config":
                actual = ["show running-config", []]
                secs.append(actual)
            actual[1].append(ln)
        elif actual is not None:
            actual[1].append(ln)
    return secs, hosts, hubo


def _pre(w: str, completo: str, minimo: int) -> bool:
    return len(w) >= minimo and completo.startswith(w)


def _clase(cmd: str):
    """Clase de parser de un comando (admite abreviaturas por palabra y `| filtro`); None = se ignora."""
    p = cmd.lower().split()
    if "|" in p:
        p = p[:p.index("|")]
    if p and p[0] == "do":
        p = p[1:]
    if len(p) < 2 or not _pre(p[0], "show", 2):
        return None
    a, resto = p[1], p[2:]
    if _pre(a, "running-config", 2) or _pre(a, "startup-config", 3):
        return "config"
    if _pre(a, "system", 3):
        return "system" if not resto else None
    if _pre(a, "version", 3):
        return "version" if not resto else None
    if _pre(a, "interface", 3) or a == "interfaces":
        if any(_pre(x, "brief", 2) for x in resto):
            return "brief"
        if any(_pre(x, "physical", 3) or _pre(x, "extended", 3) or x == "transceiver" for x in resto):
            return None
        return "interface"
    if a == "vlan":
        return "vlan" if not resto else None
    if _pre(a, "mac-address-table", 3):
        return None if any(_pre(x, "count", 3) for x in resto) else "mac"
    if _pre(a, "lldp", 3) and resto and _pre(resto[0], "neighbor-info", 3):
        return "lldp"
    if _pre(a, "cdp", 3) and resto and _pre(resto[0], "neighbor-info", 3):
        return "cdp"
    if _pre(a, "mirror", 3):
        return "mirror"
    if _pre(a, "spanning-tree", 3):
        return "stp"
    return None


def _entero(txt: str):
    return int(txt) if txt.isdigit() else None


def _valor(txt: str):
    """(numero o None, es_human_readable). `n/a` cuenta como 0."""
    txt = txt.strip()
    if txt.lower() == "n/a":
        return 0, False
    if txt.isdigit():
        return int(txt), False
    return None, bool(_RE_HR.match(txt))


def _mac(txt: str) -> str:
    return mac_norm(txt) or txt.strip().lower()


class _Lector:
    def __init__(self, sw: Switch):
        self.sw = sw
        self.hostnames: list = []
        self.modelo = ""
        self.version_show = ""
        self.version_sys = ""
        self.puertos: dict = {}
        self.brief: list = []
        self.hr = 0
        self.vecinos: list = []          # [{"v": Vecino, "chasis": str, "detalle": bool}]
        self.espejo_res: dict = {}       # {id: (admin, operacion)} del resumen
        self.resumen_visto = False       # el resumen de `show mirror` trajo su cabecera
        self._bw = None
        self.espejo_det: dict = {}       # {id: dict} del detalle
        self.stp: dict = {}              # {instancia: dict}
        self.host_cfg = ""               # running-config (AR2)
        self.version_cfg = ""
        self.vlan_cfg: dict = {}         # {id: nombre}
        self.if_cfg: list = []           # [(nombre, [subcomandos])] de interface 1/1/x y lag N
        self.svi_cfg: list = []          # [(vlan, ip/nn)]
        self.espejo_cfg: dict = {}       # {id: dict}
        self.stp_on = False
        self.stp_mode_cfg = ""

    # ---------- sistema ----------
    def system(self, cuerpo):
        for ln in cuerpo:
            ln = ln.strip()
            m = re.match(r"^Hostname\s*:\s*(\S+)", ln)
            if m:
                self.hostnames.append(m.group(1))
            m = re.match(r"^Product Name\s*:\s*(\S.*)$", ln)
            if m and not self.modelo:
                self.modelo = m.group(1).strip()
            m = re.match(r"^(?:ArubaOS-CX|AOS-CX)\s+Version\s*:\s*(\S+)", ln)
            if m and not self.version_sys:
                self.version_sys = m.group(1)

    def version(self, cuerpo):
        for ln in cuerpo:
            m = re.match(r"^\s*Version\s*:\s*(\S+)", ln)
            if m and not self.version_show:
                self.version_show = m.group(1)

    # ---------- interfaces ----------
    def _puerto(self, nombre: str) -> Puerto:
        p = self.puertos.get(nombre.lower())
        if p is None:
            p = self.puertos[nombre.lower()] = Puerto(nombre)
            self.sw.puertos.append(p)
        return p

    def interface(self, cuerpo):
        bloques, actual = [], None
        for ln in cuerpo:
            m = _RE_BLOQUE_IF.match(ln.strip())
            if m:
                actual = [m, []]
                bloques.append(actual)
            elif actual is not None:
                actual[1].append(ln.strip())
        for m, lineas in bloques:
            self._bloque(m.group(1), m.group(2).lower(), m.group(3), lineas)

    def _bloque(self, nombre, enlace, resto, lineas):
        sw = self.sw
        mv = re.match(r"^vlan(\d+)$", nombre, re.I)
        if mv:
            for ln in lineas:
                m = re.match(r"^IPv4 address\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", ln)
                if m:
                    try:
                        mascara = str(ipaddress.ip_network(f"{m.group(1)}/{m.group(2)}", strict=False).netmask)
                    except ValueError:
                        continue
                    sw.svis.append(Svi(int(mv.group(1)), m.group(1), mascara))
            return
        if not _RE_PUERTO.match(nombre):
            return
        p = self._puerto(nombre)
        self._bw = None
        admin_down = "administratively down" in resto.lower()
        l3 = False
        miembros: list = []
        modo, nativa, permitidas = "", None, ""
        vistos_modo = False
        for ln in lineas:
            m = re.match(r"^Admin state is (\w+)", ln, re.I)
            if m and m.group(1).lower() == "down":
                admin_down = True
            m = re.match(r"^Description\s*:\s*(.*)$", ln)
            if m:
                p.descripcion = m.group(1).strip().strip("'\"").strip()
            m = re.match(r"^VLAN Mode\s*:\s*(\S+)", ln, re.I)
            if m:
                vistos_modo, modo = True, m.group(1).lower()
            m = re.match(r"^Access VLAN\s*:\s*(\d+)", ln, re.I)
            if m:
                p.vlan_acceso = int(m.group(1))
            m = re.match(r"^Native VLAN\s*:\s*(\d+)", ln, re.I)
            if m:
                nativa = int(m.group(1))
            m = re.match(r"^Allowed VLAN List\s*:\s*(.*)$", ln, re.I)
            if m:
                permitidas = m.group(1).strip().lower()
            m = re.match(r"^Aggregated-interfaces\s*:\s*(.*)$", ln, re.I)
            if m:
                miembros = [x for x in re.split(r"[\s,]+", m.group(1)) if _RE_PUERTO.match(x)]
            if ln.startswith("L3 Counters"):
                l3 = True
            m = re.match(r"^Speed\s*:?\s*(\d+)\s*Mb/s", ln, re.I)
            if m and int(m.group(1)) > 0:
                self._bw = int(m.group(1)) * 1000
        p.estado = "admin down" if admin_down else enlace
        p.protocolo = enlace if enlace in ("up", "down") else ""
        p.apagado = admin_down
        if modo == "access":
            p.modo = "access"
        elif modo in ("native-untagged", "native-tagged", "trunk"):
            p.modo = "trunk"
            p.vlan_nativa = nativa
            if permitidas == "all":
                p.trunk_todas = True
            elif permitidas:
                p.vlans_trunk = rango_vlans(permitidas)
        elif not vistos_modo and l3:
            p.modo = "routed"
        if nombre.lower().startswith("lag"):
            num = int(nombre[3:])
            p.canal = num
            for mi in miembros:
                self._puerto(mi).canal = num
        self._contadores(nombre, lineas)

    def _contadores(self, nombre, lineas):
        bw, self._bw = self._bw, None
        c = Contador(puerto=nombre, bw_kbit=bw)
        hay, hr, modo, dir_ant = False, False, "", ""
        for ln in lineas:
            if _RE_STAT.match(ln):
                modo = "stat"
                continue
            if _RE_RATE.match(ln) or not ln:
                modo = ""
            if modo == "stat" and not ln.startswith("-"):
                m = re.match(r"^(.+?)\s{2,}(.*)$", ln)
                if not m:
                    continue
                etiqueta, vals = m.group(1).strip().lower(), _RE_VALORES.findall(m.group(2))
                if len(vals) < 2:
                    continue
                rx, tx = _valor(vals[0]), _valor(vals[1])
                usado = {"packets": ("paquetes", rx, "paquetes_salida", tx), "broadcast": ("broadcast", rx),
                         "errors": ("errores", rx), "crc/fcs": ("crc", rx),
                         "dropped": ("descartes", tx)}.get(etiqueta)
                if usado is None:
                    continue
                hay = True
                for campo, val in zip(usado[::2], usado[1::2]):
                    hr = hr or val[1]
                    if val[0] is not None:
                        setattr(c, campo, val[0])
                continue
            if ln in ("Rx", "Tx"):
                dir_ant, modo = ln, ""
                continue
            if dir_ant:
                for patron, campos in (
                        (r"^(\d+)\s+total packets", {"Rx": ("paquetes",), "Tx": ("paquetes_salida",)}),
                        (r"^(\d+)\s+broadcast packets", {"Rx": ("broadcast",)}),
                        (r"^(\d+)\s+errors\s+(\d+)\s+dropped", {"Rx": ("errores",), "Tx": ("errores", "descartes")}),
                        (r"^(\d+)\s+CRC/FCS", {"Rx": ("crc",)})):
                    m = re.match(patron, ln)
                    if m and dir_ant in campos:
                        hay = True
                        if patron.endswith("dropped"):
                            if dir_ant == "Rx":
                                c.errores = int(m.group(1))
                            else:
                                c.descartes = int(m.group(2))
                        else:
                            setattr(c, campos[dir_ant][0], int(m.group(1)))
        if not hay:
            return
        if hr:
            self.hr += 1
            return
        self.sw.contadores.append(c)

    def resumen_interfaces(self, cuerpo):
        """`show interface brief`: solo modo, Enabled y Status de los puertos que `show interface` no trajo."""
        en_tabla = False
        for ln in cuerpo:
            t = ln.split()
            if re.match(r"^\s*Port\s+Native\s+Mode", ln):
                en_tabla = True
                continue
            if not en_tabla or len(t) < 3 or not _RE_PUERTO.match(t[0]):
                continue
            ie = next((i for i in range(3, len(t)) if t[i].lower() in ("yes", "no")), None)
            self.brief.append((t[0], t[2].lower(), None if ie is None else t[ie].lower(),
                               t[ie + 1].lower() if ie is not None and ie + 1 < len(t) else ""))

    # ---------- VLAN y tabla MAC ----------
    def vlan(self, cuerpo):
        for ln in cuerpo:
            if not ln or ln[0].isspace() or ln.startswith("-"):
                continue
            partes = re.split(r"\s{2,}", ln.strip())
            if len(partes) >= 3 and partes[0].isdigit() and partes[2].lower() in ("up", "down"):
                self.sw.vlans[int(partes[0])] = partes[1].strip()

    def mac(self, cuerpo):
        for ln in cuerpo:
            m = _RE_MACLIN.match(ln.strip())
            if not m:
                continue
            puerto = m.group(3).split()[-1] if m.group(3).split() else ""
            if not puerto or puerto.lower().startswith("vxlan"):
                continue
            self.sw.mac.append((int(m.group(2)), mac_norm(m.group(1)), puerto))

    # ---------- vecinos ----------
    def _vecino(self, v: Vecino, chasis: str, detalle: bool):
        k = chasis.lower()
        hom = [e for e in self.vecinos if e["v"].interfaz.lower() == v.interfaz.lower()
               and ((k and e["chasis"] == k) or e["v"].id_equipo.lower() == v.id_equipo.lower())]
        if hom and not detalle:
            return
        for e in hom:
            if not e["detalle"]:
                self.vecinos.remove(e)
        self.vecinos.append({"v": v, "chasis": k, "detalle": detalle})

    def lldp(self, cuerpo):
        tabla, puerto, actual = False, "", {}

        def volcar():
            id_eq = actual.get("nombre") or actual.get("chasis") or ""
            if id_eq and puerto:
                ip = (actual.get("ip") or "").replace(",", " ").split()
                self._vecino(Vecino(id_eq, ip[0] if ip else "", (actual.get("desc") or "")[:MAX_PLATAFORMA],
                                    puerto, actual.get("puerto") or ""), _mac(actual.get("chasis") or ""), True)
            actual.clear()

        for ln in cuerpo:
            s = ln.strip()
            if re.match(r"^LOCAL-PORT\s+CHASSIS-ID", s, re.I):
                tabla = True
                continue
            if not s:
                tabla = False
                continue
            if tabla:
                self._fila_lldp(s)
                continue
            m = re.match(r"^Port\s*:\s*(\S+)", s)
            if m:
                volcar()
                puerto = m.group(1)
                continue
            if s.startswith("-----"):
                volcar()
                continue
            for campo, rx in _RE_LLDP_CAMPO:
                m = rx.match(s)
                if m:
                    if campo in actual or (campo == "nombre" and actual):
                        volcar()
                    actual[campo] = m.group(1).strip()
                    break
        volcar()

    def _fila_lldp(self, s):
        p = re.split(r"\s{2,}", s)
        if len(p) < 4 or not p[0].strip() or s.startswith("-"):
            return
        if len(p) >= 6:
            nombre, medio = p[-1], p[2:-2]
        elif p[-1].isdigit():
            nombre, medio = "", p[2:-1]
        else:
            nombre, medio = p[-1], p[2:-2]
        self._vecino(Vecino(nombre or p[1], "", "", p[0], medio[0] if medio else ""), _mac(p[1]), False)

    def cdp(self, cuerpo):
        tabla, actual = False, {}

        def volcar():
            if actual.get("id") and actual.get("local"):
                self._vecino(Vecino(actual["id"], actual.get("ip", ""), actual.get("plat", "")[:MAX_PLATAFORMA],
                                    actual["local"], actual.get("puerto", "")), "", True)
            actual.clear()

        for ln in cuerpo:
            s = ln.strip()
            if re.match(r"^Port\s+Device ID", s, re.I):
                tabla = True
                continue
            if not s:
                tabla = False
                continue
            if tabla and not s.startswith("-"):
                p = re.split(r"\s{2,}", s)
                if len(p) >= 2 and _RE_PUERTO.match(p[0]):
                    self._vecino(Vecino(p[1], "", p[2][:MAX_PLATAFORMA] if len(p) >= 4 else "", p[0], ""),
                                 "", False)
                continue
            m = re.match(r"^Local Port\s*:\s*(\S+)", s)
            if m:
                volcar()
                actual["local"] = m.group(1)
                continue
            for clave, rx in (("id", r"^Device ID\s*:\s*(.*)$"), ("ip", r"^Address\s*:\s*(\S+)"),
                              ("plat", r"^Platform\s*:\s*(.*)$"), ("puerto", r"^Neighbor Port-ID\s*:\s*(.*)$")):
                m = re.match(rx, s)
                if m:
                    actual[clave] = m.group(1).strip()
        volcar()

    # ---------- running-config (AR2, D99) ----------
    def _contar(self, clave: str):
        c = self.sw.credenciales
        c[clave] = c.get(clave, 0) + 1

    def config(self, cuerpo):
        """Lee la running-config. De las lineas con secretos solo se cuenta cuantas hay: nunca se guarda ni se
        cita el valor, el usuario ni la linea."""
        bloques = []
        for ln in cuerpo:
            s = ln.strip()
            if not s:
                continue
            if s.startswith("!"):
                m = _RE_CFG_VERSION.match(s)
                if m and not self.version_cfg:
                    self.version_cfg = m.group(1)
            elif ln[0].isspace():
                if bloques:
                    bloques[-1][1].append(s)
            else:
                bloques.append((s, []))
        if not bloques:
            return
        self.sw.config = True
        for cab, subs in bloques:
            self._cfg_bloque(cab, subs)

    def _syslog(self, p, w):
        """`logging <ip|nombre> [...] [severity <nivel>]`: solo destino y severidad; el resto de la linea
        (puerto, VRF, transporte, certificados) no se copia. `logging facility ...` y similares no son destinos."""
        d = destino_syslog(p[1])
        if not d or not (_RE_IP.fullmatch(d) or "." in d):
            return
        if d not in self.sw.syslog_destinos:
            self.sw.syslog_destinos.append(d)
        if "severity" in w[:-1]:
            n = nivel_syslog(w[w.index("severity") + 1])
            niveles = [x for x in self.sw.syslog_nivel.split("; ") if x]
            if n and n not in niveles:
                self.sw.syslog_nivel = "; ".join(niveles + [n])

    def _cfg_bloque(self, cab, subs):
        sw = self.sw
        p = cab.split()
        w = [x.lower() for x in p]
        if w[0] == "hostname" and len(p) >= 2:
            self.host_cfg = self.host_cfg or p[1]
        elif w[0] == "user":
            self._contar("usuario_local")
        elif w[:2] == ["snmpv3", "user"]:
            self._contar("snmpv3_usuario")
        elif w[:2] == ["snmp-server", "community"]:
            self._contar("snmp_community")
            if any(re.match(r"^access-level\s+rw$", x, re.I) for x in subs):
                self._contar("snmp_rw")
        elif w[:2] == ["ntp", "server"]:
            sw.ntp_servidores += 1
        elif w[0] == "logging" and len(p) >= 2:
            self._syslog(p, w)
        elif w[:4] == ["aaa", "authentication", "login", "default"]:
            if any(x == "group" and w[i + 1] != "local" for i, x in enumerate(w[:-1])):
                sw.aaa_modelo = True
        elif w[:2] in (["tacacs-server", "host"], ["radius-server", "host"]):
            sw.servidores_aaa += 1
        elif w[:2] == ["https-server", "vrf"]:
            sw.http = "https"
        elif w[:3] == ["ssh", "server", "vrf"]:
            sw.vty_transport = ["ssh"]
        elif w == ["spanning-tree"]:
            self.stp_on = True
        elif w[:2] == ["spanning-tree", "mode"] and len(w) == 3:
            self.stp_mode_cfg = w[2]
        elif w[0] == "vlan" and len(p) == 2:
            for v in rango_vlans(p[1]):
                self.vlan_cfg.setdefault(v, "")
            nombre = next((x[5:].strip() for x in subs if x.startswith("name ")), "")
            if nombre and p[1].isdigit():
                self.vlan_cfg[int(p[1])] = nombre
        elif w[0] == "interface" and len(p) >= 2:
            if w[1] == "vlan" and len(p) >= 3 and p[2].isdigit():
                for x in subs:
                    m = re.match(r"^ip address\s+(\d+\.\d+\.\d+\.\d+/\d+)\s*$", x)
                    if m:
                        self.svi_cfg.append((int(p[2]), m.group(1)))
            elif w[1] == "lag" and len(p) >= 3 and p[2].isdigit():
                self.if_cfg.append(("lag" + p[2], subs))
            elif _RE_PUERTO.match(p[1]):
                self.if_cfg.append((p[1], subs))
        elif w[:2] == ["mirror", "session"] and len(p) >= 3 and p[2].isdigit():
            self._cfg_espejo(int(p[2]), subs)

    def _cfg_espejo(self, num, subs):
        d = self.espejo_cfg[num] = {"enable": False, "vlans": [], "ifs": [], "destino": ""}
        for s in subs:
            if s.lower() == "enable":
                d["enable"] = True
            m = re.match(r"^source\s+interface\s+(\S+)\s+(?:rx|tx|both)\b", s, re.I)
            if m:
                d["ifs"].append(m.group(1))
            m = re.match(r"^source\s+vlan\s+(\d[\d,\-]*)\s+(?:rx|tx|both)\b", s, re.I)
            if m:
                d["vlans"] += rango_vlans(m.group(1))
            m = re.match(r"^destination\s+(interface|tunnel)\s+(\S+)", s, re.I)
            if m:
                d["destino"] = m.group(2) if m.group(1).lower() == "interface" else "tunnel " + m.group(2)
            elif re.match(r"^destination\s+cpu\b", s, re.I):
                d["destino"] = "cpu"

    def aplicar_config(self):
        """Puertos, SVI y VLAN de la running-config sobre lo que dejo `show`: el modo de la config gana."""
        sw = self.sw
        for nombre, subs in self.if_cfg:
            self._cfg_puerto(nombre, subs)
        for vlan, cidr in self.svi_cfg:
            try:
                red = ipaddress.ip_interface(cidr)
            except ValueError:
                continue
            ip = str(red.ip)
            if not any(s.vlan == vlan and s.ip == ip for s in sw.svis):
                sw.svis.append(Svi(vlan, ip, str(red.network.netmask)))
        for vid, nombre in self.vlan_cfg.items():
            if not sw.vlans.get(vid):
                sw.vlans[vid] = nombre

    def _cfg_puerto(self, nombre, subs):
        p = self._puerto(nombre)
        p.en_config = True
        vlan_acc = nativa = miembro = None
        todas, perm, trunk = False, set(), False
        routed = no_routing = False
        for s in subs:
            m = re.match(r"^description\s+(.+)$", s)
            if m:
                p.descripcion = m.group(1).strip()
            elif s == "shutdown":
                p.apagado, p.estado = True, "admin down"
            elif re.match(r"^lag\s+\d+$", s):
                miembro = int(s.split()[1])
            elif re.match(r"^vlan\s+access\s+\d+\b", s):
                vlan_acc = int(s.split()[2])
            elif re.match(r"^vlan\s+trunk\s+native\s+\d+\b", s):
                trunk, nativa = True, int(s.split()[3])
            elif re.match(r"^vlan\s+trunk\s+allowed\s+\S", s):
                trunk = True
                lista = s.split(None, 3)[3].strip()
                if lista.lower() == "all":
                    todas = True
                else:
                    perm.update(rango_vlans(lista))
            elif s == "routing" or re.match(r"^ip address\s", s):
                routed = True
            elif s == "no routing":
                no_routing = True
            elif s == "spanning-tree bpdu-guard":
                p.bpduguard = True
            elif s == "spanning-tree port-type admin-edge":
                p.portfast = True
            elif s == "spanning-tree root-guard":
                p.root_guard = True
        if nombre.lower().startswith("lag"):
            p.canal = int(nombre[3:])
        if miembro is not None:
            p.canal = miembro
        if vlan_acc is not None:
            p.modo, p.vlan_acceso = "access", vlan_acc
        elif trunk:
            p.modo = "trunk"
            if nativa is not None:
                p.vlan_nativa = nativa
            if todas:
                p.trunk_todas, p.vlans_trunk = True, []
            elif perm:
                p.trunk_todas, p.vlans_trunk = False, sorted(perm)
        elif miembro is not None:
            return                      # miembro de un LAG: sin VLAN propia
        elif routed:
            p.modo = "routed"
        elif no_routing:
            p.modo, p.vlan_acceso = "access", 1       # defecto de AOS-CX: VLAN 1
        if p.modo in ("access", "trunk"):
            p.modo_explicito, p.dtp = True, ""        # AOS-CX no negocia troncales

    # ---------- espejo ----------
    def mirror(self, cuerpo):
        actual = None
        for ln in cuerpo:
            s = ln.strip()
            if re.match(r"^ID\s+Admin Status", s, re.I):
                self.resumen_visto = True
                continue
            m = re.match(r"^(\d+)\s+(enable|disable)\s+(\S+)", s, re.I)
            if m:
                self.espejo_res[int(m.group(1))] = (m.group(2).lower(), m.group(3).lower())
                continue
            m = re.match(r"^Mirror Session\s*:\s*(\d+)", s, re.I)
            if m:
                actual = self.espejo_det[int(m.group(1))] = {"admin": "", "op": "", "vlans": [], "ifs": [],
                                                              "destino": ""}
                continue
            if actual is None:
                continue
            m = re.match(r"^(Admin|Operation) Status\s*:\s*(\S+)", s, re.I)
            if m:
                actual["admin" if m.group(1).lower() == "admin" else "op"] = m.group(2).lower()
                continue
            m = re.match(r"^Source\s*:\s*interface\s+(\S+)\s+(?:rx|tx|both)\b", s, re.I)
            if m:
                actual["ifs"] += [x for x in m.group(1).split(",") if x]
                continue
            m = re.match(r"^Source\s*:\s*vlan\s+(\d[\d,\-]*)\s+(?:rx|tx|both)\b", s, re.I)
            if m:
                actual["vlans"] += rango_vlans(m.group(1))
                continue
            m = re.match(r"^Destination\s*:\s*(.*)$", s, re.I)
            if m:
                d = m.group(1).split()
                if len(d) >= 2 and d[0].lower() == "interface":
                    actual["destino"] = d[1]
                elif len(d) >= 2 and d[0].lower() == "tunnel":
                    actual["destino"] = "tunnel " + d[1]
                elif d and d[0].lower() == "cpu":
                    actual["destino"] = "cpu"

    def cerrar_espejo(self):
        """Arma `sw.span` y decide si el espejo se leyo ("espejo" en `leyo`)."""
        sw = self.sw
        falta = []
        if not self.espejo_det:       # sin `show mirror <id>`: la running-config, solo sesiones con enable
            for i, d in sorted(self.espejo_cfg.items()):
                res = self.espejo_res.get(i)
                if res is not None and res != ("enable", "enabled"):
                    continue          # el estado operativo del resumen manda
                if d["enable"]:
                    self.espejo_det[i] = {"admin": "enable", "op": "enabled", "vlans": d["vlans"],
                                          "ifs": d["ifs"], "destino": d["destino"]}
                else:
                    sw.avisos.append(f"sesion de espejo {i} de la running-config sin enable: no se cuenta")
        for i in sorted(self.espejo_det):
            d = self.espejo_det[i]
            if d["admin"] == "enable" and d["op"] == "enabled":
                sw.span.append(SesionSpan(i, sorted(set(d["vlans"])), list(dict.fromkeys(d["ifs"])), d["destino"]))
            else:
                sw.avisos.append(f"sesion de espejo {i} sin efecto (admin {d['admin'] or '?'}, "
                                 f"operacion {d['op'] or '?'})")
        for i, (admin, op) in sorted(self.espejo_res.items()):
            if i in self.espejo_det or admin != "enable":
                continue
            if op == "enabled":
                falta.append(i)
                sw.avisos.append(f"falta show mirror {i}: el espejo de sus VLAN es desconocido")
            else:
                sw.avisos.append(f"sesion de espejo {i} sin efecto (admin {admin}, operacion {op})")
        if (self.espejo_det or self.espejo_res or self.resumen_visto) and not falta:
            sw.leyo.append("espejo")
        elif not falta:
            sw.avisos.append("sin show mirror: el espejo de las VLAN es desconocido")

    # ---------- spanning-tree ----------
    def stp_leer(self, cuerpo):
        cur, ctx = None, ""
        for ln in cuerpo:
            s = ln.strip()
            m = re.match(r"^(?:#+\s*)?(MST\d+|VLAN\d+)\s*$", s, re.I)
            if m:
                cur = self.stp.setdefault(m.group(1).upper(), {})
                ctx = ""
                continue
            if cur is None:
                continue
            if re.search(r"\bRoot ID\b", s, re.I):
                ctx = "root"
            elif re.search(r"\bBridge ID\b", s, re.I):
                ctx = "bridge"
            if re.search(r"This bridge is the root", s, re.I):
                cur["raiz"] = "local"
            m = re.search(r"\bPriority\s*:\s*(\d+)(,\s*Root)?", s)
            if m and ctx == "root" and m.group(2):
                cur["raiz"] = "local"
            elif m and (ctx == "bridge" or (not ctx and s.startswith("Priority"))):
                cur.setdefault("prio", int(m.group(1)))
            m = re.search(r"\bMAC-Address\s*:\s*(\S+)", s)
            if m and ctx:
                cur["raiz_mac" if ctx == "root" else "puente"] = _mac(m.group(1))
            m = re.match(r"^Bridge\s+Address\s*:\s*(\S+)(?:\s+Priority\s*:\s*(\d+))?", s)
            if m:
                cur["puente"] = _mac(m.group(1))
                if m.group(2):
                    cur["prio"] = int(m.group(2))
            m = re.match(r"^Root\s+Address\s*:\s*(\S+)", s)
            if m:
                cur["raiz_mac"] = _mac(m.group(1))
            if s == "Root":
                cur["raiz_marca"] = True
            m = re.match(r"^Number of topology changes\s*:\s*(\d+)", s, re.I)
            if m:
                cur["cambios"] = int(m.group(1))
            m = re.match(r"^Last topology change occurred\s*:\s*(\d+)\s*seconds?\s+ago", s, re.I)
            if m:
                cur["hace"] = int(m.group(1))

    def cerrar_stp(self):
        for inst, d in self.stp.items():
            if not d:
                continue
            raiz = d.get("raiz", "")
            if not raiz and d.get("raiz_mac") and d.get("raiz_mac") == d.get("puente"):
                raiz = "local"
            if not raiz and d.get("raiz_mac"):
                raiz = d["raiz_mac"]
            if not raiz and d.get("raiz_marca"):
                raiz = "local"
            self.sw.stp.append(CambioStp(inst, d.get("cambios", 0), d.get("hace"), "", raiz, d.get("prio"),
                                         d.get("puente", "")))
        if self.sw.stp:
            self.sw.leyo.append("stp")


def leer(texto: str, nombre: str = "") -> Switch:
    """Sesion guardada de AOS-CX -> Switch. `nombre` (archivo) da el hostname si no hay otro."""
    sw = Switch(archivo=nombre, origen="aoscx")
    lec = _Lector(sw)
    secs, hosts, hubo = _secciones(_limpiar(texto))
    if not hubo and not secs:
        sw.avisos.append("no se reconocio salida de CLI de AOS-CX (sin prompts)")
    despacho = {"system": lec.system, "version": lec.version, "interface": lec.interface,
                "brief": lec.resumen_interfaces, "vlan": lec.vlan, "mac": lec.mac, "lldp": lec.lldp,
                "cdp": lec.cdp, "mirror": lec.mirror, "stp": lec.stp_leer, "config": lec.config}
    leidas = 0
    for cmd, cuerpo in secs:
        clase = _clase(cmd)
        if clase is None:
            continue
        if any(ln.strip() for ln in cuerpo):
            bajo = " ".join(ln.strip().lower() for ln in cuerpo[:3])
            if "invalid input" in bajo or "unknown command" in bajo or "incomplete command" in bajo \
                    or bajo.startswith("%"):
                sw.avisos.append("el equipo devolvio error a un comando (" + clase + ")")
                continue
            leidas += 1
        despacho[clase](cuerpo)
    if lec.hr:
        sw.avisos.append(f"contadores en formato human-readable en {lec.hr} puertos: no se usan; "
                         "use show interface sin human-readable")
    # show interface brief: solo lo que show interface no trajo
    for pto, modo, enabled, estado in lec.brief:
        if pto.lower() in lec.puertos:
            continue
        p = lec._puerto(pto)
        p.modo = "access" if modo == "access" else "trunk" if modo in (
            "trunk", "native-untagged", "native-tagged") else "routed" if modo == "routed" else ""
        p.apagado = enabled == "no"
        p.estado = "admin down" if p.apagado else (estado if estado in ("up", "down") else "")
        p.protocolo = estado if estado in ("up", "down") else ""
    if sw.contadores:
        sw.leyo.append("interfaces")
    if sw.config:
        lec.aplicar_config()
        vivo = [k for k, d in lec.stp.items() if d]     # instancias en show spanning-tree: STP corre
        if not lec.stp_on and not vivo:
            sw.stp_modo = "deshabilitado"      # sin la linea `spanning-tree` (AOS-CX lo trae apagado)
        elif lec.stp_mode_cfg == "rpvst" or any(k.startswith("VLAN") for k in vivo):
            sw.stp_modo = "rapid-pvst"
        else:
            sw.stp_modo = "mst"
    lec.cerrar_stp()
    lec.cerrar_espejo()
    sw.cdp = [e["v"] for e in lec.vecinos]
    if len(set(lec.hostnames)) > 1:
        sw.avisos.append("show system trae hostnames distintos (dos equipos en el archivo); se usa el primero")
    elif len(set(hosts)) > 1:
        sw.avisos.append("el archivo mezcla sesiones de varios equipos; se lee como uno solo")
    if lec.hostnames and lec.host_cfg and lec.host_cfg != lec.hostnames[0]:
        sw.avisos.append(f"el hostname de show system ({lec.hostnames[0]}) y el de la running-config "
                         f"({lec.host_cfg}) difieren; se usa el de show system")
    sw.hostname = ((lec.hostnames[0] if lec.hostnames else "") or lec.host_cfg or (hosts[0] if hosts else "")
                   or Path(nombre).stem)
    sw.modelo = lec.modelo
    sw.version = lec.version_show or lec.version_sys or lec.version_cfg
    for _v, _m, pto in sw.mac:
        if pto.lower() not in lec.puertos and _RE_PUERTO.match(pto):
            lec._puerto(pto)
    if not leidas:
        sw.avisos.append("el archivo no trae ninguna de las salidas que se leen (show system, show interface, "
                         "show vlan, show mac-address-table, show lldp neighbor-info, show mirror, "
                         "show spanning-tree, show running-config)")
    return sw


def leer_archivo(ruta) -> Switch:
    p = Path(ruta)
    return leer(p.read_text(encoding="utf-8", errors="replace"), p.name)
