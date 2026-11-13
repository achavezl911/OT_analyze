"""Lector de la CLI de un switch Cisco IOS / IOS-XE (SW1a) hacia el modelo comun de switch.

Entrada: sesion de terminal pegada (prompts `host# show ...`, comandos abreviados incluidos) o un
bloque sin prompts con un running-config.
Se leen solo: show running-config, show ip interface brief, show mac address-table,
show interfaces description, show cdp neighbors detail, show inventory, show version y, para el estado de
capa 2 (SW2), show spanning-tree detail, show logging, show interfaces y show interfaces counters errors
(del log solo MAC flapping y err-disable; de los contadores, paquetes, broadcast y errores). Cualquier otra
seccion, y toda linea de la configuracion que no sea de las reconocidas, se descarta sin copiarse.
SEGURIDAD: de usuarios, contrasenas (tipo 0/7), secretos (5/8/9), enable password/secret, comunidades SNMP,
llaves AAA y certificados PKI solo se cuenta cuantos hay por tipo; el valor y el nombre de usuario no se
guardan en ningun campo, ni siquiera en los avisos. El numero de serie tampoco se guarda.
Formato de salida de cada comando: basado en una sesion real de un C9200L (IOS-XE 17.15); otros
modelos o versiones pueden variar.
"""
from __future__ import annotations

import re
from pathlib import Path

from .modelo import (
    CambioStp,
    Contador,
    Puerto,
    PuertoStp,
    SesionSpan,
    Svi,
    Switch,
    Vecino,
    destino_syslog,
    nivel_syslog,
)

FABRICANTE = "Cisco IOS/IOS-XE"
MAX_VLAN = 4094

_COMPLETOS = ("gigabitethernet", "tengigabitethernet", "fastethernet", "port-channel", "twentyfivegige",
              "twogigabitethernet", "fortygigabitethernet", "hundredgige", "ethernet", "vlan", "loopback",
              "tunnel", "appgigabitethernet")
_ABREV = {"gi": "gigabitethernet", "gig": "gigabitethernet", "te": "tengigabitethernet",
          "ten": "tengigabitethernet", "fa": "fastethernet", "po": "port-channel", "twe": "twentyfivegige",
          "tw": "twogigabitethernet", "fo": "fortygigabitethernet", "hu": "hundredgige",
          "eth": "ethernet", "et": "ethernet", "vl": "vlan", "lo": "loopback"}

_RE_IP = re.compile(r"(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]*:[0-9A-Fa-f:.]*)")
_RE_ANSI =re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_RE_MORE = re.compile(r"(?:<-+\s*More\s*-+>|-+\s*More\s*-+)\s*")
_RE_PROMPT = re.compile(r"^(?P<host>[\w.\-]*)(?:\([^)]*\))?[#>]\s*(?P<cmd>.*)$")
_RE_IF = re.compile(r"^([A-Za-z][A-Za-z\-]*?)\s*(\d[\d/.:]*)$")
_RE_DIR = re.compile(r"\s+(?:rx|tx|both)\s*$", re.I)
_RE_MACROW = re.compile(
    r"^\s*(?P<vlan>\d+|all)\s+(?P<mac>[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+(?P<tipo>\w+)\s+"
    r"(?:\S+\s+)*?(?P<puerto>\S+)\s*$", re.I)
_RE_BRIEF = re.compile(
    r"^(?P<if>[A-Za-z][\w\-./:]*)\s+(?P<ip>\S+)\s+(?:YES|NO)\s+\S+\s+"
    r"(?P<st>administratively down|up|down|deleted)\s+(?P<pr>up|down)\s*$", re.I)
_RE_DESC = re.compile(
    r"^(?P<if>[A-Za-z][\w\-./:]*\d)\s+(?P<st>admin down|up|down|deleted|err-disabled)\s+"
    r"(?P<pr>up|down)\s*(?P<d>.*)$", re.I)
_RE_USER = re.compile(r"^username\s+\S+\s+.*?\b(password|secret)\s+(?:(\d)\s+)?\S+", re.I)
_RE_ENABLE = re.compile(r"^enable\s+(password|secret)\s+(?:level\s+\d+\s+)?(?:(\d)\s+)?\S+", re.I)
_RE_AAA_G = re.compile(r"^(?:tacacs-server|radius-server)\b.*\bkey\s+(?:(\d)\s+)?\S+", re.I)
_RE_KEY = re.compile(r"^key\s+(?:(\d)\s+)?\S+", re.I)
_RE_PASS = re.compile(r"^password\s+(?:(\d)\s+)?\S+", re.I)


_RE_STP_INST = re.compile(r"^\s*(VLAN\d+|MST\d+)\s+is executing", re.I)
_RE_STP_CAMBIOS = re.compile(
    r"Number of topology changes\s+(\d+)\s+last change occurred\s+(\S+)\s+ago(?:\s+from\s+(\S+))?", re.I)
_RE_STP_FROM = re.compile(r"^\s*from\s+(\S+)\s*$", re.I)
_RE_STP_RAIZ = re.compile(r"Current root has priority\s+\d+,\s+address\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})", re.I)
_RE_STP_PUENTE = re.compile(
    r"Bridge Identifier has priority\s+(\d+),.*?address\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})", re.I)
_RE_STP_PTO = re.compile(r"^\s*Port\s+(\d+)\s+\(([^)]+)\)\s+of\s+(\S+)\s+is\s+(.+?)\s*$", re.I)
_RE_STP_DESIG = re.compile(r"Designated bridge has priority\s+\d+,\s+address\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})",
                           re.I)
_RE_STP_DESIG_PTO = re.compile(r"Designated port id is\s+\d+\.(\d+)", re.I)
_RE_STP_BPDU = re.compile(r"BPDU:\s*sent\s+\d+,\s*received\s+(\d+)", re.I)
_RE_LOG_FECHA = re.compile(r"^(?:\d+:\s+)?([*.]?)[A-Z][a-z]{2}\s+\d{1,2}\s+(?:\d{4}\s+)?\d\d:\d\d:\d\d")
_RE_UNIDAD =re.compile(r"(\d+)([ywdhms])")
_SEG = {"y": 31536000, "w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
_RE_FLAP = re.compile(r"MACFLAP|MAC_MOVE|flapping between port", re.I)
_RE_FLAP_MAC = re.compile(r"Host\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})", re.I)
_RE_FLAP_VLAN = re.compile(r"in vlan\s+(\d+)", re.I)
_RE_FLAP_PTOS = re.compile(r"between port\s+(\S+)\s+and port\s+(\S+)", re.I)
_RE_ERRDIS = re.compile(r"ERR_DISABLE:\s*(\S+)\s+error detected on\s+([^\s,]+)", re.I)
_RE_BPDUG = re.compile(r"BLOCK_BPDUGUARD:.*?\bport\s+([^\s,]+)", re.I)
_RE_STORM = re.compile(r"STORM_CONTROL-\d-SHUTDOWN:.*?\bon\s+([^\s,.]+)", re.I)
_RE_IF_HDR = re.compile(r"^([A-Za-z][\w\-./:]*\d) is [\w\- ]+?, line protocol is", re.I)
_RE_SKIP_IF = re.compile(r"(?:vlan|vl|loopback|lo|tunnel|null|nve)\d", re.I)


def duracion_s(txt: str):
    """`00:10:23`, `1d02h`, `2w3d` -> segundos; None si no se reconoce."""
    m = re.fullmatch(r"(\d+):(\d+):(\d+)", txt.strip())
    if m:
        return int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3))
    piezas = _RE_UNIDAD.findall(txt.strip().lower())
    if not piezas or "".join(n + u for n, u in piezas) != txt.strip().lower():
        return None
    return sum(int(n) * _SEG[u] for n, u in piezas)


def clave_if(nombre: str) -> str:
    """Nombre de interfaz canonico para comparar `Gi1/0/1` con `GigabitEthernet1/0/1`."""
    m = _RE_IF.match((nombre or "").strip())
    if not m:
        return (nombre or "").strip().lower()
    letras, num = m.group(1).lower(), m.group(2)
    full = _ABREV.get(letras) or next((f for f in _COMPLETOS if f.startswith(letras)), letras)
    return full + num


def mac_norm(txt: str) -> str:
    """aaaa.bbbb.cccc / AA-BB-.. -> aa:bb:cc:dd:ee:ff; '' si no es una MAC."""
    h = re.sub(r"[^0-9a-f]", "", (txt or "").lower())
    if len(h) != 12 or len(re.sub(r"[0-9a-f:.\-]", "", (txt or "").lower())) != 0:
        return ""
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def rango_vlans(txt: str) -> list:
    """`4 , 31 - 42`, `410,411`, `70,72,100,110-111` -> [ints] ordenados y sin repetir."""
    txt = re.sub(r"\s*([,\-])\s*", r"\1", _RE_DIR.sub("", txt.strip()))
    out: set = set()
    for pieza in txt.split(","):
        m = re.fullmatch(r"(\d+)(?:-(\d+))?", pieza.strip())
        if not m:
            continue
        a = int(m.group(1))
        b = int(m.group(2)) if m.group(2) else a
        if 0 < a <= b <= MAX_VLAN:
            out.update(range(a, b + 1))
    return sorted(out)


def _interfaces(txt: str) -> list:
    """`Gi1/0/1 - 3 , Gi1/0/5 both` -> ['Gi1/0/1', 'Gi1/0/2', 'Gi1/0/3', 'Gi1/0/5']."""
    txt = re.sub(r"\s*([,\-])\s*", r"\1", _RE_DIR.sub("", txt.strip()))
    out = []
    for pieza in txt.split(","):
        pieza = _RE_DIR.sub("", pieza.strip())
        if not pieza:
            continue
        m = re.match(r"^(.*?)(\d+)-(?:[^\d]*?[\d/]*/)?(\d+)$", pieza)
        if m and int(m.group(2)) <= int(m.group(3)) <= int(m.group(2)) + 255:
            out.extend(m.group(1) + str(i) for i in range(int(m.group(2)), int(m.group(3)) + 1))
        else:
            out.append(pieza)
    return out


def _limpiar(texto: str) -> list:
    texto = _RE_ANSI.sub("", texto.replace("\x08", "")).replace("\r\n", "\n").replace("\r", "\n")
    return [_RE_MORE.sub("", ln).rstrip() for ln in texto.split("\n")]


def _secciones(lineas: list) -> tuple:
    """([(comando, lineas)], hostnames, hubo_prompt). Lo anterior al primer prompt se descarta."""
    secs, hosts, actual, hubo = [], [], None, False
    for ln in lineas:
        m = _RE_PROMPT.match(ln)
        if m:
            hubo = True
            if m["host"]:
                hosts.append(m["host"])
            cmd = m["cmd"].strip()
            actual = [cmd, []] if cmd else None
            if actual:
                secs.append(actual)
        elif actual is not None:
            actual[1].append(ln)
    return secs, hosts, hubo


def _pre(w: str, completo: str, minimo: int) -> bool:
    return len(w) >= minimo and completo.startswith(w)


def _clase(cmd: str):
    """Clase de parser de un comando (admite abreviaturas y `| filtro`); None = se ignora."""
    p = cmd.lower().split()
    if "|" in p:
        p = p[:p.index("|")]
    if len(p) < 2 or not (p[0] in ("sh", "sho") or _pre(p[0], "show", 2)):
        return None
    a = p[1]
    if _pre(a, "running-config", 2):
        return "config"
    if a == "ip" and len(p) >= 4 and _pre(p[2], "interface", 3) and _pre(p[3], "brief", 2):
        return "brief"
    if a == "mac-address-table" or (a == "mac" and len(p) >= 3 and _pre(p[2], "address-table", 3)):
        return "mac"
    if _pre(a, "interfaces", 3) and len(p) >= 3 and _pre(p[2], "description", 4):
        return "desc"
    if a == "cdp" and len(p) >= 4 and _pre(p[2], "neighbors", 3) and _pre(p[3], "detail", 3):
        return "cdp"
    if _pre(a, "spanning-tree", 3) and any(_pre(x, "detail", 3) for x in p[2:]):
        return "stp"
    if _pre(a, "logging", 3) and len(p) == 2:
        return "logging"
    if _pre(a, "interfaces", 3) and len(p) == 2:
        return "interfaces"
    if _pre(a, "interfaces", 3) and len(p) >= 3:
        if p[2] == "counters":
            return "errores" if len(p) >= 4 and _pre(p[3], "errors", 3) else None
        if re.match(r"^[a-z][a-z\-]*\d", p[2]):             # show interfaces gi1/0/1
            return "interfaces"
    if _pre(a, "inventory", 3):
        return "inventario"
    if _pre(a, "version", 3):
        return "version"
    return None


class _Lector:
    def __init__(self, sw: Switch):
        self.sw = sw
        self.idx: dict = {}              # clave_if -> Puerto
        self.explicito: set = set()      # puertos con lista trunk explicita
        self.cont: dict = {}             # clave_if -> Contador
        self.modelo_inv = ""
        self.modelo_ver = ""
        self.http_srv = self.http_seg = False
        self.leyo_config = False
        self.version_cfg = ""

    # ---------- utilidades ----------
    def contar(self, clave: str, n: int = 1) -> None:
        self.sw.credenciales[clave] = self.sw.credenciales.get(clave, 0) + n

    def tipo(self, tipo, secreto: bool) -> None:
        """Cuenta el tipo de una credencial (jamas su valor)."""
        if secreto:
            self.contar("secret" + (tipo or "0"))
        else:
            self.contar("tipo7" if tipo == "7" else "tipo0" if tipo in (None, "0") else "tipo" + tipo)

    def puerto(self, nombre: str, crear: bool = True):
        k = clave_if(nombre)
        p = self.idx.get(k)
        if p is None and crear:
            p = Puerto(nombre)
            self.idx[k] = p
            self.sw.puertos.append(p)
        return p

    def sesion(self, n: int) -> SesionSpan:
        s = next((x for x in self.sw.span if x.id == n), None)
        if s is None:
            s = SesionSpan(n)
            self.sw.span.append(s)
        return s

    # ---------- running-config ----------
    def config(self, lineas: list) -> None:
        self.leyo_config = True
        ctx = None
        en_cert = en_cadena = False
        delim = None
        for ln in lineas:
            s = ln.strip()
            if delim is not None:                       # dentro de un banner: se descarta
                if delim in ln:
                    delim = None
                continue
            if en_cert:                                 # cuerpo hexadecimal de un certificado
                en_cert = s != "quit"
                continue
            if not s:
                continue
            sangria = ln[0] in " \t"
            if en_cadena:
                if s.startswith("certificate "):
                    self.contar("certificado_pki")
                    en_cert = True
                    continue
                if sangria:
                    continue
                en_cadena = False
            if not sangria:
                ctx = None
                if s.startswith("!"):
                    continue
                if s.lower().startswith("crypto pki certificate chain"):
                    en_cadena = True
                    continue
                m = re.match(r"^banner\s+\S+\s+(\^C|\S)", s)
                if m:
                    delim = m.group(1)
                    resto = s[m.end():]
                    if delim in resto:
                        delim = None
                    continue
                ctx = self.superior(s)
            else:
                self.interior(ctx, s)
        self.cerrar_config()

    def superior(self, s: str):
        sw = self.sw
        m = re.match(r"^hostname\s+(\S+)", s, re.I)
        if m:
            sw.hostname = m.group(1)
            return None
        m = re.match(r"^version\s+(\S+)", s, re.I)
        if m:
            self.version_cfg = m.group(1)
            return None
        m = re.match(r"^vlan\s+([\d,\-\s]+)$", s, re.I)
        if m:
            ids = rango_vlans(m.group(1))
            for i in ids:
                sw.vlans.setdefault(i, "")
            return ("vlan", ids)
        m = re.match(r"^interface\s+(\S+)", s, re.I)
        if m:
            nombre = m.group(1)
            mv = re.fullmatch(r"vlan(\d+)", nombre, re.I)
            if mv:
                return ("svi", int(mv.group(1)))
            if re.match(r"(loopback|tunnel|null|range|nve|bdi)", nombre, re.I):
                return None
            p = self.puerto(nombre)
            p.en_config = True
            return ("if", p)
        m = re.match(r"^monitor\s+session\s+(\d+)\s*(.*)$", s, re.I)
        if m:
            n = int(m.group(1))
            self.sesion(n)
            if m.group(2):
                self.span(n, m.group(2))
            return ("monitor", n)
        if re.match(r"^no\s+ip\s+http\s+server", s, re.I):
            self.http_srv = False
        elif re.match(r"^ip\s+http\s+server", s, re.I):
            self.http_srv = True
        elif re.match(r"^no\s+ip\s+http\s+secure-server", s, re.I):
            self.http_seg = False
        elif re.match(r"^ip\s+http\s+secure-server", s, re.I):
            self.http_seg = True
        m = re.match(r"^line\s+(con|vty|aux)", s, re.I)
        if m:
            return ("line", m.group(1).lower() == "vty")
        if re.match(r"^(tacacs|radius)\s+server\s+\S+", s, re.I):
            self.sw.servidores_aaa += 1
            return ("aaa",)
        if re.match(r"^(tacacs|radius)-server\s+host\s+\S+", s, re.I):
            self.sw.servidores_aaa += 1
        elif re.match(r"^no\s+aaa\s+new-model\b", s, re.I):
            self.sw.aaa_modelo = False
        elif re.match(r"^aaa\s+new-model\b", s, re.I):
            self.sw.aaa_modelo = True
        self.credencial_global(s)
        self.control_global(s)
        return None

    def control_global(self, s: str) -> None:
        """Controles de capa 2 globales: STP, DHCP snooping, DAI, UDLD."""
        sw = self.sw
        m = re.match(r"^spanning-tree\s+mode\s+(pvst|rapid-pvst|mst)\b", s, re.I)
        if m:
            sw.stp_modo = m.group(1).lower()
        elif re.match(r"^spanning-tree\s+loopguard\s+default\b", s, re.I):
            sw.stp_loopguard = True
        elif re.match(r"^spanning-tree\s+portfast(?:\s+edge)?\s+bpduguard\s+default\b", s, re.I):
            sw.stp_bpduguard_defecto = True
        elif re.match(r"^spanning-tree\s+portfast(?:\s+edge)?\s+default\b", s, re.I):
            sw.stp_portfast_defecto = True
        elif re.match(r"^udld\s+(enable|aggressive)\b", s, re.I):
            sw.udld = True
        elif re.match(r"^ntp\s+(server|peer)\s+\S", s, re.I):
            sw.ntp_servidores += 1                      # solo el conteo: ni la IP ni la llave
        elif re.match(r"^(no\s+)?logging\s", s, re.I):
            self.syslog(s)
        elif re.fullmatch(r"ip\s+dhcp\s+snooping", s, re.I):
            sw.dhcp_snooping = True
        elif re.fullmatch(r"no\s+ip\s+dhcp\s+snooping", s, re.I):
            sw.dhcp_snooping = False
        else:
            m = re.match(r"^ip\s+dhcp\s+snooping\s+vlan\s+([\d,\-\s]+)$", s, re.I)
            if m:
                sw.dhcp_snooping_vlans = sorted(set(sw.dhcp_snooping_vlans) | set(rango_vlans(m.group(1))))
                return
            m = re.match(r"^ip\s+arp\s+inspection\s+vlan\s+([\d,\-\s]+)$", s, re.I)
            if m:
                sw.dai_vlans = sorted(set(sw.dai_vlans) | set(rango_vlans(m.group(1))))

    def syslog(self, s: str) -> None:
        """Destinos de syslog (`logging host X`, `logging X` con una IP) y nivel (`logging trap N`). Solo el
        destino y el nivel: del resto de la linea (puerto, VRF, transporte, llaves) no se copia nada."""
        sw = self.sw
        quita = bool(re.match(r"^no\s", s, re.I))
        w = s.split()[1 if quita else 0:]
        if len(w) < 2:
            return
        if w[1].lower() == "trap" and not quita:
            sw.syslog_nivel = nivel_syslog(w[2]) if len(w) > 2 else sw.syslog_nivel
            return
        resto = w[1:]
        if resto[0].lower() == "host":
            resto = resto[1:]
            host = True
        else:
            host = False
        if resto and resto[0].lower() == "ipv6":
            resto = resto[1:]
        if len(resto) >= 2 and resto[0].lower() == "vrf":
            resto = resto[2:]
        if not resto:
            return
        d = destino_syslog(resto[0])
        if not d or not (host or _RE_IP.fullmatch(d)):      # `logging <palabra>` sin host: solo si es una IP
            return
        if quita:
            sw.syslog_destinos = [x for x in sw.syslog_destinos if x != d]
        elif d not in sw.syslog_destinos:
            sw.syslog_destinos.append(d)

    def credencial_global(self, s: str) -> None:
        m = _RE_USER.match(s)
        if re.match(r"^username\s", s, re.I):
            self.contar("usuario_local")
            if m:
                self.tipo(m.group(2), m.group(1).lower() == "secret")
            elif re.search(r"\bnopassword\b", s, re.I):
                self.contar("usuario_sin_password")
            return
        m = _RE_ENABLE.match(s)
        if m:
            sec = m.group(1).lower() == "secret"
            self.contar("enable_secret" if sec else "enable_password")
            self.tipo(m.group(2), sec)
            return
        p = s.split()
        if len(p) >= 3 and p[0].lower() == "snmp-server" and p[1].lower() == "community":
            self.contar("snmp_community")
            if any(x.lower() == "rw" for x in p[3:]):
                self.contar("snmp_rw")
            return
        m = _RE_AAA_G.match(s)
        if m:
            self.contar("aaa_key")
            if m.group(1) == "7":
                self.contar("tipo7")

    def interior(self, ctx, s: str) -> None:
        if ctx is None:
            return
        tipo = ctx[0]
        if tipo == "vlan":
            m = re.match(r"^name\s+(.+)$", s, re.I)
            if m:
                for i in ctx[1]:
                    self.sw.vlans[i] = m.group(1).strip()
        elif tipo == "if":
            self.puerto_linea(ctx[1], s)
        elif tipo == "svi":
            m = re.match(r"^ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s*$", s, re.I)
            if m and not any(x.vlan == ctx[1] for x in self.sw.svis):
                self.sw.svis.append(Svi(ctx[1], m.group(1), m.group(2)))
        elif tipo == "monitor":
            self.span(ctx[1], s)
        elif tipo == "line":
            m = re.match(r"^transport\s+input\s+(.+)$", s, re.I)
            if m and ctx[1]:
                for x in m.group(1).lower().split():
                    if x not in self.sw.vty_transport:
                        self.sw.vty_transport.append(x)
            m = _RE_PASS.match(s)
            if m:
                self.contar("password_linea")
                self.tipo(m.group(1), False)
        elif tipo == "aaa":
            m = _RE_KEY.match(s)
            if m:
                self.contar("aaa_key")
                if m.group(1) == "7":
                    self.contar("tipo7")

    def span(self, n: int, txt: str) -> None:
        ses = self.sesion(n)
        m = re.match(r"^source\s+vlan\s+(.+)$", txt, re.I)
        if m:
            ses.vlans_origen = sorted(set(ses.vlans_origen) | set(rango_vlans(m.group(1))))
            return
        m = re.match(r"^source\s+interface\s+(.+)$", txt, re.I)
        if m:
            for i in _interfaces(m.group(1)):
                if i not in ses.interfaces_origen:
                    ses.interfaces_origen.append(i)
            return
        m = re.match(r"^destination\s+interface\s+(\S+)", txt, re.I)
        if m:
            ses.destino = m.group(1)
            return
        m = re.match(r"^destination\s+remote\s+vlan\s+(\d+)", txt, re.I)
        if m:
            ses.destino = "remote vlan " + m.group(1)

    def puerto_linea(self, p: Puerto, s: str) -> None:
        m = re.match(r"^description\s+(.*)$", s, re.I)
        if m:
            p.descripcion = m.group(1).strip()
        elif re.fullmatch(r"shutdown", s, re.I):
            p.apagado = True
        elif re.fullmatch(r"no\s+shutdown", s, re.I):
            p.apagado = False
        elif re.fullmatch(r"no\s+switchport", s, re.I):
            p.modo = "routed"
        elif re.match(r"^switchport\s+mode\s+(access|trunk)\b", s, re.I):
            p.modo = s.split()[2].lower()
            p.modo_explicito = True
        elif re.match(r"^switchport\s+mode\s+dynamic\s+(auto|desirable)\b", s, re.I):
            p.dtp = s.split()[3].lower()
        elif re.fullmatch(r"switchport\s+nonegotiate", s, re.I):
            p.nonegotiate = True
        elif re.fullmatch(r"switchport\s+port-security", s, re.I):
            p.port_security = True
        elif re.match(r"^storm-control\s+broadcast\s+level\b", s, re.I):
            p.storm_broadcast = True
        elif re.match(r"^spanning-tree\s+portfast\b", s, re.I):
            resto = s.lower().split()[2:]
            if resto[:1] == ["edge"]:
                resto = resto[1:]
            if not resto:
                p.portfast = True
            elif resto == ["disable"]:
                p.portfast_off = True
        elif re.match(r"^spanning-tree\s+bpduguard\s+(enable|disable)\b", s, re.I):
            if s.split()[2].lower() == "enable":
                p.bpduguard = True
            else:
                p.bpduguard_off = True
        elif re.fullmatch(r"spanning-tree\s+guard\s+root", s, re.I):
            p.root_guard = True
        elif re.match(r"^switchport\s+access\s+vlan\s+\d+", s, re.I):
            p.vlan_acceso = int(s.split()[3])
        elif re.match(r"^switchport\s+trunk\s+native\s+vlan\s+\d+", s, re.I):
            p.vlan_nativa = int(s.split()[4])
        elif re.match(r"^switchport\s+trunk\s+allowed\s+vlan\s+", s, re.I):
            self.trunk_permitidas(p, s.split(None, 4)[4].strip())
        else:
            m = re.match(r"^channel-group\s+(\d+)", s, re.I)
            if m:
                p.canal = int(m.group(1))

    def trunk_permitidas(self, p: Puerto, arg: str) -> None:
        bajo = arg.lower()
        k = clave_if(p.nombre)
        if bajo.startswith("add "):
            if k in self.explicito:
                p.vlans_trunk = sorted(set(p.vlans_trunk) | set(rango_vlans(arg[4:])))
            return
        if bajo.startswith("remove "):
            p.vlans_trunk = [v for v in p.vlans_trunk if v not in set(rango_vlans(arg[7:]))]
            return
        if bajo.startswith("except "):
            self.sw.avisos.append("trunk allowed vlan except: no se modela, se toma como todas las VLAN")
            self.explicito.discard(k)
            return
        if bajo == "none":
            self.explicito.add(k)
            p.vlans_trunk = []
        elif bajo == "all":
            self.explicito.discard(k)
            p.vlans_trunk = []
        else:
            self.explicito.add(k)
            p.vlans_trunk = rango_vlans(arg)

    def cerrar_config(self) -> None:
        for p in self.sw.puertos:
            if not p.modo and p.vlan_acceso is not None:
                p.modo = "access"
            p.trunk_todas = p.modo == "trunk" and clave_if(p.nombre) not in self.explicito
        self.sw.config = True
        self.sw.http = ",".join(x for x, ok in (("http", self.http_srv), ("https", self.http_seg)) if ok)

    # ---------- otros comandos ----------
    def brief(self, lineas: list) -> None:
        for ln in lineas:
            m = _RE_BRIEF.match(ln.strip())
            if not m:
                continue
            nombre, ip = m["if"], m["ip"]
            mv = re.fullmatch(r"vlan(\d+)", nombre, re.I)
            if mv:
                v = int(mv.group(1))
                if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip) and not any(x.vlan == v for x in self.sw.svis):
                    self.sw.svis.append(Svi(v, ip, ""))
                continue
            if re.match(r"(loopback|tunnel|null|nve)", nombre, re.I):
                continue
            self.estado(self.puerto(nombre), m["st"], m["pr"])

    def descripciones(self, lineas: list) -> None:
        for ln in lineas:
            m = _RE_DESC.match(ln.strip())
            if not m or re.match(r"(vl|vlan|lo|loopback|tunnel)", m["if"], re.I):
                continue
            p = self.puerto(m["if"])
            self.estado(p, m["st"], m["pr"])
            if m["d"].strip() and not p.descripcion:
                p.descripcion = m["d"].strip()

    @staticmethod
    def estado(p: Puerto, st: str, pr: str) -> None:
        st = st.lower()
        p.estado = "admin down" if st == "administratively down" else st
        p.protocolo = pr.lower()

    def tabla_mac(self, lineas: list) -> None:
        vistos = set(self.sw.mac)
        for ln in lineas:
            m = _RE_MACROW.match(ln)
            if not m or not m["vlan"].isdigit():           # vlan All = estaticas del CPU
                continue
            puerto = m["puerto"]
            mac = mac_norm(m["mac"])
            if not mac or puerto.lower() in ("cpu", "drop", "router", "switch") or "," in puerto:
                continue
            if int(mac[1], 16) & 1:                      # multicast
                continue
            fila = (int(m["vlan"]), mac, puerto)
            if fila not in vistos:
                vistos.add(fila)
                self.sw.mac.append(fila)

    def cdp(self, lineas: list) -> None:
        v = None
        for ln in lineas:
            s = ln.strip()
            if s.startswith("Device ID:"):
                if v:
                    self.sw.cdp.append(v)
                v = Vecino(s.split(":", 1)[1].strip())
            elif v is None:
                continue
            elif not v.ip and re.match(r"^IP(?:v4)? address:", s, re.I):
                v.ip = s.split(":", 1)[1].strip()
            elif s.startswith("Platform:"):
                v.plataforma = s[len("Platform:"):].split(",")[0].strip()
            else:
                m = re.match(r"^Interface:\s*([^,]+),\s*Port ID \(outgoing port\):\s*(.*)$", s)
                if m:
                    v.interfaz, v.puerto_remoto = m.group(1).strip(), m.group(2).strip()
        if v:
            self.sw.cdp.append(v)

    def inventario(self, lineas: list) -> None:
        for ln in lineas:
            m = re.search(r"\bPID:\s*([^,\s]+)", ln)
            if m and not self.modelo_inv:
                self.modelo_inv = m.group(1)

    def version(self, lineas: list) -> None:
        for ln in lineas:
            if not self.sw.version and "software" in ln.lower():
                m = re.search(r"\bVersion\s+([0-9][\w.()\-]*)", ln)
                if m:
                    self.sw.version = m.group(1)
            if not self.modelo_ver:
                m = re.match(r"^\s*Model Number\s*:\s*(\S+)", ln, re.I) or \
                    re.match(r"^cisco\s+(\S+)\s+\(.*\)\s+processor", ln, re.I)
                if m:
                    self.modelo_ver = m.group(1)

    def stp(self, lineas: list) -> None:
        """show spanning-tree detail: por instancia, cambios de topologia, hace cuanto y desde que puerto."""
        cur = None
        pto = None
        espera_puerto = False
        for ln in lineas:
            m = _RE_STP_INST.match(ln)
            if m:
                cur = CambioStp(m.group(1).upper())
                self.sw.stp.append(cur)
                espera_puerto = False
                pto = None
                continue
            if cur is None:
                continue
            m = _RE_STP_PTO.match(ln)
            if m:
                pto = PuertoStp(m.group(2).strip(), int(m.group(1)), m.group(4).lower())
                cur.puertos.append(pto)
                espera_puerto = False
                continue
            if pto is not None:
                m = _RE_STP_DESIG.search(ln)
                if m:
                    pto.puente_designado = mac_norm(m.group(1))
                    continue
                m = _RE_STP_DESIG_PTO.search(ln)
                if m:
                    pto.puerto_designado = int(m.group(1))
                    continue
                m = _RE_STP_BPDU.search(ln)
                if m:
                    pto.bpdu_recibidas = int(m.group(1))
                    continue
                if re.search(r"port is in the portfast", ln, re.I):
                    pto.portfast = True
                    continue
            m = _RE_STP_PUENTE.search(ln)
            if m:
                cur.prioridad, cur.puente = int(m.group(1)), mac_norm(m.group(2))
                continue
            m = _RE_STP_CAMBIOS.search(ln)
            if m:
                cur.cambios = int(m.group(1))
                cur.hace_s = duracion_s(m.group(2))
                cur.puerto = m.group(3) or ""
                espera_puerto = not cur.puerto
                continue
            if espera_puerto:
                espera_puerto = False
                m = _RE_STP_FROM.match(ln)
                if m:
                    cur.puerto = m.group(1)
                    continue
            if re.search(r"We are the root of the spanning tree", ln, re.I):
                cur.raiz = "local"
                continue
            m = _RE_STP_RAIZ.search(ln)
            if m:
                cur.raiz = mac_norm(m.group(1))


    def logging(self, lineas: list) -> None:
        """show logging: MAC flapping y puertos en err-disable. El resto del log se descarta sin copiarse."""
        flap: dict = {}
        err: dict = {}
        for ln in lineas:
            f = _RE_LOG_FECHA.match(ln.strip())
            if f:                                       # solo se cuenta la marca; el resto de la linea se descarta
                self.sw.log_fechadas += 1
                self.sw.log_sin_sincronizar += f.group(1) == "*"
                self.sw.log_sincronia_perdida += f.group(1) == "."
            if _RE_FLAP.search(ln):
                self.sw.macflap_total += 1
                mac = _RE_FLAP_MAC.search(ln)
                vlan = _RE_FLAP_VLAN.search(ln)
                ptos = _RE_FLAP_PTOS.search(ln)
                k = (mac_norm(mac.group(1)) if mac else "", int(vlan.group(1)) if vlan else 0,
                     f"{ptos.group(1)} {ptos.group(2)}" if ptos else "")
                flap[k] = flap.get(k, 0) + 1
                continue
            for rx, motivo in ((_RE_ERRDIS, None), (_RE_BPDUG, "bpduguard"), (_RE_STORM, "storm-control")):
                m = rx.search(ln)
                if m:
                    k = (m.group(2), m.group(1).lower()) if motivo is None else (m.group(1), motivo)
                    err[k] = err.get(k, 0) + 1
                    break
        self.sw.macflap = [k + (n,) for k, n in sorted(flap.items())]
        self.sw.errdisable = [k + (n,) for k, n in sorted(err.items())]


    def contador(self, nombre: str) -> Contador:
        k = clave_if(nombre)
        c = self.cont.get(k)
        if c is None:
            c = self.cont[k] = Contador(nombre)
            self.sw.contadores.append(c)
        return c


    def interfaces(self, lineas: list) -> None:
        """show interfaces: paquetes, broadcast y errores de entrada por puerto."""
        c = None
        for ln in lineas:
            m = _RE_IF_HDR.match(ln.strip())
            if m:
                c = None if _RE_SKIP_IF.match(m.group(1)) else self.contador(m.group(1))
                continue
            if c is None:
                continue
            m = re.search(r"\bBW (\d+) Kbit", ln)
            if m:
                c.bw_kbit = int(m.group(1))
            m = re.search(r"5 minute (input|output) rate (\d+) bits/sec", ln)
            if m:
                if m.group(1) == "input":
                    c.tasa_entrada_bps = int(m.group(2))
                else:
                    c.tasa_salida_bps = int(m.group(2))
            m = re.search(r"(\d+) packets input", ln)
            if m:
                c.paquetes = int(m.group(1))
            m = re.search(r"Received (\d+) broadcasts", ln)
            if m:
                c.broadcast = int(m.group(1))
            m = re.search(r"(\d+) input errors, (\d+) CRC", ln)
            if m:
                c.errores, c.crc = int(m.group(1)), int(m.group(2))
            m = re.search(r"Total output drops:\s*(\d+)", ln)
            if m:
                c.descartes = max(c.descartes, int(m.group(1)))
            m = re.search(r"(\d+) packets output", ln)
            if m:
                c.paquetes_salida = int(m.group(1))
            m = re.search(r'Last clearing of\W+show interface\W+counters\s+(.+?)\s*$', ln, re.I)
            if m:
                c.limpieza = m.group(1)


    def errores(self, lineas: list) -> None:
        """show interfaces counters errors: FCS-Err (CRC) y Rcv-Err por puerto."""
        cols = None
        for ln in lineas:
            s = ln.split()
            if not s:
                continue
            if s[0] == "Port":
                cols = [x.lower() for x in s[1:]]
                if not {"fcs-err", "rcv-err", "outdiscards"} & set(cols):
                    cols = None
                continue
            if cols and len(s) == len(cols) + 1 and all(x.isdigit() for x in s[1:]) \
                    and not _RE_SKIP_IF.match(s[0]):
                fila = dict(zip(cols, (int(x) for x in s[1:])))
                c = self.contador(s[0])
                c.crc = max(c.crc, fila.get("fcs-err", 0))
                c.errores = max(c.errores, fila.get("rcv-err", 0))
                c.descartes = max(c.descartes, fila.get("outdiscards", 0))


def leer(texto: str, nombre: str = "") -> Switch:
    """Sesion pegada (o un running-config suelto) -> Switch. `nombre` (archivo) da el hostname si falta."""
    sw = Switch(archivo=nombre)
    lec = _Lector(sw)
    lineas = _limpiar(texto)
    secs, hosts, hubo = _secciones(lineas)
    if not hubo:
        if any(re.match(r"^(hostname|interface|vlan)\s", ln) for ln in lineas):
            secs = [("show running-config", lineas)]
        else:
            sw.avisos.append("no se reconocio salida de CLI de IOS/IOS-XE (sin prompts ni configuracion)")
    elif len(set(hosts)) > 1:
        sw.avisos.append("el archivo mezcla sesiones de varios equipos; se lee como uno solo")
    despacho = {"config": lec.config, "brief": lec.brief, "desc": lec.descripciones, "mac": lec.tabla_mac,
                "cdp": lec.cdp, "inventario": lec.inventario, "version": lec.version, "stp": lec.stp,
                "logging": lec.logging, "interfaces": lec.interfaces, "errores": lec.errores}
    estado = {"stp": "stp", "logging": "logging", "interfaces": "interfaces", "errores": "interfaces"}
    leidas = 0
    for cmd, cuerpo in secs:
        clase = _clase(cmd)
        if clase is None:
            continue
        if any(ln.strip() for ln in cuerpo):
            leidas += 1
            bajo = " ".join(ln.strip().lower() for ln in cuerpo[:3])
            if "invalid input" in bajo or bajo.startswith("% "):
                sw.avisos.append("el equipo devolvio error a un comando (" + clase + ")")
                continue
            if clase in estado and estado[clase] not in sw.leyo:
                sw.leyo.append(estado[clase])
        despacho[clase](cuerpo)
    if hubo and not leidas:
        sw.avisos.append("el archivo no trae ninguna de las salidas que se leen "
                         "(running-config, mac address-table, interfaces, cdp, version)")
    sw.hostname = sw.hostname or (hosts[0] if hosts else "") or Path(nombre).stem
    sw.modelo = lec.modelo_inv or lec.modelo_ver
    sw.version = sw.version or lec.version_cfg
    for _v, _m, pto in sw.mac:
        if lec.puerto(pto, crear=False) is None:
            lec.puerto(pto)
    if sw.mac and not lec.leyo_config:
        sw.avisos.append("sin running-config: no se distingue puerto de acceso de trunk salvo por "
                         "Port-channel y CDP")
    return sw


def leer_archivo(ruta) -> Switch:
    p = Path(ruta)
    return leer(p.read_text(encoding="utf-8", errors="replace"), p.name)
