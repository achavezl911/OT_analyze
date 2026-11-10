"""Anonimizador de capturas (E5b): seudonimiza cabeceras de un pcap con el Mapa de E5a.

Lectura y escritura en flujo, paquete por paquete. Transforma MAC, ARP e IPv4 (y la IPv4 interna de
los ICMP de error), recalcula las sumas y, opcionalmente, recorta la carga. Con la carga
(E5c) sustituye IP, MAC, terminos y nombres conocidos sin cambiar longitudes. IPv6 y otros enlaces: sin soporte.
"""
from __future__ import annotations

import os
import re
import socket
import struct
import subprocess
import sys
import tempfile
from array import array
from pathlib import Path

from .anonimizar import ES_IP, IPV4, PCAP_MAGICOS, Mapa, Omitir
from .catalog import OT_PORTS

IPV4_B = re.compile(IPV4.pattern.encode("ascii"))
DIGITO_B = re.compile(rb"\d")
PUERTOS_DNS = (53, 5353, 5355)   # DNS, mDNS, LLMNR: nombres en formato de etiquetas
CONTADORES = ("ip_binarias", "mac_binarias", "ip_texto", "ip_texto_enmascaradas",
              "terminos_carga", "carga_ot_modificada")
ENLACES = (1, 101, 228)          # Ethernet, IPv4/IPv6 crudo, IPv4 crudo
ICMP_ERROR = (3, 4, 5, 11, 12)
VLAN = (0x8100, 0x88A8)
MAX_CAPLEN = 0x4000000           # 64 MiB: por encima el registro esta corrupto
# (formato de struct del orden de bytes, magic en disco)
FORMATOS = {b"\xd4\xc3\xb2\xa1": "<", b"\x4d\x3c\xb2\xa1": "<",
            b"\xa1\xb2\xc3\xd4": ">", b"\xa1\xb2\x3c\x4d": ">"}


def suma(datos: bytes, inicial: int = 0) -> int:
    """Suma de verificacion de Internet (complemento a uno de 16 bits)."""
    if len(datos) & 1:
        datos += b"\x00"
    a = array("H", datos)
    if sys.byteorder == "little":
        a.byteswap()
    s = sum(a) + inicial
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def es_captura(ruta: Path) -> bool:
    if ruta.suffix.lower() in (".pcap", ".pcapng", ".cap"):
        return True
    try:
        with open(ruta, "rb") as fh:
            return fh.read(4) in PCAP_MAGICOS
    except OSError:
        return False


def es_pcapng(ruta: Path) -> bool:
    try:
        with open(ruta, "rb") as fh:
            return fh.read(4) == b"\x0a\x0d\x0d\x0a"
    except OSError:
        return False


def nombre_salida(rel: Path) -> Path:
    """La salida de una captura es siempre pcap: .pcapng -> .pcap."""
    return rel.with_suffix(".pcap") if rel.suffix.lower() == ".pcapng" else rel


def _lit(b: int, casi: bool) -> bytes:
    if casi and 97 <= b <= 122:
        return bytes([91, b, b - 32, 93])               # [aA]
    return re.escape(bytes([b]))


def _emitir(nodo: dict, casi: bool) -> bytes:
    """Arbol de prefijos -> expresion regular: el motor salta por el primer byte sin probar cada clave."""
    hijos = sorted((b, h) for b, h in nodo.items() if b is not None)
    if not hijos:
        return b""
    alts = [_lit(b, casi) + _emitir(h, casi) for b, h in hijos]
    if None in nodo:
        return b"(?:" + b"|".join(alts) + b")?"          # codicioso: gana la clave mas larga
    return alts[0] if len(alts) == 1 else b"(?:" + b"|".join(alts) + b")"


def _regex_claves(claves, casi: bool = False):
    raiz: dict = {}
    for k in claves:
        n = raiz
        for b in k:
            n = n.setdefault(b, {})
        n[None] = True
    return re.compile(_emitir(raiz, casi)) if raiz else None


def _mayusculas(visto: bytes, pseudo: bytes) -> bytes:
    """Reaplica a `pseudo` (minusculas) las mayusculas que tenia lo encontrado."""
    return bytes(q - 32 if 65 <= v <= 90 and 97 <= q <= 122 else q for v, q in zip(visto, pseudo))


class Carga:
    """Sustitucion dentro de la carga util sin cambiar longitudes (E5c). Se construye una vez, con el
    Mapa ya poblado (pasada previa), de modo que el resultado no dependa del orden de los paquetes."""

    def __init__(self, mapa: Mapa):
        self.mapa = mapa
        self.ips: dict = {}
        for k, v in mapa.ips.items():
            if "/" in k or k == v:
                continue
            try:
                self.ips[socket.inet_aton(k)] = socket.inet_aton(v)
            except OSError:
                continue
        self.macs: dict = {}
        for k, v in mapa.macs.items():
            try:
                a, b = bytes.fromhex(k.replace(":", "")), bytes.fromhex(v.replace(":", ""))
            except ValueError:
                continue
            if len(a) == 6 and len(b) == 6 and a != b:
                self.macs[a] = b
        self.re_ip = _regex_claves(self.ips)
        self.re_mac = _regex_claves(self.macs)
        reales = list(mapa.terminos) + [n for n in mapa.nombres if len(n) >= 4 and not ES_IP.match(n)]
        self.claves: dict = {}                  # forma en bytes (minusculas) -> (real, seudonimo en bytes, str)
        self.dns: list = []                     # (regex con bytes de longitud de etiqueta, real, seudonimo)
        vistos = set()
        for real in sorted(reales, key=lambda t: (-len(t), t)):
            lt = "".join(c.lower() if c < "\x80" else c for c in real)
            if lt in vistos:
                continue
            vistos.add(lt)
            ps = mapa.seudonimo_largo(real)
            if ps == lt:
                continue                        # sin letras ni digitos: nada que cambiar
            for enc in ("utf-8", "utf-16-le"):
                self.claves[lt.encode(enc)] = (real, ps.encode(enc), ps)
            if "." in lt and lt.isascii() and ".." not in lt and not lt.startswith(".") and not lt.endswith("."):
                etiquetas = [b"".join(_lit(b, True) for b in e.encode("ascii")) for e in lt.split(".")]
                self.dns.append((re.compile(b"[\x01-\x3f]".join(etiquetas)), real, ps))
        self.re_t = _regex_claves(self.claves, casi=True)
        self.cache_txt: dict = {}
        self.reiniciar()

    def reiniciar(self):
        self.c = dict.fromkeys(CONTADORES, 0)

    def _ip_texto(self, ip: str) -> str:
        r = self.cache_txt.get(ip)
        if r is None:
            ya = ip in self.mapa.ips
            r = self.mapa.ip(ip)
            if not ya:
                self.mapa.ips.pop(ip, None)     # el conjunto de IP conocidas no cambia durante la escritura
            self.cache_txt[ip] = r
        return r

    def _f_ip_texto(self, m):
        ip = m.group(1).decode("ascii")
        nuevo = self._ip_texto(ip)
        if nuevo == ip:
            return m.group(0)
        resto = m.group(0)[len(m.group(1)):]
        if len(nuevo) == len(ip):
            self.c["ip_texto"] += 1
            self.mapa.carga[ip] = nuevo
            return nuevo.encode("ascii") + resto
        self.c["ip_texto_enmascaradas"] += 1
        return DIGITO_B.sub(b"x", m.group(1)) + resto

    def _f_termino(self, m):
        visto = m.group(0)
        clave = visto.lower()
        real, pb, ps = self.claves[clave]
        self.c["terminos_carga"] += 1
        self.mapa.carga[real] = ps
        return pb if visto == clave else _mayusculas(visto, pb)

    def _f_dns(self, real, ps):
        def f(m):
            visto = m.group(0)
            out = bytearray(visto)
            pb = ps.encode("ascii")
            for i, ch in enumerate(ps):
                if ch != ".":
                    out[i] = pb[i] - 32 if 65 <= visto[i] <= 90 and 97 <= pb[i] <= 122 else pb[i]
            self.c["terminos_carga"] += 1
            self.mapa.carga[real] = ps
            return bytes(out)
        return f

    def transformar(self, d: bytes, dns: bool = False) -> tuple:
        """-> (carga nueva, coincidencias binarias de IP o MAC). Siempre de la misma longitud."""
        binarias = 0
        if self.re_ip:
            d, n = self.re_ip.subn(lambda m: self.ips[m.group(0)], d)
            self.c["ip_binarias"] += n
            binarias += n
        if self.re_mac:
            d, n = self.re_mac.subn(lambda m: self.macs[m.group(0)], d)
            self.c["mac_binarias"] += n
            binarias += n
        if b"." in d:
            d = IPV4_B.sub(self._f_ip_texto, d)
        if dns:
            for rx, real, ps in self.dns:
                d = rx.sub(self._f_dns(real, ps), d)
        if self.re_t:
            d = self.re_t.sub(self._f_termino, d)
        return d, binarias


class _Estado:
    def __init__(self, mapa: Mapa, recortar: bool, plan=None):
        self.mapa = mapa
        self.recortar = recortar
        self.plan = None if recortar else plan
        self._ip: dict = {}
        self._mac: dict = {}
        self.ips: set = set()
        self.macs: set = set()
        self.paquetes = 0
        self.sin_recalcular = 0
        self.recortados = 0
        self.ipv6 = 0

    def ip(self, b: bytes) -> bytes:
        r = self._ip.get(b)
        if r is None:
            r = socket.inet_aton(self.mapa.ip(socket.inet_ntoa(b)))
            self._ip[b] = r
        if r != b:
            self.ips.add(b)
        return r

    def mac(self, b: bytes) -> bytes:
        r = self._mac.get(b)
        if r is None:
            r = bytes.fromhex(self.mapa.mac(b.hex(":")).replace(":", ""))
            self._mac[b] = r
        if r != b:
            self.macs.add(b)
        return r


def _carga(e: _Estado, p: bytearray, ini: int, fin: int, puertos=(), proto: str = "") -> None:
    """Sustituye en p[ini:fin] (misma longitud). `puertos`: los de origen y destino del L4."""
    if e.plan is None or fin - ini < 2:
        return
    datos = bytes(p[ini:fin])
    nuevo, binarias = e.plan.transformar(datos, any(x in PUERTOS_DNS for x in puertos))
    if nuevo != datos:
        assert len(nuevo) == len(datos)
        p[ini:fin] = nuevo
    # puerto de servicio = el menor de los dos: el efimero del cliente puede caer por azar en un puerto OT
    # (p. ej. 44818 o 47808 en una consulta DNS o SMB); y OT_PORTS tambien trae puertos 'it' (SMB, DNS)
    if binarias and puertos and OT_PORTS.get((min(puertos), proto), ('', ''))[1] == 'ot':
        e.plan.c["carga_ot_modificada"] += binarias


def _ipv4(e: _Estado, p: bytearray, o: int) -> int:
    """Transforma el paquete IPv4 que empieza en p[o]. -> longitud de lo que se conserva (o hasta
    donde se recorta la carga), contada desde o. Devuelve -1 si no hay cabecera IPv4 utilizable."""
    n = len(p) - o
    if n < 20 or p[o] >> 4 != 4:
        return -1
    ihl = (p[o] & 15) * 4
    if ihl < 20 or n < ihl:
        return -1
    total = (p[o + 2] << 8) | p[o + 3]
    frag = ((p[o + 6] & 0x3F) << 8) | p[o + 7]          # MF + desplazamiento
    proto = p[o + 9]
    p[o + 12:o + 16] = e.ip(bytes(p[o + 12:o + 16]))
    p[o + 16:o + 20] = e.ip(bytes(p[o + 16:o + 20]))
    ip_src, ip_dst = bytes(p[o + 12:o + 16]), bytes(p[o + 16:o + 20])
    p[o + 10:o + 12] = b"\x00\x00"
    p[o + 10:o + 12] = suma(bytes(p[o:o + ihl])).to_bytes(2, "big")
    fin_ip = min(o + total, len(p)) if total >= ihl else len(p)
    completo = total >= ihl and o + total <= len(p) and frag == 0
    ini = o + ihl
    seg = fin_ip - ini
    corte = ini                                          # sin L4 reconocido: tras la cabecera IP
    if proto == 6:
        if seg >= 20:
            corte = ini + min(max(((p[ini + 12] >> 4) * 4), 20), seg)
            _carga(e, p, ini if frag & 0x1FFF else corte, fin_ip,
                   ((p[ini] << 8) | p[ini + 1], (p[ini + 2] << 8) | p[ini + 3]), "tcp")
            if completo:
                _suma_l4(p, ini, seg, 6, ip_src, ip_dst)
            else:
                e.sin_recalcular += 1
        else:
            e.sin_recalcular += 1
    elif proto == 17:
        if seg >= 8:
            corte = ini + 8
            ulen = (p[ini + 4] << 8) | p[ini + 5]
            _carga(e, p, ini if frag & 0x1FFF else corte,
                   fin_ip if frag & 0x1FFF or not 8 <= ulen <= seg else ini + ulen,
                   ((p[ini] << 8) | p[ini + 1], (p[ini + 2] << 8) | p[ini + 3]), "udp")
            if p[ini + 6] == 0 and p[ini + 7] == 0:
                pass                                     # suma 0 = sin suma: se queda
            elif completo and 8 <= ulen <= seg:
                _suma_l4(p, ini, ulen, 17, ip_src, ip_dst)
            else:
                e.sin_recalcular += 1
        else:
            e.sin_recalcular += 1
    elif proto == 1:
        if seg >= 8:
            corte = ini + 8
            if p[ini] in ICMP_ERROR and seg >= 8 + 20:
                _ipv4_interno(e, p, ini + 8)
            elif p[ini] not in ICMP_ERROR:
                _carga(e, p, ini if frag & 0x1FFF else corte, fin_ip)
            if completo:
                p[ini + 2:ini + 4] = b"\x00\x00"
                p[ini + 2:ini + 4] = suma(bytes(p[ini:fin_ip])).to_bytes(2, "big")
            else:
                e.sin_recalcular += 1
        else:
            e.sin_recalcular += 1
    return corte - o


def _suma_l4(p: bytearray, ini: int, largo: int, proto: int, src: bytes, dst: bytes) -> None:
    """Recalcula la suma TCP (proto 6) o UDP (proto 17) del segmento p[ini:ini+largo]."""
    campo = ini + (16 if proto == 6 else 6)
    p[campo:campo + 2] = b"\x00\x00"
    pseudo = suma(src + dst + bytes([0, proto]) + largo.to_bytes(2, "big"))
    s = suma(bytes(p[ini:ini + largo]), (~pseudo) & 0xFFFF)
    if proto == 17 and s == 0:
        s = 0xFFFF
    p[campo:campo + 2] = s.to_bytes(2, "big")


def _ipv4_interno(e: _Estado, p: bytearray, o: int) -> None:
    """Cabecera IPv4 citada dentro de un ICMP de error: direcciones y suma de esa cabecera.
    Si el datagrama citado cabe entero (poco comun: suelen citarse 8 bytes), tambien su suma L4."""
    if p[o] >> 4 != 4:
        return
    ihl = (p[o] & 15) * 4
    if ihl < 20 or o + ihl > len(p):
        return
    p[o + 12:o + 16] = e.ip(bytes(p[o + 12:o + 16]))
    p[o + 16:o + 20] = e.ip(bytes(p[o + 16:o + 20]))
    p[o + 10:o + 12] = b"\x00\x00"
    p[o + 10:o + 12] = suma(bytes(p[o:o + ihl])).to_bytes(2, "big")
    total = (p[o + 2] << 8) | p[o + 3]
    ini = o + ihl
    seg = total - ihl
    if (p[o + 6] & 0x3F) or p[o + 7] or total < ihl or o + total > len(p):
        return
    src, dst = bytes(p[o + 12:o + 16]), bytes(p[o + 16:o + 20])
    if p[o + 9] == 6 and seg >= 20:
        _suma_l4(p, ini, seg, 6, src, dst)
    elif p[o + 9] == 17 and seg >= 8 and (p[ini + 6] or p[ini + 7]) and ((p[ini + 4] << 8) | p[ini + 5]) == seg:
        _suma_l4(p, ini, seg, 17, src, dst)


def _arp(e: _Estado, p: bytearray, o: int) -> int:
    if len(p) - o < 28 or p[o:o + 6] != b"\x00\x01\x08\x00\x06\x04":
        return -1
    p[o + 8:o + 14] = e.mac(bytes(p[o + 8:o + 14]))
    p[o + 14:o + 18] = e.ip(bytes(p[o + 14:o + 18]))
    p[o + 18:o + 24] = e.mac(bytes(p[o + 18:o + 24]))
    p[o + 24:o + 28] = e.ip(bytes(p[o + 24:o + 28]))
    return 28


def _paquete(e: _Estado, datos: bytes, enlace: int) -> bytes:
    """Transforma un paquete; con recortar devuelve solo hasta el final de la cabecera L4."""
    p = bytearray(datos)
    corte = len(p)
    if enlace == 1:
        if len(p) < 14:
            return datos
        p[0:6] = e.mac(bytes(p[0:6]))
        p[6:12] = e.mac(bytes(p[6:12]))
        o = 12
        tipo = (p[o] << 8) | p[o + 1]
        while tipo in VLAN and len(p) >= o + 6:
            o += 4
            tipo = (p[o] << 8) | p[o + 1]
        o += 2
        if tipo == 0x0800:
            r = _ipv4(e, p, o)
            if r >= 0:
                corte = o + r
            else:
                corte = o
        elif tipo == 0x0806:
            r = _arp(e, p, o)
            corte = o + r if r >= 0 else o
        else:
            corte = o
            if tipo == 0x86DD:
                e.ipv6 += 1
                corte = o + 40
            else:
                _carga(e, p, o, len(p))
    else:
        if p and p[0] >> 4 == 6:
            e.ipv6 += 1
            corte = 40
        else:
            r = _ipv4(e, p, 0)
            corte = max(r, 0)
    if e.recortar and corte < len(p):
        e.recortados += 1
        return bytes(p[:corte])
    return bytes(p)


def _convertir_pcapng(origen: Path, carpeta: Path) -> Path:
    from .tools import find_tool, run
    try:
        editcap = find_tool("editcap")
    except SystemExit:
        raise Omitir("pcapng: falta editcap (instale tshark/Wireshark) para convertirlo a pcap")
    carpeta.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".anon_", suffix=".pcap", dir=carpeta)
    os.close(fd)
    try:
        rc, _, _err = run([editcap, "-F", "pcap", str(origen), tmp])
    except (OSError, subprocess.SubprocessError) as ex:
        os.unlink(tmp)
        raise Omitir(f"pcapng: no pude ejecutar editcap: {ex}")
    if rc != 0:
        os.unlink(tmp)
        raise Omitir("pcapng: editcap no pudo convertirlo a pcap (p. ej. varias interfaces con distinto "
                     "tipo de enlace): separe la captura por interfaz y vuelva a intentar")
    return Path(tmp)


def _registros(entrada: Path, info: dict):
    """Genera (ts, tf, caplen, origlen, datos); antes del primero deja en `info` la cabecera global,
    el formato y el enlace. Lanza Omitir si la captura no se puede leer."""
    with open(entrada, "rb") as fi:
        cab = fi.read(24)
        if len(cab) < 24 or cab[:4] not in FORMATOS:
            raise Omitir("no es un pcap reconocible (cabecera global incompleta o magic desconocido)")
        fmt = FORMATOS[cab[:4]]
        enlace = struct.unpack(fmt + "I", cab[20:24])[0] & 0x0FFFFFFF
        if enlace not in ENLACES:
            raise Omitir(f"tipo de enlace {enlace} no soportado: no se puede anonimizar "
                         "(solo Ethernet e IPv4 crudo)")
        info.update(cab=cab, fmt=fmt, enlace=enlace)
        rec = struct.Struct(fmt + "IIII")
        while True:
            h = fi.read(16)
            if not h:
                return
            if len(h) < 16:
                raise Omitir("captura truncada: registro de paquete incompleto")
            ts, tf, caplen, origlen = rec.unpack(h)
            if caplen > MAX_CAPLEN:
                raise Omitir("captura corrupta: tamano de paquete absurdo")
            datos = fi.read(caplen)
            if len(datos) < caplen:
                raise Omitir("captura truncada: paquete incompleto al final del archivo")
            yield ts, tf, caplen, origlen, datos


def prepasar(mapa: Mapa, origen: Path) -> None:
    """Pasada previa: registra en el Mapa todas las IP y MAC que la transformacion de cabeceras va a
    tocar (la misma funcion, sin escribir), para que la sustitucion en la carga no dependa del orden
    de los paquetes ni de las capturas. Lanza Omitir si no se puede leer; el llamador lo ignora."""
    temporal = None
    entrada = origen
    if es_pcapng(origen):
        temporal = _convertir_pcapng(origen, Path(tempfile.gettempdir()))
        entrada = temporal
    try:
        e = _Estado(mapa, True)
        info: dict = {}
        for _ts, _tf, _cl, _ol, datos in _registros(entrada, info):
            _paquete(e, datos, info["enlace"])
    finally:
        if temporal is not None and temporal.exists():
            temporal.unlink()


def anonimizar_captura(mapa: Mapa, origen: Path, destino: Path, recortar: bool = False,
                       plan: Carga | None = None) -> dict:
    """Escribe en `destino` la captura seudonimizada. -> conteos. Lanza Omitir si no se puede.
    Con `recortar` no se toca ni se busca nada en la carga; si no, `plan` (o uno nuevo del Mapa)."""
    temporal = None
    entrada = origen
    if es_pcapng(origen):
        temporal = _convertir_pcapng(origen, destino.parent)
        entrada = temporal
    if not recortar and plan is None:
        plan = Carga(mapa)
    if plan is not None:
        plan.reiniciar()
    e = _Estado(mapa, recortar, plan)
    destino.parent.mkdir(parents=True, exist_ok=True)
    parcial = destino.with_name(destino.name + ".parcial")
    try:
        info: dict = {}
        gen = _registros(entrada, info)
        with open(parcial, "wb") as fo:
            for n, (ts, tf, _cl, origlen, datos) in enumerate(gen):
                if n == 0:
                    fo.write(info["cab"])
                    rec = struct.Struct(info["fmt"] + "IIII")
                nuevo = _paquete(e, datos, info["enlace"])
                e.paquetes += 1
                fo.write(rec.pack(ts, tf, len(nuevo), origlen))
                fo.write(nuevo)
            if e.paquetes == 0:
                fo.write(info["cab"])
        os.replace(parcial, destino)
    except BaseException:
        if parcial.exists():
            parcial.unlink()
        raise
    finally:
        if temporal is not None and temporal.exists():
            temporal.unlink()
    r = {"ips": len(e.ips), "macs": len(e.macs), "ipv6": e.ipv6, "paquetes": e.paquetes,
         "sin_recalcular": e.sin_recalcular, "recortados": e.recortados}
    r.update(plan.c if plan is not None else dict.fromkeys(CONTADORES, 0))
    return r
