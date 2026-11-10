"""Anonimizador (E5): seudonimizacion reversible de exportaciones y configuraciones.

No es anonimato garantizado: el mapa (real -> seudonimo) permite volver al dato real y la
estructura que el analisis necesita se conserva a proposito (ver D41). Capas: `Mapa` guarda
la clave y las correspondencias; `Anonimizador` transforma texto, tablas, JSON y
configuraciones usando el mapa. La entrada y la salida de archivos viven en cli_anonimizar.py.
"""
from __future__ import annotations

import csv
import hashlib
import hmac
import io
import ipaddress
import json
import os
import re
import secrets
from pathlib import Path

from . import json_entrada
from .importers.lector import _texto, leer_xlsx_hojas
from .importers.perfiles import normalizar
from .report.xlsx import escribir_xlsx

# Columna (normalizada) -> tipo de seudonimo.
COLUMNAS_NOMBRE = {
    "name": "host", "device_name": "host", "hostname": "host", "host": "host",
    "host_name": "host", "nombre": "host",
    "site": "sitio", "sitio": "sitio", "site_name": "sitio",
    "user": "usuario", "usuario": "usuario", "username": "usuario",
    "owner": "usuario", "contact": "usuario",
    "serial": "serie", "serial_number": "serie",
    "email": "correo", "correo": "correo",
}
# Columnas de texto libre: se omite el contenido.
COLUMNAS_LIBRES = {"description", "descripcion", "notes", "notas", "comment", "comentario",
                   "comments"}
FORMATOS = {"host": "host-{:04d}", "sitio": "sitio-{:03d}", "usuario": "usuario-{:03d}",
            "serie": "serie-{:04d}", "correo": "correo-{:03d}@ejemplo.invalid"}
OMITIDO = "[texto omitido]"
LINEA_SECRETO = "! [linea omitida: secreto]"
BLOQUE_CERT = "! [bloque omitido: certificado]"
CENTINELAS = {"n/a", "na", "none", "null", "unknown", "-", "--"}

_OCTETO = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
IPV4 = re.compile(r"(?<![\d.])(" + _OCTETO + r"(?:\." + _OCTETO + r"){3})(?:/(3[0-2]|[12]?\d))?(?!\d|\.\d)")
MAC = re.compile(r"(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}"
                 r"|[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})(?![0-9A-Fa-f])(?![:-][0-9A-Fa-f])")
CORREO = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
IPV6_CAND = re.compile(r"(?<![0-9A-Za-z:])[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*(?![0-9A-Za-z:])")
DOMINIO = re.compile(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
ES_IP = re.compile(r"^" + _OCTETO + r"(?:\." + _OCTETO + r"){3}(?:/\d{1,2})?$")
IP_ANTES = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\s+$")
PALABRA_MASCARA = re.compile(r"\b(?:net)?mask\b", re.IGNORECASE)

SECRETO = re.compile(r"\b(?:password|passwd|secret|token)|\b(?:key|community|pre-shared|psk|private"
                     r"|authentication-key)\b", re.IGNORECASE)
INICIO_CERT = re.compile(r"^\s*certificate\b", re.IGNORECASE)
HOSTNAME = re.compile(r"^(\s*hostname\s+)(\S+)(.*)$", re.IGNORECASE)
DOMINIO_CFG = re.compile(r"^\s*(?:ip\s+)?domain[- ]name\s+(\S+)", re.IGNORECASE)
DESCRIPCION = re.compile(r"^(.*?\b(?:description|remark)\s+)\S.*$", re.IGNORECASE)

PCAP_MAGICOS = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a",
                b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")


class MapaError(Exception):
    pass


class Omitir(Exception):
    """El archivo no se puede transformar: se salta con este motivo."""


def es_mascara(n: int) -> bool:
    """Mascara contigua (unos y luego ceros) o wildcard contigua (ceros y luego unos)."""
    inv = n ^ 0xFFFFFFFF
    return (inv & (inv + 1)) == 0 or (n & (n + 1)) == 0


def _prefijo_preservado(o: list) -> int:
    """Bits de la red privada o especial a la que pertenece la direccion (8 si es publica)."""
    if o[0] == 10:
        return 8
    if o[0] == 172 and 16 <= o[1] <= 31:
        return 12
    if o[0] == 192 and o[1] == 168:
        return 16
    if o[0] == 100 and 64 <= o[1] <= 127:
        return 10
    if o[0] == 169 and o[1] == 254:
        return 16
    return 8


def _publica(o: list) -> bool:
    p = _prefijo_preservado(o)
    return p == 8 and o[0] != 10


class Mapa:
    """Clave y correspondencias real -> seudonimo; JSON 0600. Reutilizarlo da la misma salida."""

    def __init__(self, path):
        self.path = Path(path)
        d: dict = {}
        self.nuevo = not self.path.exists()
        if not self.nuevo:
            try:
                d = json_entrada.cargar(self.path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as e:
                raise MapaError(f"no pude leer el mapa '{path}': {e}")
            if not isinstance(d, dict):
                raise MapaError(f"el mapa '{path}' no es un objeto JSON")
        self.clave = d.get("clave") or secrets.token_hex(32)
        try:
            self._k = bytes.fromhex(self.clave)
        except ValueError:
            raise MapaError(f"la clave del mapa '{path}' no es hexadecimal")
        for campo in ("ips", "macs", "nombres", "terminos", "carga"):
            v = d.get(campo, {})
            if not isinstance(v, dict):
                raise MapaError(f"el campo '{campo}' del mapa '{path}' no es un objeto")
            setattr(self, campo, dict(v))
        self._nom = {k.lower(): v for k, v in self.nombres.items()}
        self._ter = {k.lower(): v for k, v in self.terminos.items()}
        self._cont: dict = {}
        for v in self.nombres.values():
            self._cont[v.split("-", 1)[0]] = self._cont.get(v.split("-", 1)[0], 0) + 1
        self._cont_t: dict = {}
        for v in self.terminos.values():
            self._cont_t[v.split("-", 1)[0]] = self._cont_t.get(v.split("-", 1)[0], 0) + 1
        self._re_t = None
        self._re_n = None
        self._re_n_largo = -1

    def guardar(self):
        """Escribe el mapa con permisos 0600 (archivo temporal + reemplazo)."""
        datos = {"clave": self.clave, "ips": self.ips, "macs": self.macs,
                 "nombres": self.nombres, "terminos": self.terminos, "carga": self.carga}
        tmp = self.path.with_name(self.path.name + ".tmp")
        try:
            tmp.unlink()
        except OSError:
            pass
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(datos, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(str(tmp), str(self.path))

    # ---- nombres y terminos -------------------------------------------------------------
    def seudonimo(self, real: str, tipo: str) -> str:
        k = real.lower()
        if k in self._nom:
            return self._nom[k]
        n = self._cont.get(tipo, 0) + 1
        self._cont[tipo] = n
        pseudo = FORMATOS[tipo].format(n)
        self.nombres[real] = pseudo
        self._nom[k] = pseudo
        return pseudo

    def agregar_termino(self, real: str):
        real = real.strip()
        k = real.lower()
        if not real or k in self._ter:
            return
        tipo = "dominio" if DOMINIO.match(real) else "termino"
        n = self._cont_t.get(tipo, 0) + 1
        self._cont_t[tipo] = n
        pseudo = f"dominio-{n:02d}.invalid" if tipo == "dominio" else f"termino-{n:02d}"
        self.terminos[real] = pseudo
        self._ter[k] = pseudo
        self._re_t = None

    def seudonimo_largo(self, real: str) -> str:
        """Seudonimo de la misma longitud (carga de capturas, E5c): cada letra o digito ASCII cambia
        (siempre a otro) y los signos y las demas letras quedan donde estan. Trabaja sobre la forma
        en minusculas ASCII; el llamador reaplica las mayusculas. Determinista con la clave del mapa."""
        base = "".join(c.lower() if c < "\x80" else c for c in real)
        flujo = b""
        i = 0
        while len(flujo) < len(base):
            flujo += hmac.new(self._k, f"carga:{i}:{base}".encode(), hashlib.sha256).digest()
            i += 1
        out = []
        for c, b in zip(base, flujo):
            if "a" <= c <= "z":
                out.append(chr(97 + (ord(c) - 97 + 1 + b % 25) % 26))
            elif "0" <= c <= "9":
                out.append(chr(48 + (ord(c) - 48 + 1 + b % 9) % 10))
            else:
                out.append(c)
        return "".join(out)

    def termino(self, encontrado: str) -> str:
        return self._ter[encontrado.lower()]

    def regex_terminos(self):
        if self._re_t is None and self._ter:
            alt = "|".join(re.escape(t) for t in sorted(self._ter, key=lambda t: (-len(t), t)))
            self._re_t = re.compile(alt, re.IGNORECASE)
        return self._re_t

    def regex_nombres(self):
        """Nombres ya mapeados (3 o mas caracteres) como palabra completa dentro de otro texto."""
        if self._re_n_largo != len(self._nom):
            claves = [k for k in self._nom if len(k) >= 3 and not ES_IP.match(k)]
            self._re_n = None
            if claves:
                alt = "|".join(re.escape(k) for k in sorted(claves, key=lambda k: (-len(k), k)))
                self._re_n = re.compile(r"(?<![\w-])(?:" + alt + r")(?![\w-])", re.IGNORECASE)
            self._re_n_largo = len(self._nom)
        return self._re_n

    def nombre(self, encontrado: str) -> str:
        return self._nom[encontrado.lower()]

    # ---- IPv4 y MAC ---------------------------------------------------------------------
    def _bit(self, msg: str) -> int:
        return hmac.new(self._k, msg.encode("ascii"), hashlib.sha256).digest()[0] >> 7

    def ip(self, ip: str) -> str:
        """Seudonimo de una IPv4 que conserva prefijos hasta /24 y el ultimo octeto."""
        if ip in self.ips:
            return self.ips[ip]
        o = [int(x) for x in ip.split(".")]
        n = (o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]
        if n == 0 or n == 0xFFFFFFFF or o[0] in (0, 127) or o[0] >= 224:
            return ip
        p = _prefijo_preservado(o)
        publica = _publica(o)
        for intento in range(10000):
            salida = n
            for i in range(p, 24):
                bits = n >> (32 - i)
                salida ^= self._bit(f"ip:{intento}:{i}:{bits}") << (31 - i)
            # Una publica debe seguir siendo global; si no, otro intento (se pierde el prefijo).
            if not publica or ipaddress.ip_address(salida | 1).is_global:
                break
        else:
            return ip
        pseudo = str(ipaddress.ip_address(salida))
        self.ips[ip] = pseudo
        return pseudo

    def cidr(self, ip: str, n: int) -> str:
        """a.b.c.d/n: se transforma la direccion; si era una red (bits de host en cero) se re-enmascara."""
        clave = f"{ip}/{n}"
        if clave in self.ips:
            return self.ips[clave]
        pseudo = self.ip(ip)
        if pseudo != ip and n <= 24:
            real = int(ipaddress.ip_address(ip))
            mascara = (0xFFFFFFFF << (32 - n)) & 0xFFFFFFFF
            if real & ~mascara & 0xFFFFFFFF == 0:
                pseudo = str(ipaddress.ip_address(int(ipaddress.ip_address(pseudo)) & mascara))
        out = f"{pseudo}/{n}"
        if pseudo != ip:
            self.ips[clave] = out
        return out

    def mac(self, original: str) -> str:
        """Conserva el OUI, transforma los 3 ultimos bytes y respeta el formato de entrada."""
        hexa = re.sub(r"[^0-9A-Fa-f]", "", original).lower()
        if hexa == "ffffffffffff" or hexa == "0" * 12 or int(hexa[:2], 16) & 1:
            return original
        canon = ":".join(hexa[i:i + 2] for i in range(0, 12, 2))
        if canon not in self.macs:
            h = hmac.new(self._k, ("mac:" + hexa).encode("ascii"), hashlib.sha256).digest()
            self.macs[canon] = canon[:9] + ":".join(f"{b:02x}" for b in h[:3])
        nuevo = self.macs[canon].replace(":", "")
        if "." in original:
            s = ".".join(nuevo[i:i + 4] for i in range(0, 12, 4))
        else:
            sep = "-" if "-" in original else ":"
            s = sep.join(nuevo[i:i + 2] for i in range(0, 12, 2))
        mayus = any(c in "ABCDEF" for c in original)
        if mayus and not any(c in "abcdef" for c in original) or \
                (not mayus and "-" in original and not any(c in "abcdef" for c in original)):
            s = s.upper()           # sin letras en el original, el guion se asume en mayusculas
        return s


def _tipo_col(encabezado: str):
    n = normalizar(encabezado)
    if n in COLUMNAS_NOMBRE:
        return COLUMNAS_NOMBRE[n]
    return "libre" if n in COLUMNAS_LIBRES else None


def _indice_cabecera(filas: list):
    """Misma regla que lector: primera fila con dos o mas celdas llenas."""
    for i, f in enumerate(filas):
        if sum(1 for c in f if str(c).strip()) >= 2:
            return i
    return None


def codificacion(raw: bytes) -> str:
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return "utf-16"
    if raw[:3] == b"\xef\xbb\xbf":
        return "utf-8-sig"
    for enc in ("utf-8", "cp1252"):
        try:
            raw.decode(enc)
            return enc
        except UnicodeDecodeError:
            continue
    return "latin-1"


def _contar_ipv6(s: str) -> int:
    n = 0
    for m in IPV6_CAND.finditer(s):
        tok = m.group(0)
        if tok.count(":") < 2:
            continue
        try:
            ipaddress.IPv6Address(tok)
        except ValueError:
            continue
        n += 1
    return n


class Anonimizador:
    """Transforma contenidos con un Mapa. `seco=True` solo registra nombres (pasada previa)."""

    def __init__(self, mapa: Mapa):
        self.mapa = mapa
        self.seco = False
        self.c = self.reiniciar()

    def reiniciar(self) -> dict:
        self.c = {"ips": 0, "macs": 0, "nombres": 0, "terminos": 0, "omitidas": 0, "ipv6": 0}
        return self.c

    # ---- texto ----------------------------------------------------------------------------
    def _sub_correo(self, m):
        self.c["nombres"] += 1
        return self.mapa.seudonimo(m.group(0), "correo")

    def _sub_termino(self, m):
        self.c["terminos"] += 1
        return self.mapa.termino(m.group(0))

    def _sub_nombre(self, m):
        self.c["nombres"] += 1
        return self.mapa.nombre(m.group(0))

    def _sub_mac(self, m):
        self.c["macs"] += 1
        return self.mapa.mac(m.group(0))

    def _sub_ip(self, m):
        ip, n = m.group(1), m.group(2)
        o = [int(x) for x in ip.split(".")]
        valor = (o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]
        if n is None and es_mascara(valor):
            antes = m.string[:m.start()]
            if IP_ANTES.search(antes[-24:]) or PALABRA_MASCARA.search(m.string):
                return m.group(0)
        self.c["ips"] += 1
        return self.mapa.ip(ip) if n is None else self.mapa.cidr(ip, int(n))

    def texto(self, s: str, nombres: bool = True) -> str:
        """Correos, terminos, nombres ya mapeados, MAC e IPv4 dentro de un texto cualquiera."""
        if self.seco or not s:
            return s
        self.c["ipv6"] += _contar_ipv6(s)
        s = CORREO.sub(self._sub_correo, s)
        rt = self.mapa.regex_terminos()
        if rt:
            s = rt.sub(self._sub_termino, s)
        rn = self.mapa.regex_nombres() if nombres else None
        if rn:
            s = rn.sub(self._sub_nombre, s)
        s = MAC.sub(self._sub_mac, s)
        return IPV4.sub(self._sub_ip, s)

    def celda(self, valor: str, tipo):
        if not valor.strip():
            return valor
        if tipo == "libre":
            return OMITIDO
        v = valor.strip()
        # un valor con una IPv4 o MAC dentro (xDome: "10.1.1.1 (texto)" como nombre) no es nombre:
        # registrarlo como tal haria que la celda IP con el mismo texto perdiera la direccion
        if (tipo in FORMATOS and v.lower() not in CENTINELAS and not IPV4.search(v)
                and not MAC.search(v)):
            self.c["nombres"] += 1
            return self.mapa.seudonimo(v, tipo)
        return self.texto(valor)

    # ---- tablas ---------------------------------------------------------------------------
    def tabla(self, filas: list) -> list:
        """Filas crudas -> filas transformadas; la fila de cabecera no se toca."""
        i = _indice_cabecera(filas)
        tipos: dict = {}
        out = []
        for n, f in enumerate(filas):
            if i is not None and n == i:
                tipos = {j: _tipo_col(h) for j, h in enumerate(f)}
                out.append(list(f))
            elif i is None or n < i:
                out.append([self.texto(c) for c in f])
            else:
                out.append([self.celda(c, tipos.get(j)) for j, c in enumerate(f)])
        return out

    def csv(self, raw: bytes) -> bytes:
        enc, t = codificacion(raw), _texto(raw)
        lineas = [ln for ln in t.splitlines() if ln.strip()][:10]
        delim = max(",;\t|", key=lambda d: max((ln.count(d) for ln in lineas), default=0))
        if max((ln.count(delim) for ln in lineas), default=0) == 0:
            delim = ","
        filas = self.tabla(list(csv.reader(io.StringIO(t, newline=""), delimiter=delim)))
        eol = "\r\n" if "\r\n" in t else "\n"
        buf = io.StringIO(newline="")
        w = csv.writer(buf, delimiter=delim, lineterminator=eol)
        w.writerows(filas)
        s = buf.getvalue()
        if s.endswith(eol) and not t.endswith(("\n", "\r")):
            s = s[:-len(eol)]
        return s.encode(enc, errors="replace")

    def xlsx(self, raw: bytes) -> bytes:
        salida = []
        for nombre, filas in leer_xlsx_hojas(raw):
            f = self.tabla(filas)
            salida.append((self.texto(nombre, nombres=False), f[0] if f else [], f[1:]))
        buf = io.BytesIO()
        escribir_xlsx(buf, salida or [("Hoja1", [], [])])
        return buf.getvalue()

    # ---- JSON -----------------------------------------------------------------------------
    def _json(self, o, tipo=None, registro=True):
        """`registro`: el dict es la raiz o un elemento de lista (un activo). En un objeto anidado
        ("type": {"name": "PLC"}) un `name` es una etiqueta, no un nombre de equipo: solo vale
        el tipo de la clave padre (`site` -> sitio)."""
        if isinstance(o, dict):
            out = {}
            for k, v in o.items():
                t = _tipo_col(k)
                if t in FORMATOS and not registro:
                    t = tipo
                out[self.texto(k, nombres=False)] = self._json(v, t, not isinstance(v, dict))
            return out
        if isinstance(o, list):
            return [self._json(x, tipo, True) for x in o]
        if isinstance(o, str):
            return self.celda(o, tipo)
        if tipo in FORMATOS and isinstance(o, (int, float)) and not isinstance(o, bool):
            self.c["nombres"] += 1
            return self.mapa.seudonimo(str(o), tipo)
        return o

    def json(self, raw: bytes) -> bytes:
        enc, t = codificacion(raw), _texto(raw)
        try:
            dato, jsonl = json_entrada.cargar(t), False
        except ValueError:
            try:
                dato, jsonl = [json_entrada.cargar(ln) for ln in t.splitlines() if ln.strip()], True
            except ValueError:
                return self.config(raw)
        nuevo = self._json(dato)
        if jsonl:
            s = "\n".join(json.dumps(x, ensure_ascii=False) for x in nuevo) + "\n"
        else:
            s = json.dumps(nuevo, ensure_ascii=False, indent=2) + "\n"
        return s.encode(enc, errors="replace")

    # ---- configuraciones y texto ------------------------------------------------------------
    def config(self, raw: bytes) -> bytes:
        enc, t = codificacion(raw), _texto(raw)
        out, bloque = [], None
        for ln in t.splitlines(keepends=True):
            cuerpo = ln.rstrip("\r\n")
            eol = ln[len(cuerpo):]
            if bloque:
                self.c["omitidas"] += 1
                if (bloque == "cert" and cuerpo.strip().lower() == "quit") or \
                        (bloque == "pem" and "-----END" in cuerpo):
                    bloque = None
                continue
            if INICIO_CERT.match(cuerpo) or "-----BEGIN" in cuerpo:
                self.c["omitidas"] += 1
                if "-----BEGIN" in cuerpo:
                    bloque = None if "-----END" in cuerpo else "pem"
                else:
                    bloque = "cert"
                out.append(BLOQUE_CERT + eol)
                continue
            if SECRETO.search(cuerpo):
                self.c["omitidas"] += 1
                out.append(LINEA_SECRETO + eol)
                continue
            m = HOSTNAME.match(cuerpo)
            if m:
                self.c["nombres"] += 1
                pseudo = self.mapa.seudonimo(m.group(2), "host")
                out.append(m.group(1) + pseudo + self.texto(m.group(3)) + eol)
                continue
            m = DOMINIO_CFG.match(cuerpo)
            if m:
                self.mapa.agregar_termino(m.group(1))
            m = DESCRIPCION.match(cuerpo)
            if m:
                out.append(self.texto(m.group(1)) + OMITIDO + eol)
                continue
            out.append(self.texto(cuerpo) + eol)
        return "".join(out).encode(enc, errors="replace")

    # ---- despacho ---------------------------------------------------------------------------
    def transformar(self, ext: str, raw: bytes) -> tuple:
        """-> (tipo, bytes). Lanza Omitir si el archivo no se puede transformar."""
        ext = ext.lower()
        if ext == ".xlsx":
            try:
                return "xlsx", self.xlsx(raw)
            except Exception as e:  # noqa: BLE001 - cualquier fallo del lector XLSX se reporta como archivo omitido
                raise Omitir(f"no pude leer el XLSX: {e}")
        if raw[:2] == b"PK":
            raise Omitir("archivo comprimido o de Office no reconocido")
        if raw[:2] not in (b"\xff\xfe", b"\xfe\xff") and b"\x00" in raw[:8192]:
            raise Omitir("archivo binario no reconocido")
        if ext in (".csv", ".tsv"):
            return "csv", self.csv(raw)
        if ext in (".json", ".jsonl", ".ndjson"):
            return "json", self.json(raw)
        return "texto", self.config(raw)
