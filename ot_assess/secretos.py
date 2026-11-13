"""Escaneo de secretos en salidas (SEC1, D138).

Busca valores que no deben salir en una entrega: comunidades SNMP, Authorization, contrasenas, hashes crypt,
llaves TACACS/RADIUS, PSK, tokens JWT, cookies, llaves privadas y llaves de acceso AKIA. Es una busqueda por
patrones: sin coincidencias no prueba que no haya secretos; con ellas hay que revisar a mano.
NUNCA devuelve ni imprime el valor completo: solo los 2 primeros caracteres y "***"."""
from __future__ import annotations

import html
import io
import os
import re
import zipfile
from pathlib import Path

EXT_TEXTO = {".csv", ".tsv", ".json", ".md", ".html", ".htm", ".txt", ".svg", ".drawio", ".xml"}
EXT_ZIP = {".xlsx", ".docx"}
_VAL = r"""(?P<v>[^\s"',;}\]<]+)"""
_SEP = r"""["']?\s*[=:]\s*["']?"""


def _p(rx: str) -> re.Pattern:
    return re.compile(rx, re.IGNORECASE)


# (tipo, patron con grupo "v"). El orden es la prioridad: un mismo valor se informa una sola vez.
PATRONES = [
    ("llave privada", re.compile(r"(?P<v>-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----)")),
    ("llave de acceso AKIA", re.compile(r"\b(?P<v>(?:AKIA|ASIA)[0-9A-Z]{16})\b")),
    ("token JWT", re.compile(r"\b(?P<v>eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*)")),
    ("Authorization", _p(r"\bauthorization" + _SEP + r"(?:basic|bearer)\s+(?P<v>[A-Za-z0-9+/=._~-]{4,})")),
    ("Cisco tipo 7", _p(r"\b(?:password|key|secret)\s+7\s+(?P<v>[0-9A-Fa-f]{4,})")),
    ("Cisco secret 5/8/9", _p(r"\bsecret\s+[589]\s+(?P<v>\S{6,})")),
    ("hash crypt", re.compile(r"(?<![\w$])(?P<v>\$(?:1|5|6|8|9|y)\$[^\s\"',;]{6,})")),
    ("comunidad SNMP", _p(r"\bsnmp-server\s+community\s+(?:[0-7]\s+)?" + _VAL)),
    ("comunidad SNMP", _p(r"\bcommunity" + _SEP + _VAL)),
    ("llave TACACS/RADIUS", _p(r"\b(?:tacacs|radius)(?:-server)?\b[^\r\n]*?\bkey\s+(?:(?:plaintext|ciphertext|[0-7])\s+)?"
                               + _VAL)),
    ("PSK", _p(r"\b(?:pre-?shared-?key|psk)" + _SEP + _VAL)),
    ("PSK", _p(r"\b(?:pre-?shared-?key|psk)\s+(?:0|6|7|ascii-text|hex|local|remote|enc)\s+" + _VAL)),
    ("PSK", _p(r"\bpsksecret\s+(?:enc\s+)?" + _VAL)),
    ("contrasena", _p(r"\b(?:password|passwd|pwd|secret)" + _SEP + _VAL)),
    ("Cookie", _p(r"\b(?:set-)?cookie\s*:\s*(?P<v>[^\r\n\"'<]{3,})")),
]
_CLAVE_BLOQUE = re.compile(r"^\s*(?:single-connection\s+)?key\s+(?:(?:plaintext|ciphertext|[0-7])\s+)?(?P<v>\S+)",
                           re.IGNORECASE)
_ABRE_BLOQUE = re.compile(r"\b(?:tacacs|radius)\b", re.IGNORECASE)
_VENTANA_BLOQUE = 8
# Valores que son marcas de posicion, no secretos.
_VACIOS = {"none", "null", "true", "false", "nil", "n/a", "na", "xxx", "xxxx", "redactado", "redacted",
           "oculto", "hidden", "cifrado", "encrypted", "unset", "disabled"}


def enmascarar(valor: str) -> str:
    return valor[:2] + "***"


def _es_marca(v: str) -> bool:
    v = v.strip().strip("'\"")
    if not v or v.lower() in _VACIOS:
        return True
    if v.startswith(("<", "{", "[", "*", "%", "(", "$(", "${")):
        return True
    return set(v) <= set("*xX.-_#")


def escanear_texto(texto: str) -> list:
    """-> [(linea, tipo, valor_enmascarado)]. Nunca incluye el valor completo."""
    out: list = []
    ventana = 0
    for n, linea in enumerate(texto.splitlines(), 1):
        vistos: set = set()
        if _ABRE_BLOQUE.search(linea):
            ventana = _VENTANA_BLOQUE
        elif ventana:
            ventana -= 1
            m = _CLAVE_BLOQUE.match(linea)
            if m and not _es_marca(m.group("v")):
                vistos.add(m.start("v"))
                out.append((n, "llave TACACS/RADIUS", enmascarar(m.group("v"))))
        for tipo, rx in PATRONES:
            for m in rx.finditer(linea):
                v = m.group("v")
                if m.start("v") in vistos or _es_marca(v):
                    continue
                if tipo == "comunidad SNMP" and re.match(r"\d+\b", v) and linea[:m.start()].lower().endswith("snmp "):
                    continue    # "SNMP community: 3" es el conteo del hallazgo, no una comunidad
                vistos.add(m.start("v"))
                out.append((n, tipo, enmascarar(v)))
    return out


_ETIQ_XML = re.compile(r"<[^>]+>")
_CIERRE_XML = re.compile(r"</(?:w:p|si|c|row|a:p|text:p)>|<br\s*/?>", re.IGNORECASE)


def _texto_xml(xml: str) -> str:
    return html.unescape(_ETIQ_XML.sub("", _CIERRE_XML.sub("\n", xml)))


def _escanear_zip(datos: bytes, rel: str) -> list:
    out: list = []
    try:
        z = zipfile.ZipFile(io.BytesIO(datos))
    except zipfile.BadZipFile:
        return out
    with z:
        for nombre in sorted(z.namelist()):
            if not nombre.lower().endswith((".xml", ".rels")):
                continue
            txt = _texto_xml(z.read(nombre).decode("utf-8", "replace"))
            for n, tipo, val in escanear_texto(txt):
                out.append({"archivo": rel, "lugar": f"{nombre}:{n}", "tipo": tipo, "valor": val})
    return out


def escanear_datos(rel: str, datos: bytes) -> list:
    """Escanea un archivo ya leido. -> [{archivo, lugar, tipo, valor(enmascarado)}]."""
    ext = os.path.splitext(rel)[1].lower()
    if ext in EXT_ZIP:
        return _escanear_zip(datos, rel)
    if ext in EXT_TEXTO:
        return [{"archivo": rel, "lugar": f"linea {n}", "tipo": tipo, "valor": val}
                for n, tipo, val in escanear_texto(datos.decode("utf-8", "replace"))]
    return []


def escanear_contenidos(contenidos: dict) -> list:
    """Escanea {ruta: bytes} (lo que va a un paquete)."""
    out: list = []
    for rel in sorted(contenidos):
        out.extend(escanear_datos(rel, contenidos[rel]))
    return out


def escanear(carpeta) -> list:
    """Recorre una carpeta (sin seguir enlaces simbolicos). -> lista de coincidencias."""
    carpeta = Path(carpeta)
    out: list = []
    for dirpath, dirnames, nombres in os.walk(carpeta):
        dirnames[:] = sorted(d for d in dirnames if not os.path.islink(os.path.join(dirpath, d)))
        for n in sorted(nombres):
            p = Path(dirpath) / n
            if p.is_symlink() or not p.is_file():
                continue
            ext = p.suffix.lower()
            if ext not in EXT_TEXTO and ext not in EXT_ZIP:
                continue
            rel = p.relative_to(carpeta).as_posix()
            out.extend(escanear_datos(rel, p.read_bytes()))
    return out


def linea(c: dict) -> str:
    return f"{c['archivo']} | {c['lugar']} | {c['tipo']} | {c['valor']}"
