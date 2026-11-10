"""Lectura tolerante de tablas exportadas: CSV/TSV, JSON (o JSON Lines) y XLSX.

Devuelve siempre una lista de dicts {encabezado: texto}. Sin dependencias: el XLSX se lee
directamente del zip. Los valores anidados de un JSON se aplanan (clave_subclave) y las
listas se unen con ";".
"""
from __future__ import annotations

import csv
import io
import re
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

from .. import json_entrada

NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
      "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships"}


def _texto(raw: bytes) -> str:
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16")
    for enc in ("utf-8-sig", "cp1252"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1")


def _filas_a_dicts(filas: list) -> list:
    """Primera fila con al menos dos celdas llenas = encabezado; el resto son registros."""
    filas = [f for f in filas if any(str(c).strip() for c in f)]
    for i, f in enumerate(filas):
        if sum(1 for c in f if str(c).strip()) >= 2:
            cab, vistos = [], {}
            for c in f:
                c = str(c).strip() or "columna"
                vistos[c] = vistos.get(c, 0) + 1
                cab.append(c if vistos[c] == 1 else f"{c}_{vistos[c]}")
            return [{h: (str(v).strip() if v is not None else "") for h, v in zip(cab, r)}
                    for r in filas[i + 1:]]
    return []


def leer_csv(raw: bytes) -> list:
    t = _texto(raw)
    # El delimitador es el que mas se repite en una linea de las primeras (hay reportes con
    # una linea de titulo antes del encabezado).
    lineas = [ln for ln in t.splitlines() if ln.strip()][:10]
    delim = max(",;\t|", key=lambda d: max((ln.count(d) for ln in lineas), default=0))
    if max((ln.count(delim) for ln in lineas), default=0) == 0:
        delim = ","
    return _filas_a_dicts(list(csv.reader(io.StringIO(t), delimiter=delim)))


def aplanar(obj, prefijo: str = "") -> dict:
    """{'a': {'b': 1}, 'c': [1, 2], 'd': [{'x': 1}, {'x': 2}]} -> {'a_b': '1', 'c': '1;2', 'd_x': '1;2'}"""
    out: dict = {}

    def poner(k, v):
        out[k] = f"{out[k]};{v}" if k in out and out[k] else v

    def texto(v):
        return "" if v is None else ("true" if v is True else "false" if v is False else str(v))

    if isinstance(obj, dict):
        for k, v in obj.items():
            clave = f"{prefijo}{k}"
            if isinstance(v, dict):
                for kk, vv in aplanar(v, f"{clave}_").items():
                    poner(kk, vv)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, (dict, list)):
                        for kk, vv in aplanar({clave: item} if isinstance(item, list) else item, f"{clave}_").items():
                            poner(kk, vv)
                    else:
                        poner(clave, texto(item))
            else:
                poner(clave, texto(v))
    return out


def _lista_de_registros(dato, profundidad: int = 0):
    """La lista de dicts mas larga dentro de un JSON (respuestas de API: {'result': [...]})."""
    if isinstance(dato, list):
        return dato if dato and all(isinstance(x, dict) for x in dato) else None
    if isinstance(dato, dict) and profundidad < 3:
        mejor = None
        for v in dato.values():
            cand = _lista_de_registros(v, profundidad + 1)
            if cand is not None and (mejor is None or len(cand) > len(mejor)):
                mejor = cand
        return mejor
    return None


def leer_json(raw: bytes) -> list:
    t = _texto(raw).strip()
    try:
        dato = json_entrada.cargar(t)
    except ValueError:
        dato = [json_entrada.cargar(ln) for ln in t.splitlines() if ln.strip()]      # JSON Lines
    regs = _lista_de_registros(dato)
    if regs is None and isinstance(dato, dict):
        regs = [dato]
    return [aplanar(r) for r in regs or []]


def _col(ref: str) -> int:
    n = 0
    for ch in re.match(r"[A-Z]+", ref).group():
        n = n * 26 + ord(ch) - 64
    return n - 1


MAX_PARTE = 64 * 1024 * 1024     # tope descomprimido por parte del zip
MAX_TOTAL = 256 * 1024 * 1024    # tope descomprimido sumando las partes leidas
MAX_PARTES = 10000               # tope de entradas en el zip


def _rechazo(nombre: str):
    return SystemExit(f"[!] XLSX rechazado: {nombre} excede el tope de descompresion (posible bomba zip)")


class _Lectura:
    """Lee partes del zip con tope real (no confia en el tamano declarado en la cabecera)."""

    def __init__(self, z: zipfile.ZipFile):
        self.z, self.total = z, 0
        if len(z.infolist()) > MAX_PARTES:
            raise _rechazo("el archivo (demasiadas entradas)")

    def __call__(self, nombre: str) -> bytes:
        with self.z.open(nombre) as f:
            datos = f.read(MAX_PARTE + 1)
        self.total += len(datos)
        if len(datos) > MAX_PARTE or self.total > MAX_TOTAL:
            raise _rechazo(nombre)
        return datos

    def xml(self, nombre: str):
        datos = self(nombre)
        return ET.fromstring(datos)  # nosec B314 - riesgo A6 aceptado (docs/SEGURIDAD.md); parte con tope de SEG-01


def leer_xlsx(raw: bytes) -> list:
    """Primera hoja de un .xlsx (cadenas compartidas, en linea y numeros)."""
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        _leer_parte = _Lectura(z)
        nombres = set(z.namelist())
        compartidas = []
        if "xl/sharedStrings.xml" in nombres:
            for si in _leer_parte.xml("xl/sharedStrings.xml").findall("m:si", NS):
                compartidas.append("".join(t.text or "" for t in si.iter(f"{{{NS['m']}}}t")))
        hoja = "xl/worksheets/sheet1.xml"
        if "xl/workbook.xml" in nombres and "xl/_rels/workbook.xml.rels" in nombres:
            wb = _leer_parte.xml("xl/workbook.xml")
            primera = wb.find("m:sheets/m:sheet", NS)
            if primera is not None:
                rid = primera.get(f"{{{NS['r']}}}id")
                for rel in _leer_parte.xml("xl/_rels/workbook.xml.rels"):
                    if rel.get("Id") == rid:
                        destino = rel.get("Target").lstrip("/")
                        hoja = destino if destino.startswith("xl/") else f"xl/{destino}"
        filas = []
        for fila in _leer_parte.xml(hoja).iter(f"{{{NS['m']}}}row"):
            celdas: dict = {}
            for c in fila.findall("m:c", NS):
                tipo, v = c.get("t"), c.find("m:v", NS)
                if tipo == "s" and v is not None:
                    val = compartidas[int(v.text)]
                elif tipo == "inlineStr":
                    val = "".join(t.text or "" for t in c.iter(f"{{{NS['m']}}}t"))
                else:
                    val = v.text if v is not None and v.text is not None else ""
                    if re.fullmatch(r"-?\d+\.0+", val):
                        val = val.split(".")[0]
                celdas[_col(c.get("r"))] = val
            filas.append([celdas.get(i, "") for i in range(max(celdas) + 1)] if celdas else [])
    return _filas_a_dicts(filas)


def leer_xlsx_hojas(raw: bytes) -> list:
    """Todas las hojas de un .xlsx como [(nombre, filas crudas)]; cada fila es una lista de textos.

    A diferencia de leer_xlsx no busca cabecera ni descarta filas: sirve para copiar o transformar
    el libro entero (anonimizador).
    """
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        _leer_parte = _Lectura(z)
        nombres = set(z.namelist())
        compartidas = []
        if "xl/sharedStrings.xml" in nombres:
            for si in _leer_parte.xml("xl/sharedStrings.xml").findall("m:si", NS):
                compartidas.append("".join(t.text or "" for t in si.iter(f"{{{NS['m']}}}t")))
        destinos = [("Hoja1", "xl/worksheets/sheet1.xml")]
        if "xl/workbook.xml" in nombres and "xl/_rels/workbook.xml.rels" in nombres:
            rels = {rel.get("Id"): rel.get("Target") for rel in _leer_parte.xml("xl/_rels/workbook.xml.rels")}
            destinos = []
            for h in _leer_parte.xml("xl/workbook.xml").findall("m:sheets/m:sheet", NS):
                destino = (rels.get(h.get(f"{{{NS['r']}}}id")) or "").lstrip("/")
                if destino:
                    destinos.append((h.get("name") or "Hoja",
                                     destino if destino.startswith("xl/") else f"xl/{destino}"))
        hojas = []
        for nombre, parte in destinos:
            filas = []
            for fila in _leer_parte.xml(parte).iter(f"{{{NS['m']}}}row"):
                celdas: dict = {}
                for c in fila.findall("m:c", NS):
                    tipo, v = c.get("t"), c.find("m:v", NS)
                    if tipo == "s" and v is not None:
                        val = compartidas[int(v.text)]
                    elif tipo == "inlineStr":
                        val = "".join(t.text or "" for t in c.iter(f"{{{NS['m']}}}t"))
                    else:
                        val = v.text if v is not None and v.text is not None else ""
                        if re.fullmatch(r"-?\d+\.0+", val):
                            val = val.split(".")[0]
                    celdas[_col(c.get("r"))] = val
                filas.append([celdas.get(i, "") for i in range(max(celdas) + 1)] if celdas else [])
            hojas.append((nombre, filas))
    return hojas


def leer_tabla(path) -> list:
    p = Path(path)
    try:
        raw = p.read_bytes()
    except OSError as e:
        raise SystemExit(f"[!] No pude leer '{path}': {e}")
    ext = p.suffix.lower()
    try:
        if ext == ".xlsx" or raw[:2] == b"PK":
            return leer_xlsx(raw)
        if ext in (".json", ".jsonl", ".ndjson") or raw.lstrip()[:1] in (b"{", b"["):
            return leer_json(raw)
        return leer_csv(raw)
    except (ValueError, KeyError, zipfile.BadZipFile, ET.ParseError) as e:
        raise SystemExit(f"[!] '{path}' no parece un CSV, JSON o XLSX valido: {e}")
