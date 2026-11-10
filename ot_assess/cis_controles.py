"""CIS1 (D108): salvaguardas de CIS Controls v8.1 leidas de un archivo del analista (`--cis`).

CIS Controls es CC BY-NC-ND 4.0: el repo no distribuye ningun titulo ni texto de CIS, solo identificadores.
Aqui se leen, en tiempo de corrida, el titulo y las marcas de grupo de implementacion (IG1, IG2, IG3) del XLSX
oficial o de un CSV con las mismas columnas. La columna Description no se lee hacia ninguna salida.
"""
from __future__ import annotations

import csv
import io
import re
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

from .importers import lector

MAX_BYTES = 20 << 20
GRUPOS = ("IG1", "IG2", "IG3")
REFERENCIA = "www.cisecurity.org/controls/"
_CAB = ("CIS Control", "CIS Safeguard", "Asset Class", "Security Function", "Title", "Description", "IG1", "IG2",
        "IG3")
_NUM = re.compile(r"\d+")


def _norm(s) -> str:
    return str(s or "").replace("\xa0", " ").strip()


def _tabla(filas: list):
    """(cabecera -> indice, filas siguientes) si la primera fila no vacia tiene las columnas de CIS."""
    for i, f in enumerate(filas):
        if any(_norm(c) for c in f):
            idx = {_norm(c): j for j, c in enumerate(f) if _norm(c)}
            return (idx, filas[i + 1:]) if all(c in idx for c in _CAB) else None
    return None


def _raw(p: Path, raw: bytes) -> list:
    """Filas crudas: la hoja del XLSX con la cabecera de CIS o las filas del CSV."""
    try:
        if p.suffix.lower() == ".xlsx" or raw[:2] == b"PK":
            for _nombre, filas in lector.leer_xlsx_hojas(raw):
                if _tabla(filas):
                    return filas
            raise SystemExit(f"[!] '{p.name}': ninguna hoja tiene las columnas de CIS Controls "
                             f"({', '.join(_CAB)})")
        t = lector._texto(raw)
        lineas = [ln for ln in t.splitlines() if ln.strip()][:10]
        delim = max(",;\t|", key=lambda d: max((ln.count(d) for ln in lineas), default=0))
        return list(csv.reader(io.StringIO(t), delimiter=delim))
    except (ValueError, KeyError, zipfile.BadZipFile, ET.ParseError) as e:
        raise SystemExit(f"[!] '{p.name}' no parece un XLSX o CSV valido: {e}")


def cargar(ruta) -> list:
    """[{id, control, clase, funcion, titulo, ig1, ig2, ig3}] en el orden del archivo. SystemExit si no sirve."""
    p = Path(ruta)
    try:
        if p.stat().st_size > MAX_BYTES:
            raise SystemExit(f"[!] '{p.name}': el archivo de CIS pasa de {MAX_BYTES >> 20} MB")
        raw = p.read_bytes()
    except OSError as e:
        raise SystemExit(f"[!] No pude leer '{p.name}': {e.strerror or e}")
    tab = _tabla(_raw(p, raw))
    if not tab:
        raise SystemExit(f"[!] '{p.name}': no tiene las columnas de CIS Controls ({', '.join(_CAB)})")
    idx, filas = tab

    def celda(f, nombre):
        j = idx[nombre]
        return _norm(f[j]) if j < len(f) else ""

    out, ordinal = [], {}
    for f in filas:
        control, celda_id = celda(f, "CIS Control"), celda(f, "CIS Safeguard")
        if not control or not celda_id:         # fila de control (sin salvaguarda) o vacia
            continue
        m = _NUM.match(control)
        if not m:
            continue
        control = m.group(0)
        ordinal[control] = ordinal.get(control, 0) + 1
        ident = f"{control}.{ordinal[control]}"
        try:
            ok = abs(float(ident) - float(celda_id.replace(",", "."))) < 1e-9
        except ValueError:
            ok = False
        if not ok:
            raise SystemExit(f"[!] '{p.name}': la salvaguarda '{celda_id}' no coincide con su posicion "
                             f"({ident}) dentro del control {control}")
        out.append({"id": ident, "control": control, "clase": celda(f, "Asset Class"),
                    "funcion": celda(f, "Security Function"), "titulo": celda(f, "Title"),
                    "ig1": celda(f, "IG1").lower() == "x", "ig2": celda(f, "IG2").lower() == "x",
                    "ig3": celda(f, "IG3").lower() == "x"})
    if not out:
        raise SystemExit(f"[!] '{p.name}': sin salvaguardas de CIS Controls")
    return out
