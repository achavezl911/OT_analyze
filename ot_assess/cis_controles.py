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


def _raw(p: Path, raw: bytes, buscar=None, columnas=None) -> list:
    """Filas crudas: la hoja del XLSX con la cabecera de CIS (`buscar` decide) o las filas del CSV."""
    buscar = buscar or _tabla
    columnas = columnas or _CAB
    try:
        if p.suffix.lower() == ".xlsx" or raw[:2] == b"PK":
            for _nombre, filas in lector.leer_xlsx_hojas(raw):
                if buscar(filas):
                    return filas
            raise SystemExit(f"[!] '{p.name}': ninguna hoja tiene las columnas de CIS Controls "
                             f"({', '.join(columnas)})")
        t = lector._texto(raw)
        lineas = [ln for ln in t.splitlines() if ln.strip()][:10]
        delim = max(",;\t|", key=lambda d: max((ln.count(d) for ln in lineas), default=0))
        return list(csv.reader(io.StringIO(t), delimiter=delim))
    except (ValueError, KeyError, zipfile.BadZipFile, ET.ParseError) as e:
        raise SystemExit(f"[!] '{p.name}' no parece un XLSX o CSV valido: {e}")


def _leer(ruta) -> tuple:
    p = Path(ruta)
    try:
        if p.stat().st_size > MAX_BYTES:
            raise SystemExit(f"[!] '{p.name}': el archivo de CIS pasa de {MAX_BYTES >> 20} MB")
        return p, p.read_bytes()
    except OSError as e:
        raise SystemExit(f"[!] No pude leer '{p.name}': {e.strerror or e}")


def _ident(p: Path, control: str, celda_id: str, n: int) -> str:
    """Id `control.n` validado contra la celda (numerica con ruido de flotante o texto)."""
    ident = f"{control}.{n}"
    try:
        ok = abs(float(ident) - float(celda_id.replace(",", "."))) < 1e-9
    except ValueError:
        ok = False
    if not ok:
        raise SystemExit(f"[!] '{p.name}': la salvaguarda '{celda_id}' no coincide con su posicion "
                         f"({ident}) dentro del control {control}")
    return ident


def cargar(ruta) -> list:
    """[{id, control, clase, funcion, titulo, ig1, ig2, ig3}] en el orden del archivo. SystemExit si no sirve."""
    p, raw = _leer(ruta)
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
        ident = _ident(p, control, celda_id, ordinal[control])
        out.append({"id": ident, "control": control, "clase": celda(f, "Asset Class"),
                    "funcion": celda(f, "Security Function"), "titulo": celda(f, "Title"),
                    "ig1": celda(f, "IG1").lower() == "x", "ig2": celda(f, "IG2").lower() == "x",
                    "ig3": celda(f, "IG3").lower() == "x"})
    if not out:
        raise SystemExit(f"[!] '{p.name}': sin salvaguardas de CIS Controls")
    return out


# CIS1b (D111): mapeos oficiales de CIS (a SP 800-53 Rev 5 y a CSF 2.0), solo ids y relacion.
_CAB_MAPEO = ("CIS Control", "CIS Safeguard", "Relationship")
_DESTINO = {"Control Identifier": "sp800_53", "CSF Subcategories": "csf2"}
_RE_DESTINO = {"sp800_53": re.compile(r"([A-Z]{2})-(\d{1,2})(?:\((\d{1,2})\))?$"),
               "csf2": re.compile(r"([A-Z]{2})\.([A-Z]{2})-(\d{2})$")}


def _tabla_mapeo(filas: list):
    """(cabecera -> indice, posicion de la cabecera, tipo) si una de las primeras 5 filas tiene las columnas."""
    for i, f in enumerate(filas[:5]):
        idx = {_norm(c): j for j, c in enumerate(f) if _norm(c)}
        if all(c in idx for c in _CAB_MAPEO):
            for col, tipo in _DESTINO.items():
                if col in idx:
                    return idx, i, tipo
    return None


def _destino(p: Path, hoja_linea: str, tipo: str, valor: str) -> str:
    """Id de destino normalizado ('CM-8 (1)' -> 'CM-8(1)'); SystemExit si la forma no es la del tipo."""
    v = valor.replace(" ", "").upper()
    m = _RE_DESTINO[tipo].match(v)
    if not m:
        raise SystemExit(f"[!] '{p.name}' {hoja_linea}: '{valor}' no es un id de "
                         f"{'SP 800-53 Rev 5' if tipo == 'sp800_53' else 'CSF 2.0'}")
    if tipo == "csf2":
        return v
    base = f"{m.group(1)}-{int(m.group(2))}"
    return f"{base}({int(m.group(3))})" if m.group(3) else base


def cargar_mapeo(ruta, ids_validos) -> dict:
    """Mapeo oficial de CIS a SP 800-53 Rev 5 o a CSF 2.0: solo ids y relacion.

    {"tipo": "sp800_53"|"csf2", "archivo", "por_salvaguarda": {id: [(destino, relacion)]}, "sin": [ids]}.
    `ids_validos`: ids de las salvaguardas del archivo de --cis. SystemExit si no sirve."""
    p, raw = _leer(ruta)
    cab = ", ".join(_CAB_MAPEO) + " y Control Identifier o CSF Subcategories"
    filas = _raw(p, raw, lambda fs: _tabla_mapeo(fs) is not None, (*_CAB_MAPEO, "Control Identifier|CSF Subcategories"))
    tab = _tabla_mapeo(filas)
    if not tab:
        raise SystemExit(f"[!] '{p.name}': no tiene las columnas del mapeo de CIS ({cab})")
    idx, pos, tipo = tab
    col_dest = "Control Identifier" if tipo == "sp800_53" else "CSF Subcategories"

    def celda(f, nombre):
        j = idx[nombre]
        return _norm(f[j]) if j < len(f) else ""

    por: dict = {}
    vigente, ordinal, previa, ident = "", {}, None, ""
    for n, f in enumerate(filas[pos + 1:], pos + 2):
        c = celda(f, "CIS Control")
        if c:
            vigente = c
        celda_id = celda(f, "CIS Safeguard")
        if not celda_id or not vigente:
            continue
        m = _NUM.match(vigente)
        if not m:
            continue
        control = m.group(0)
        if previa != (control, celda_id):
            ordinal[control] = ordinal.get(control, 0) + 1
            ident = _ident(p, control, celda_id, ordinal[control])
            previa = (control, celda_id)
        lista = por.setdefault(ident, [])
        valor = celda(f, col_dest)
        if not valor:
            continue
        par = (_destino(p, f"linea {n}", tipo, valor), celda(f, "Relationship"))
        if par not in lista:
            lista.append(par)
    if not por:
        raise SystemExit(f"[!] '{p.name}': el mapeo no tiene salvaguardas de CIS Controls")
    validos = set(ids_validos)
    fuera = [i for i in por if i not in validos]
    if fuera:
        raise SystemExit(f"[!] '{p.name}': el mapeo cita salvaguardas que no estan en el archivo de --cis "
                         f"(v8.1): {', '.join(fuera[:5])}")
    return {"tipo": tipo, "archivo": p.name, "por_salvaguarda": por, "sin": [i for i, v in por.items() if not v]}


def cargar_con_mapeos(ruta_cis, rutas_mapeo) -> tuple:
    """(salvaguardas, [mapeos]) de --cis y --cis-mapeo; dos mapeos del mismo tipo son un error."""
    cis = cargar(ruta_cis)
    ids = [s["id"] for s in cis]
    mapeos = []
    for r in rutas_mapeo or ():
        m = cargar_mapeo(r, ids)
        previo = next((x for x in mapeos if x["tipo"] == m["tipo"]), None)
        if previo:
            raise SystemExit(f"[!] '{m['archivo']}' y '{previo['archivo']}' son mapeos del mismo tipo "
                             f"({'SP 800-53 Rev 5' if m['tipo'] == 'sp800_53' else 'CSF 2.0'}): "
                             "entregue uno por tipo")
        mapeos.append(m)
    return cis, mapeos
