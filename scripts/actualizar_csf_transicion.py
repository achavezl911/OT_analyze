"""Genera ot_assess/marcos/csf_transicion.json desde la hoja oficial de NIST "CSF 1.1 to 2.0 Core Transition Changes".

Uso: python3 scripts/actualizar_csf_transicion.py XLSX [--salida RUTA] [--check]

El xlsx (normas/nist/, ignorada por git) se descarga aparte. Se copian los textos oficiales tal cual
(recortando espacios de los extremos); no se copian los Implementation Examples ni los SORT-ID.
Con --check no escribe: compara y sale 1 si el archivo de salida difiere.
"""
import argparse
import json
import os
import sys
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from ot_assess.importers.lector import leer_xlsx_hojas

MAX_BYTES = 64 * 1024 * 1024
SALIDA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ot_assess", "marcos", "csf_transicion.json")
HOJA = "Change Analysis CSF 1.1-2.0"
URL = "https://www.nist.gov/system/files/documents/2024/09/19/CSF%201.1%20to%202.0%20Core%20Transition%20Changes.xlsx"
FECHA = "2024-09-19"
DERECHOS = ("Obra del gobierno de EE. UU., dominio publico (17 U.S.C. 105). Fuente: NIST, CSF 1.1 to 2.0 Core "
            "Transition Changes.")
# (clave en el json, columna oficial)
COLUMNAS = [("id_11", "CSF 1.1 Identifier"), ("descripcion_11", "CSF 1.1 Description"),
            ("reubicacion", "Relocation"), ("modificaciones", "Noteworthy Modifications"),
            ("id_20", "CSF 2.0 Identifier"), ("descripcion_20", "CSF 2.0 Description"),
            ("nueva_en_20", "New in CSF 2.0")]


def construir(raw, nombre_archivo):
    try:
        hojas = dict(leer_xlsx_hojas(raw))
    except (zipfile.BadZipFile, KeyError, ValueError, SyntaxError) as e:
        raise SystemExit(f"El archivo no es un .xlsx legible: {e}")
    if HOJA not in hojas:
        raise SystemExit(f"Falta la hoja '{HOJA}'.")
    datos = hojas[HOJA]
    if not datos:
        raise SystemExit(f"La hoja '{HOJA}' esta vacia.")
    cab = [c.strip() for c in datos[0]]
    pos = []
    for _clave, col in COLUMNAS:
        if col not in cab:
            raise SystemExit(f"Falta la columna '{col}' en la hoja '{HOJA}'.")
        pos.append(cab.index(col))
    filas = []
    for r in datos[1:]:
        if not any((c or "").strip() for c in r):
            continue
        filas.append({clave: (r[p].strip() if p < len(r) else "") for (clave, _c), p in zip(COLUMNAS, pos)})
    if not filas:
        raise SystemExit(f"La hoja '{HOJA}' no trae filas de datos.")
    return {
        "marco": "NIST CSF 1.1 a 2.0 (transicion oficial del Core)",
        "fuente": "NIST, CSF 1.1 to 2.0 Core Transition Changes (" + nombre_archivo + ")",
        "url": URL,
        "fecha": FECHA,
        "derechos": DERECHOS,
        "filas": filas,
    }


def serializar(cat):
    return json.dumps(cat, ensure_ascii=False, indent=1) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("xlsx")
    ap.add_argument("--salida", default=SALIDA)
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args(argv)
    if os.path.getsize(a.xlsx) > MAX_BYTES:
        raise SystemExit(f"El archivo supera el limite de {MAX_BYTES // (1024 * 1024)} MB.")
    with open(a.xlsx, "rb") as f:
        raw = f.read()
    texto = serializar(construir(raw, "CSF 1.1 to 2.0 Core Transition Changes.xlsx"))
    if a.check:
        try:
            with open(a.salida, encoding="utf-8") as f:
                igual = f.read() == texto
        except OSError:
            igual = False
        if not igual:
            print("csf_transicion.json difiere del xlsx: regenera con scripts/actualizar_csf_transicion.py",
                  file=sys.stderr)
            return 1
        return 0
    with open(a.salida, "w", encoding="utf-8", newline="\n") as f:
        f.write(texto)
    return 0


if __name__ == "__main__":
    sys.exit(main())
