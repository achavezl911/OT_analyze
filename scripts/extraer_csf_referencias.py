"""CIS1 (D108): extrae de la descarga publica de NIST CPRT las referencias informativas de CSF 2.0 que usa la
matriz de controles: por subcategoria, solo identificadores (salvaguardas de CIS Controls v8.1 y controles de
SP 800-53). No guarda titulos ni texto de NIST ni de CIS.

Uso:  python3 scripts/extraer_csf_referencias.py          # regenera ot_assess/marcos/csf2_referencias.json
      python3 scripts/extraer_csf_referencias.py --check  # compara; no falla si normas/ no existe (CI)
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from ot_assess.importers.lector import leer_xlsx_hojas

ORIGEN = RAIZ / "normas" / "nist" / "CSF_2.0_Core_referencias_informativas.xlsx"
DESTINO = RAIZ / "ot_assess" / "marcos" / "csf2_referencias.json"
HOJA = "CSF 2.0"
_SUB = re.compile(r"^([A-Z]{2}\.[A-Z]{2}-\d+)")
_CIS = re.compile(r"^CIS Controls v8\.1:\s*(\d+\.\d+)\s*$")
_800_53 = re.compile(r"^SP 800-53 Rev 5\.2\.0:\s*([A-Z]{2})-0*(\d+)((?:\(0*\d+\))?)\s*$")
META = {
    "fuente": "NIST CSF 2.0 Core con referencias informativas (descarga publica de NIST CPRT)",
    "url": "https://csrc.nist.gov/projects/cybersecurity-framework/filters#/csf/filters",
    "fecha_descarga": "2026-11-10",
    "aviso": ("Solo identificadores. Una correspondencia entre marcos no es equivalencia ni prueba de "
              "cumplimiento. CIS Controls v8.1: referencias a salvaguardas; ids de SP 800-53 Rev 5.2.0 "
              "normalizados (AC-02 -> AC-2; CP-02(08) -> CP-2(8))."),
}


def _norm_800(linea: str) -> str:
    m = _800_53.match(linea.strip())
    if not m:
        return ""
    mejora = re.sub(r"\(0*(\d+)\)", r"(\1)", m.group(3))
    return f"{m.group(1)}-{m.group(2)}{mejora}"


def _clave_cis(i: str) -> tuple:
    return tuple(int(x) for x in i.split("."))


def extraer(raw: bytes) -> dict:
    hojas = dict(leer_xlsx_hojas(raw))
    filas = hojas.get(HOJA)
    if not filas or len(filas) < 3:
        raise SystemExit(f"[!] el libro no tiene la hoja '{HOJA}'")
    cab = [c.strip() for c in filas[1]]
    try:
        i_sub, i_ref = cab.index("Subcategory"), cab.index("Informative References")
    except ValueError:
        raise SystemExit("[!] la hoja no tiene las columnas Subcategory e Informative References en la fila 2")
    subs = {}
    for f in filas[2:]:
        m = _SUB.match(f[i_sub]) if len(f) > i_sub else None
        if not m:
            continue
        lineas = (f[i_ref] if len(f) > i_ref else "").split("\n")
        cis = {_CIS.match(x.strip()).group(1) for x in lineas if _CIS.match(x.strip())}
        sp = {_norm_800(x) for x in lineas} - {""}
        subs[m.group(1)] = {"cis_v8_1": sorted(cis, key=_clave_cis),
                            "sp800_53": sorted(sp, key=lambda c: (c.split("-")[0],
                                                                  [int(n) for n in re.findall(r"\d+", c)]))}
    return {**META, "subcategorias": subs}


def texto(datos: dict) -> str:
    return json.dumps(datos, ensure_ascii=False, indent=1, sort_keys=False) + "\n"


def main(argv: list) -> int:
    check = "--check" in argv
    if not ORIGEN.exists():
        print(f"[i] {ORIGEN.relative_to(RAIZ)} no existe: no se {'compara' if check else 'regenera'}")
        return 0
    datos = extraer(ORIGEN.read_bytes())
    if check:
        if not DESTINO.exists() or json.loads(DESTINO.read_text(encoding="utf-8")) != datos:
            print(f"[!] {DESTINO.relative_to(RAIZ)} no corresponde al xlsx de NIST: regenerar sin --check")
            return 1
        print("[ok] csf2_referencias.json corresponde al xlsx")
        return 0
    DESTINO.write_text(texto(datos), encoding="utf-8")
    cis = {c for s in datos["subcategorias"].values() for c in s["cis_v8_1"]}
    print(f"[ok] {len(datos['subcategorias'])} subcategorias, {len(cis)} salvaguardas CIS distintas")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
