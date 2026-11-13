"""Subcomando `revisar-secretos`: escanea una carpeta de salida antes de entregarla (SEC1, D138)."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, secretos
from .i18n import t

AYUDA = """
Ejemplo:
  python ot_pcap_assess.py revisar-secretos ~/salidas/cliente_2026-11

Recorre csv, json, md, html, txt, svg, drawio y el XML dentro de xlsx y docx. Imprime por coincidencia el archivo,
el lugar (linea o parte del documento) y el tipo, con el valor enmascarado (2 primeros caracteres y ***).
Codigo 0 sin coincidencias, 3 con coincidencias, 2 si la carpeta no existe. Es una busqueda por patrones: sin
coincidencias no prueba que no haya secretos.
"""


def crear_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="ot_pcap_assess.py revisar-secretos",
        description="Busca secretos (comunidades SNMP, contrasenas, hashes, llaves, tokens) en una carpeta de salida.",
        epilog=AYUDA, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("carpeta", metavar="CARPETA", help="Carpeta de salida a revisar.")
    ap.add_argument("--version", action="version", version=f"ot_assess {__version__}")
    return ap


def imprimir(coincidencias: list) -> None:
    for c in coincidencias:
        print(f"[!] {secretos.linea(c)}")


def main(argv=None) -> int:
    args = crear_parser().parse_args(argv)
    carpeta = Path(args.carpeta).expanduser()
    if not carpeta.is_dir():
        print(t("[!] '{ruta}' no es una carpeta.", ruta=carpeta), file=sys.stderr)
        return 2
    cs = secretos.escanear(carpeta)
    if not cs:
        print(t("OK: sin coincidencias de secretos."))
        return 0
    imprimir(cs)
    print(t("{n} coincidencias de secretos: revisa y limpia antes de entregar.", n=len(cs)))
    return 3


if __name__ == "__main__":
    sys.exit(main())
