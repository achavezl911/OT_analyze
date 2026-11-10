"""Subcomando `comparar`: que cambio entre dos corridas de la herramienta (E4, D62)."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from . import comparar as cmp
from .permisos import salida_privada

AYUDA = """
Ejemplo:
  python ot_pcap_assess.py comparar --antes ~/datos/cliente_antes --despues ~/datos/cliente_despues \\
      -o ~/datos/cliente_cambios

Lee los CSV publicos de cada corrida (inventario, comunicaciones, control, hallazgos y, si existe en ambas,
firewall_contraste). Escribe comparacion_*.csv, comparacion.json, comparacion.md y comparacion.html. El volumen
depende de la ventana de captura de cada corrida: una razon alta puede ser solo una ventana mas larga.
"""


def crear_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="ot_pcap_assess.py comparar",
        description="Compara dos corridas (antes y despues): activos, conductos, escritores, hallazgos y firewall.",
        epilog=AYUDA, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--antes", required=True, metavar="CARPETA", help="Carpeta de salida de la corrida anterior.")
    ap.add_argument("--despues", required=True, metavar="CARPETA", help="Carpeta de salida de la corrida posterior.")
    ap.add_argument("--umbral-volumen", type=float, default=cmp.UMBRAL_DEFECTO, metavar="N",
                    help="Razon de bytes despues/antes, en cualquier sentido, desde la que se marca (defecto: 10).")
    ap.add_argument("-o", "--out", required=True, metavar="CARPETA", help="Carpeta de salida (datos del cliente).")
    ap.add_argument("--version", action="version", version=f"ot_assess {__version__}")
    return ap


@salida_privada
def main(argv=None) -> int:
    args = crear_parser().parse_args(argv)
    out = Path(args.out).expanduser()
    if out.exists() and not out.is_dir():
        print(f"[!] '{args.out}' existe y no es una carpeta.", file=sys.stderr)
        return 2
    try:
        r = cmp.comparar(args.antes, args.despues, args.umbral_volumen)
    except cmp.ErrorComparar as e:
        print("[!] No se genero nada:\n" + str(e), file=sys.stderr)
        return 2
    archivos = cmp.escribir(out, r)
    print("Comparacion: " + (", ".join(f"{k}: {v['cambios']}" for k, v in r["resumen"].items()) or "sin datos"))
    for a in r["avisos"]:
        print(f"[!] {a}")
    print("     " + "\n     ".join(str(out / a) for a in archivos))
    return 0


if __name__ == "__main__":
    sys.exit(main())
