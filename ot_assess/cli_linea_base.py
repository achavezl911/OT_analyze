"""Subcomando `linea-base`: aprobar una corrida como referencia de un sitio y verificarla (LB1, D82)."""
from __future__ import annotations

import argparse
import sys

from . import __version__
from . import linea_base_aprobada as lba
from .permisos import salida_privada

AYUDA = """
Ejemplo:
  python ot_pcap_assess.py linea-base aprobar ~/datos/cliente_corrida -o ~/datos/cliente_linea_base \\
      --sitio "Planta 1" --aprobado-por "Ana Perez" --revisado-por "Luis Gomez"
  python ot_pcap_assess.py linea-base verificar ~/datos/cliente_linea_base
  python ot_pcap_assess.py ~/capturas -o ~/datos/cliente_nueva --linea-base ~/datos/cliente_linea_base

'aprobar' copia de la corrida solo lo necesario (inventario, comunicaciones, control, hallazgos, linea base de
trafico, periodicidad, firewall y resultado.json), nunca capturas, cache ni mapas de anonimizacion, y escribe
linea_base_aprobada.json con el manifiesto SHA-256. La carpeta es inmutable: para cambiarla se aprueba otra.
Quien aprueba y quien revisa deben ser personas distintas.
"""


def crear_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="ot_pcap_assess.py linea-base",
        description="Linea base aprobada de un sitio: aprobar una corrida como referencia y verificar que sigue intacta.",
        epilog=AYUDA, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"ot_assess {__version__}")
    sub = ap.add_subparsers(dest="accion", required=True)
    a = sub.add_parser("aprobar", help="Aprueba una corrida como linea base del sitio.")
    a.add_argument("corrida", metavar="CORRIDA", help="Carpeta de salida de la corrida que se aprueba.")
    a.add_argument("-o", "--out", required=True, metavar="CARPETA",
                   help="Carpeta nueva o vacia de la linea base (datos del cliente).")
    a.add_argument("--sitio", required=True, metavar="NOMBRE", help="Nombre del sitio.")
    a.add_argument("--aprobado-por", required=True, metavar="NOMBRE", dest="aprobado_por")
    a.add_argument("--revisado-por", default="", metavar="NOMBRE", dest="revisado_por",
                   help="Segunda persona que reviso la corrida; debe ser distinta de quien aprueba.")
    a.add_argument("--nota", default="", metavar="TEXTO", help="Nota libre (alcance, ventana de operacion...).")
    v = sub.add_parser("verificar", help="Recalcula los hash de una linea base aprobada.")
    v.add_argument("carpeta", metavar="CARPETA")
    return ap


@salida_privada
def main(argv=None) -> int:
    args = crear_parser().parse_args(argv)
    if args.accion == "verificar":
        errores = lba.verificar(args.carpeta)
        if errores:
            print("[!] La linea base aprobada no esta intacta:\n    " + "\n    ".join(errores), file=sys.stderr)
            return 1
        print(f"OK: {args.carpeta} coincide con su manifiesto SHA-256.")
        return 0
    try:
        r = lba.aprobar(args.corrida, args.out, args.sitio, args.aprobado_por, args.revisado_por, args.nota)
    except lba.ErrorLineaBase as e:
        print("[!] No se aprobo nada: " + str(e), file=sys.stderr)
        return 2
    for adv in r["avisos"]:
        print(f"[!] {adv}")
    print(f"Linea base aprobada en {r['carpeta']}: {len(r['archivos'])} archivos, manifiesto en {lba.ARCHIVO}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
