"""Subcomando `politica-fmc`: exporta la politica propuesta (M3a, revisada por el analista) a Cisco FMC 7.6 (M3b, D48)."""
from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from . import __version__, perfil
from .firewalls import exportar, fmc
from .permisos import salida_privada

AYUDA = """
Ejemplo:
  python ot_pcap_assess.py politica-fmc --propuesta salida/politica_propuesta.csv \\
      --objetos salida/politica_objetos.csv -o ~/datos/cliente_fmc
  cd ~/datos/cliente_fmc && python3 aplicar_fmc.py          # simula
  python3 aplicar_fmc.py --aplicar                          # crea (pide escribir SI)
  python ot_pcap_assess.py politica-fmc --formato fortios|checkpoint|panos ...   # archivos de comandos (M4)

Sin --incluir-revisar solo se exportan las filas con decision = permitir; con la opcion, las revisar entran
DESHABILITADAS y con comentario. Las bloquear nunca generan regla. La herramienta no se conecta a ningun FMC.
"""


def crear_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="ot_pcap_assess.py politica-fmc",
        description="Genera la carga para Cisco FMC 7.6 (objetos y reglas en JSON y un script que por defecto "
                    "solo simula) a partir de politica_propuesta.csv y politica_objetos.csv.",
        epilog=AYUDA, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--propuesta", required=True, metavar="CSV", help="politica_propuesta.csv (editado por el analista)")
    ap.add_argument("--objetos", required=True, metavar="CSV", help="politica_objetos.csv (editado por el analista)")
    ap.add_argument("-o", "--out", required=True, metavar="CARPETA", help="Carpeta de salida (datos del cliente).")
    ap.add_argument("--politica", metavar="NOMBRE",
                    help="Nombre de la politica de acceso NUEVA. Defecto: PROPUESTA_<firewall>_<AAAAMMDD>")
    ap.add_argument("--incluir-revisar", action="store_true",
                    help="Exporta tambien las decision = revisar, deshabilitadas y con comentario.")
    ap.add_argument("--formato", choices=exportar.FORMATOS, default="fmc",
                    help="fmc (defecto: JSON y script para la API de FMC), fortios, checkpoint o panos (archivos de "
                         "comandos para revisar y aplicar).")
    ap.add_argument("--capa", metavar="NOMBRE", help="Check Point: capa de la politica (defecto: Network).")
    ap.add_argument("--vsys", metavar="NOMBRE", help="PAN-OS: vsys destino (ej. vsys1); sin la opcion, 'set ...'.")
    ap.add_argument("--version", action="version", version=f"ot_assess {__version__}")
    return ap


@salida_privada
def main(argv=None) -> int:
    args = crear_parser().parse_args(argv)
    msg = perfil.deshabilitado("politica-fmc", args.propuesta)
    if msg:
        print("[!] No se genero nada: " + msg, file=sys.stderr)
        return 2
    try:
        prop, objs = fmc.leer_entradas(args.propuesta, args.objetos)
        nombre = args.politica or fmc.nombre_politica_defecto(args.propuesta, datetime.now().strftime("%Y%m%d"))
        res = fmc.construir(prop, objs, nombre, args.incluir_revisar)
    except fmc.ErrorFmc as e:
        print("[!] No se genero nada:\n" + str(e), file=sys.stderr)
        return 2
    out = Path(args.out).expanduser()
    if out.exists() and not out.is_dir():
        print(f"[!] '{args.out}' existe y no es una carpeta.", file=sys.stderr)
        return 2
    if args.formato != "fmc":
        try:
            gen = exportar.generar(args.formato, res, capa=args.capa, vsys=args.vsys)
        except fmc.ErrorFmc as e:
            print("[!] No se genero nada:\n" + str(e), file=sys.stderr)
            return 2
        res["avisos"] = gen["avisos"]
        archivos = exportar.escribir(gen["archivos"], out)
    else:
        archivos = fmc.escribir(res, out)
    for a in res["avisos"]:
        print("[aviso] " + a)
    n_rev = sum(1 for r in res["reglas"] if not r["enabled"])
    print(f"Politica nueva '{res['politica']}': {len(res['reglas'])} reglas ({n_rev} deshabilitadas por revisar); "
          f"omitidas: {res['omitidas']['bloquear']} bloquear, {res['omitidas']['revisar']} revisar.")
    print("Escrito en " + str(out) + ": " + ", ".join(archivos))
    if args.formato == "fmc":
        print("Siguiente paso: lea LEEME_FMC.txt y ejecute aplicar_fmc.py (simula por defecto).")
    else:
        print(f"Siguiente paso: lea {exportar.LEEME_ARCHIVO[args.formato]}, revise {exportar.ARCHIVO[args.formato]} "
              "y apliquelo en una ventana de cambio.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
