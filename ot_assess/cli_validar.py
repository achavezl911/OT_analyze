"""Subcomando `politica-validar`: que romperia la politica propuesta con el trafico de otra ventana (M5, D67)."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .firewalls import politica
from .firewalls import validar_politica as vp
from .permisos import salida_privada

AYUDA = """
Ejemplo:
  python ot_pcap_assess.py politica-validar --propuesta salida/politica_propuesta.csv \\
      --objetos salida/politica_objetos.csv --cruces salida_otra_ventana/ -o ~/datos/cliente_validacion

--cruces es la carpeta de salida de otra corrida hecha con --firewall del MISMO equipo (o su
firewall_cruces_detalle.csv); se puede repetir y los cruces iguales se suman. Escribe validacion_cruces.csv,
validacion_reglas.csv y validacion.md. Categorias: sigue_permitido, se_romperia (hoy cruza y la propuesta no lo
permite), bloqueo_decidido, sigue_bloqueado, se_abriria,
probable_respuesta (puerto dinamico con cruce inverso a puerto bajo: respuesta por estado). Sin --incluir-revisar las reglas revisar no se evaluan.
La ventana nueva tambien es parcial: no prueba que no falte nada. Codigo de salida 0 aunque haya se_romperia.
"""


def crear_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="ot_pcap_assess.py politica-validar",
        description="Evalua politica_propuesta.csv y politica_objetos.csv contra los cruces de otra ventana de "
                    "trafico: que dejaria de pasar, que casi coincide con una regla y que reglas no se usaron.",
        epilog=AYUDA, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--propuesta", required=True, metavar="CSV", help="politica_propuesta.csv (editado por el analista)")
    ap.add_argument("--objetos", required=True, metavar="CSV", help="politica_objetos.csv (editado por el analista)")
    ap.add_argument("--cruces", required=True, action="append", metavar="RUTA",
                    help="Carpeta de salida de otra corrida o su firewall_cruces_detalle.csv (se puede repetir).")
    ap.add_argument("-o", "--out", required=True, metavar="CARPETA", help="Carpeta de salida (datos del cliente).")
    ap.add_argument("--incluir-revisar", action="store_true",
                    help="Evalua las decision = revisar como permitir (igual que politica-fmc --incluir-revisar).")
    ap.add_argument("--zonas-fw", metavar="CSV",
                    help="Zonas por interfaz (firewall,interfaz,zona); solo se usa en reglas sin columna interfaces.")
    ap.add_argument("--firewall-nombre", action="append", default=[], metavar="TEXTO",
                    help="Nombre del firewall en --zonas-fw (se puede repetir).")
    ap.add_argument("--version", action="version", version=f"ot_assess {__version__}")
    return ap


@salida_privada
def main(argv=None) -> int:
    args = crear_parser().parse_args(argv)
    out = Path(args.out).expanduser()
    if out.exists() and not out.is_dir():
        print(f"[!] '{out.name}' existe y no es una carpeta.", file=sys.stderr)
        return 2
    try:
        zonas = None
        if args.zonas_fw:
            try:
                zonas = politica.cargar_zonas(args.zonas_fw)
            except ValueError as e:
                raise vp.ErrorValidar(str(e).replace(args.zonas_fw, Path(args.zonas_fw).name))
        res = vp.validar(args.propuesta, args.objetos, args.cruces, args.incluir_revisar, zonas,
                         args.firewall_nombre)
    except vp.ErrorValidar as e:
        print("[!] No se valido nada:\n" + str(e), file=sys.stderr)
        return 2
    archivos = vp.escribir(res, out, args.incluir_revisar, args.cruces)
    for k, (n, con) in vp.resumen(res).items():
        print(f"{k}: {n} cruces ({con} conductos)")
    sin = sum(1 for r in res["reglas"] if r["sin_uso"] == "si")
    print(f"Reglas de la propuesta sin uso en la ventana nueva: {sin} de {len(res['reglas'])}.")
    print("Escrito en " + str(out) + ": " + ", ".join(archivos))
    print("La ventana nueva tambien es parcial: no prueba que no falte nada.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
