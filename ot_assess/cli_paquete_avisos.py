"""Subcomando `paquete-avisos`: arma y verifica el paquete de avisos ICS de CISA y KEV para sitios sin red (AVK1, D124)."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from . import entrega as ent
from . import paquete_avisos as pa
from .permisos import salida_privada

AYUDA = """
Ejemplos:
  python3 ot_pcap_assess.py paquete-avisos --avisos-ics ~/cisa/csaf --kev ~/cisa/known_exploited_vulnerabilities.json \\
      -o ~/medio/avisos_2026-11 [--zip]
  python3 ot_pcap_assess.py paquete-avisos --verificar ~/medio/avisos_2026-11     (carpeta o .zip)
  python3 ot_pcap_assess.py --paquete-avisos ~/medio/avisos_2026-11 ...          (corrida; solo carpeta)

La herramienta no descarga nada: usted obtiene los avisos y el KEV en un equipo con red. El paquete lleva
manifiesto_avisos.json y manifiesto_avisos.sha256 (formato sha256sum). Es evidencia de integridad del medio;
no firma ni cifra el paquete ni prueba su origen.
"""


def crear_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="ot_pcap_assess.py paquete-avisos",
        description="Arma el paquete verificable de avisos ICS (CSAF) y KEV de CISA, o lo verifica.",
        epilog=AYUDA, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--avisos-ics", metavar="RUTA", dest="avisos_ics",
                    help="Un aviso CSAF 2.0 (JSON) o una carpeta con muchos (recursiva).")
    ap.add_argument("--kev", metavar="ARCHIVO", help="Catalogo KEV de CISA (JSON o CSV).")
    ap.add_argument("-o", "--out", metavar="CARPETA",
                    help="Carpeta del paquete (con --zip, ademas CARPETA.zip). Debe no existir o estar vacia.")
    ap.add_argument("--zip", action="store_true", help="Escribir tambien un ZIP determinista.")
    ap.add_argument("--verificar", metavar="CARPETA_O_ZIP",
                    help="Comprueba un paquete. Codigo 0 si coincide, 2 si no.")
    ap.add_argument("--version", action="version", version=f"ot_assess {__version__}")
    return ap


def _verificar(ruta: str) -> int:
    try:
        r = pa.verificar(ruta)
    except ent.ErrorEntrega as e:
        print(f"[!] No se pudo verificar: {e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"[!] No se pudo leer '{ruta}': {e}", file=sys.stderr)
        return 2
    if r["problemas"]:
        for p in r["problemas"][:pa.MAX_PROBLEMAS]:
            print(f"[!] {p}")
        mas = len(r["problemas"]) - pa.MAX_PROBLEMAS
        if mas > 0:
            print(f"[!] ... y {mas} mas")
        print(f"NO COINCIDE: {len(r['problemas'])} problemas.")
        return 2
    print(f"OK: {r['archivos']} archivos coinciden con {pa.SUMAS}.")
    return 0


@salida_privada
def main(argv=None) -> int:
    ap = crear_parser()
    args = ap.parse_args(argv)
    if args.verificar:
        if args.avisos_ics or args.kev or args.out or args.zip:
            ap.error("--verificar no se combina con --avisos-ics, --kev, -o ni --zip")
        return _verificar(args.verificar)
    if not (args.avisos_ics or args.kev) or not args.out:
        ap.error("indica --avisos-ics y/o --kev, y -o CARPETA (o usa --verificar)")
    out = Path(args.out).expanduser()
    zip_ruta = Path(str(out) + ".zip")
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        print(f"[!] '{out}' ya existe y no esta vacia: elige otra carpeta.", file=sys.stderr)
        return 2
    if args.zip and zip_ruta.exists():
        print(f"[!] '{zip_ruta}' ya existe: elige otra carpeta.", file=sys.stderr)
        return 2
    fecha = ent.ahora_utc()
    try:
        contenidos, man = pa.construir(args.avisos_ics, args.kev, fecha)
        ent.escribir_carpeta(out, contenidos)
        if args.zip:
            ent.escribir_zip(zip_ruta, contenidos, fecha)
    except ent.ErrorEntrega as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2
    if man["csaf"]:
        c = man["csaf"]
        print(f"Avisos CSAF: {c['archivos']} JSON, {c['avisos_csaf']} avisos CSAF validos, {c['saltados']} saltados, "
              f"mas reciente {c['aviso_mas_reciente'] or 'sin fecha'}")
    if man["kev"]:
        k = man["kev"]
        print(f"KEV: {k['archivo']}, version {k['catalogVersion'] or 'sin version'}, "
              f"publicado {k['dateReleased'] or 'sin fecha'}, {k['registros']} registros")
    print(f"Paquete: {out}" + (f" y {zip_ruta}" if args.zip else ""))
    return 0
