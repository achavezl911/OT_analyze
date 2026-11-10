"""Subcomando `custodia`: registro encadenado de cadena de custodia de la evidencia (K1, D95)."""
from __future__ import annotations

import argparse
import sys

from . import __version__, i18n
from . import custodia as cu
from .permisos import salida_privada

AYUDA = """
Ejemplos:
  python ot_pcap_assess.py custodia registrar --registro custodia.jsonl --evento recepcion \\
      --entrega "Ing. A (cliente)" --recibe "Analista B" --medio "USB 64 GB" --cifrado BitLocker \\
      --ubicacion "Oficina, gabinete 2" captura1.pcap captura2.pcap
  python ot_pcap_assess.py custodia verificar --registro custodia.jsonl [captura1.pcap ...]
  python ot_pcap_assess.py custodia exportar --registro custodia.jsonl -o ~/entregas/custodia

El registro es de solo agregar: cada evento lleva el SHA-256 de la linea anterior, asi que editar o borrar
un evento en medio se detecta. Borrar los ULTIMOS eventos no se detecta con el archivo solo: comunique la
huella que imprime `verificar` por un canal aparte. El registro tiene nombres de personas: es dato del cliente.
La herramienta no cifra ni firma: el cifrado en reposo es del volumen (BitLocker, FileVault, LUKS, VeraCrypt)
o del contenedor, y aqui solo se declara. Es evidencia tecnica, no dictamen.
"""


def crear_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="ot_pcap_assess.py custodia",
        description="Registro de cadena de custodia encadenado por hash: registrar, verificar y exportar.",
        epilog=AYUDA, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"ot_assess {__version__}")
    sub = ap.add_subparsers(dest="accion", required=True)
    r = sub.add_parser("registrar", help="Agrega un evento al registro (valida la cadena antes).")
    r.add_argument("--registro", required=True, metavar="R.jsonl")
    r.add_argument("--evento", required=True, choices=cu.EVENTOS)
    for k in ("entrega", "recibe", "medio", "cifrado", "ubicacion", "nota"):
        r.add_argument(f"--{k}", default="", metavar="TEXTO")
    r.add_argument("--fecha", default=None, metavar="ISO",
                   help="Fecha UTC declarada (p. ej. 2026-11-08T15:00:00Z), para registrar a posteriori.")
    r.add_argument("rutas", nargs="*", metavar="RUTA", help="Archivos o carpetas (sin enlaces ni ocultos).")
    v = sub.add_parser("verificar", help="Verifica la cadena y, si se dan rutas, sus hash.")
    v.add_argument("--registro", required=True, metavar="R.jsonl")
    v.add_argument("rutas", nargs="*", metavar="RUTA")
    x = sub.add_parser("exportar", help="Escribe custodia.csv y custodia.html imprimible.")
    x.add_argument("--registro", required=True, metavar="R.jsonl")
    x.add_argument("-o", "--out", required=True, metavar="CARPETA")
    x.add_argument("--idioma", choices=i18n.IDIOMAS, default="es",
                   help="Idioma de custodia.html y de las cabeceras de custodia.csv (por defecto es).")
    return ap


def _registrar(ap, args) -> int:
    if not args.rutas and not (args.evento in cu.SIN_ARCHIVOS and args.nota):
        ap.error("indica al menos una RUTA (solo devolucion y destruccion admiten cero rutas, con --nota)")
    try:
        ev = cu.registrar(args.registro, args.evento, args.rutas, entrega=args.entrega, recibe=args.recibe,
                          medio=args.medio, cifrado=args.cifrado, ubicacion=args.ubicacion, nota=args.nota,
                          fecha=args.fecha)
    except ValueError as e:
        print(f"[!] Cadena rota, no se agrego nada: {e}", file=sys.stderr)
        return 1
    except (cu.ErrorCustodia, OSError) as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2
    print(f"OK: evento {ev['n']} ({ev['evento']}), {len(ev['archivos'])} archivos registrados.")
    return 0


def _verificar(args) -> int:
    try:
        a = cu.analizar(cu.leer(args.registro))
        rutas = cu.comparar_rutas(a, args.rutas) if args.rutas and a["rota"] is None else []
    except cu.ErrorCustodia as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2
    malo = a["rota"] is not None
    if malo:
        print(f"[!] CADENA ROTA: {a['mensaje']}")
    else:
        print(f"Cadena integra: {len(a['eventos'])} eventos.")
    for nombre, estado in rutas:
        print(f"{'[!] ' if estado != 'coincide' else ''}{estado.upper()}: {nombre}")
        malo = malo or estado != "coincide"
    if malo and a["rota"] is not None and args.rutas:
        print("No se comparo ninguna ruta: la cadena no es confiable.")
    print(f"Huella del registro (SHA-256 de la ultima linea): {a['huella']}")
    return 1 if malo else 0


def _exportar(args) -> int:
    anterior = i18n.idioma()
    i18n.usar(args.idioma)
    try:
        a = cu.exportar(args.registro, args.out)
    except cu.ErrorCustodia as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"[!] No se pudo escribir en '{args.out}': {e}", file=sys.stderr)
        return 2
    finally:
        i18n.usar(anterior)
    print(f"Escritos custodia.csv y custodia.html en {args.out}. Huella: {a['huella']}")
    if a["rota"] is not None:
        # La consola sigue en espanol: el mensaje de `a` pudo armarse en el idioma del export.
        print(f"[!] CADENA ROTA: {cu.analizar(cu.leer(args.registro))['mensaje']}", file=sys.stderr)
        return 1
    return 0


@salida_privada
def main(argv=None) -> int:
    ap = crear_parser()
    args = ap.parse_args(argv)
    if args.accion == "registrar":
        return _registrar(ap, args)
    if args.accion == "verificar":
        return _verificar(args)
    return _exportar(args)
