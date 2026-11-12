"""Subcomando `madurez`: plantilla del cuestionario de entrevista de madurez por dominio (M7, D84)."""
from __future__ import annotations

import argparse
from pathlib import Path

from . import __version__
from . import madurez as ma
from .i18n import IDIOMAS, t, usar
from .perfil import cargar as cargar_perfil
from .permisos import salida_privada

AYUDA = """
Ejemplo:
  python ot_pcap_assess.py madurez cuestionario -o cuestionario_madurez.csv
  (se contesta en la entrevista: columna 'respuesta' con 0 a 4, N/A o vacio)
  python ot_pcap_assess.py ~/capturas -o ~/datos/cliente --madurez cuestionario_madurez.csv

Ocho dominios y 32 preguntas. Escala 0 a 4 alineada a ML1-ML4 de IEC 62443. El nivel es lo que el sitio declara
en la entrevista; el analisis solo agrega la evidencia tecnica y marca donde no la respalda.
"""


def crear_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="ot_pcap_assess.py madurez",
        description="Madurez de ciberseguridad OT por dominio: plantilla del cuestionario de entrevista.",
        epilog=AYUDA, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"ot_assess {__version__}")
    sub = ap.add_subparsers(dest="accion", required=True)
    c = sub.add_parser("cuestionario", help="Escribe la plantilla del cuestionario (CSV, UTF-8 con BOM).")
    c.add_argument("-o", "--out", required=True, metavar="ARCHIVO.csv", help="Archivo CSV de la plantilla.")
    c.add_argument("--idioma", choices=IDIOMAS, default="es", help="Idioma de la plantilla (por defecto es).")
    c.add_argument("--perfil", metavar="JSON",
                   help="Perfil del proyecto: si trae 'escala_madurez', la columna escala de la plantilla muestra "
                        "la escala del proyecto (valor = nombre: descripcion).")
    return ap


@salida_privada
def main(argv=None) -> int:
    args = crear_parser().parse_args(argv)
    usar(args.idioma)
    ruta = Path(args.out)
    if not ruta.parent.is_dir():
        crear_parser().error(f"la carpeta '{ruta.parent}' no existe")
    esc = None
    if args.perfil:
        if not Path(args.perfil).is_file():
            crear_parser().error(f"--perfil espera un archivo existente: '{args.perfil}'")
        esc = ma.escala_de(cargar_perfil(args.perfil))
    ma.escribir_cuestionario(ruta, escala=esc)
    rango = (esc["min"], esc["max"]) if esc and esc["proyecto"] else (0, 4)
    print(f"[OK] {ruta}: {len(ma.preguntas())} preguntas en {len(ma.claves())} dominios. "
          + (t("Contestar la columna respuesta (0 a 4, N/A o vacio).") if rango == (0, 4) else
             t("Contestar la columna respuesta ({lo} a {hi}, N/A o vacio).", lo=rango[0], hi=rango[1])))
    return 0
