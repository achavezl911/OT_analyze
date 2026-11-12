"""Subcomando `sitios`: consolidado del programa desde las carpetas de salida de varios sitios (M1, D94)."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from . import sitios as st
from .i18n import IDIOMAS, t
from .permisos import salida_privada

AYUDA = """
Ejemplo:
  python ot_pcap_assess.py sitios ~/datos/planta_a ~/datos/planta_b ~/datos/planta_c -o ~/datos/programa

Lee los CSV publicos de cada carpeta de salida (hallazgos, riesgos, madurez, inventario normalizado,
vulnerabilidades de firmware, eventos de ingenieria y salud de red) y de resultado.json solo cliente, sitio,
idioma y version. El libro siempre trae las mismas hojas y columnas; si falta un archivo, avisa y esa hoja no
recibe filas de ese sitio. Son datos agregados de evidencia tecnica, no un dictamen de cumplimiento.
"""


def crear_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="ot_pcap_assess.py sitios",
        description="Consolida las carpetas de salida de varios sitios en un libro de hojas fijas.",
        epilog=AYUDA, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("carpetas", nargs="+", metavar="CARPETA_SITIO", help="Carpeta de salida de cada sitio.")
    ap.add_argument("--nombre", action="append", default=[], metavar="CARPETA=NOMBRE",
                    help="Nombre del sitio para esa carpeta (manda sobre el perfil; repetible).")
    ap.add_argument("--idioma", choices=IDIOMAS, default=None,
                    help="Idioma de hojas y cabeceras (defecto: el del primer sitio).")
    ap.add_argument("-o", "--out", required=True, metavar="CARPETA", help="Carpeta de salida (datos del cliente).")
    ap.add_argument("--version", action="version", version=f"ot_assess {__version__}")
    return ap


def _nombres(pares: list, carpetas: list) -> dict:
    out = {}
    conocidas = {Path(c).expanduser().resolve() for c in carpetas}
    for p in pares:
        carpeta, sep, nombre = p.rpartition("=")
        if not sep or not carpeta or not nombre.strip():
            raise st.ErrorSitios(f"--nombre espera CARPETA=NOMBRE, no '{p}'")
        ruta = Path(carpeta).expanduser().resolve()
        if ruta not in conocidas:
            raise st.ErrorSitios(f"--nombre apunta a '{carpeta}', que no esta entre las carpetas")
        out[ruta] = nombre.strip()
    return out


@salida_privada
def main(argv=None) -> int:
    args = crear_parser().parse_args(argv)
    out = Path(args.out).expanduser()
    if out.exists() and not out.is_dir():
        print(f"[!] '{args.out}' existe y no es una carpeta.", file=sys.stderr)
        return 2
    sal = out.resolve()
    for c in args.carpetas:
        cr = Path(c).expanduser().resolve()
        if sal == cr or cr in sal.parents:
            print("[!] " + t("el consolidado mezcla sitios: escribelo fuera de las carpetas de cada sitio"),
                  file=sys.stderr)
            return 2
    try:
        r = st.consolidar(args.carpetas, _nombres(args.nombre, args.carpetas))
    except st.ErrorSitios as e:
        print(f"[!] No se genero nada: {e}", file=sys.stderr)
        return 2
    archivos = st.escribir(out, r, args.idioma)
    print(f"Consolidado: {len(r['sitios'])} sitios, {len(r['tablas']['Hallazgos comunes'])} hallazgos distintos")
    print(t(st.USO))
    for a in r["avisos"]:
        print(f"[!] {a}")
    print("     " + "\n     ".join(str(out / a) for a in archivos))
    return 0


if __name__ == "__main__":
    sys.exit(main())
