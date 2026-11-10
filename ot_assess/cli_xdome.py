"""Subcomando `xdome-descargar`: baja de la API de Claroty xDome lo que ya sabemos importar (E1e, D42)."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

from . import __version__
from .importers import xdome_api as xa
from .permisos import salida_privada
from .report.common import escritor_csv

RAIZ_REPO = Path(__file__).resolve().parent.parent
TOKEN_DEFECTO = "~/.config/xdome/token"

AYUDA = """
Ejemplo:
  python ot_pcap_assess.py xdome-descargar -o ~/datos/cliente_xdome
  python ot_pcap_assess.py diagrama --activos ~/datos/cliente_xdome/activos_xdome.csv \\
      --enlaces comunicaciones.csv --vulnerabilidades ~/datos/cliente_xdome/vulnerabilidades_xdome.csv \\
      --alertas ~/datos/cliente_xdome/alertas_xdome.csv

Solo lectura. El token es de un usuario API de solo lectura de xDome y se lee de un archivo con
permisos 0600; nunca se imprime ni se guarda. Los flujos (comunicaciones) no estan en esta API:
siguen viniendo de la exportacion «Communication» de la interfaz (docs/DECISIONES.md, D42).
"""


def crear_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="ot_pcap_assess.py xdome-descargar",
        description="Descarga de la API de xDome inventario, vulnerabilidades por dispositivo, alertas y "
                    "eventos, y los deja como CSV para --activos, --vulnerabilidades y --alertas.",
        epilog=AYUDA, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--out", required=True, metavar="CARPETA",
                    help="Carpeta de salida (fuera del repositorio: son datos del cliente).")
    ap.add_argument("--base", default=xa.BASE, metavar="URL", help="Base de la API (https). Defecto: %(default)s")
    ap.add_argument("--token-archivo", default=TOKEN_DEFECTO, metavar="ARCHIVO",
                    help="Archivo con el token (permisos 0600). Defecto: %(default)s")
    ap.add_argument("--version", action="version", version=f"ot_assess {__version__}")
    return ap


def _error(msg: str) -> int:
    print(f"[!] {msg}", file=sys.stderr)
    return 2


def _dentro(hijo: Path, padre: Path) -> bool:
    return hijo == padre or padre in hijo.parents


def leer_token(ruta: str) -> tuple:
    """-> (token, error). No devuelve el token en ningun mensaje."""
    p = Path(ruta).expanduser()
    try:
        st = p.stat()
        if os.name != "nt" and st.st_mode & 0o077:
            return None, (f"El archivo del token '{p.name}' tiene permisos {oct(st.st_mode & 0o777)[2:]}: "
                          "debe ser 0600 (chmod 600).")
        token = p.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as e:
        return None, f"No pude leer el archivo del token '{ruta}': {type(e).__name__}"
    if not token or re.search(r"\s", token):
        return None, f"El archivo del token '{p.name}' esta vacio o no es un solo valor."
    return token, None


def _csv(ruta: Path, cabecera: list, filas: list) -> None:
    with open(ruta, "w", newline="", encoding="utf-8") as fh:
        w = escritor_csv(fh)
        w.writerow(cabecera)
        w.writerows(filas)


@salida_privada
def main(argv=None, peticion=None, dormir=None) -> int:
    args = crear_parser().parse_args(argv)
    out = Path(args.out).expanduser().resolve()
    if _dentro(out, RAIZ_REPO):
        return _error(f"La carpeta '{args.out}' esta dentro del repositorio: la descarga es dato del cliente. "
                      "Use una carpeta fuera del repo.")
    if not args.base.lower().startswith("https://"):
        return _error("--base debe empezar con https:// (el token viajaria en claro).")
    token, falla = leer_token(args.token_archivo)
    if falla:
        return _error(falla)
    if out.exists() and not out.is_dir():
        return _error(f"'{args.out}' existe y no es una carpeta.")

    cli = xa.Cliente(args.base, token, peticion=peticion, dormir=dormir)
    try:
        res = xa.descargar_conjuntos(cli, lambda m: print(m.replace(token, "***")))
    except xa.ErrorApi as e:
        return _error(str(e).replace(token, "***"))
    if not any(regs for regs, _c in res.values()):
        return _error("La API no devolvio registros en ningun conjunto.")

    (out / "crudo").mkdir(parents=True, exist_ok=True, mode=0o700)
    for nombre, (regs, _campos) in res.items():
        with open(out / "crudo" / f"{nombre}.jsonl", "w", encoding="utf-8") as fh:
            fh.writelines(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in regs)

    activos = xa.filas_activos(res)
    vulns, sin_cve = xa.filas_vulnerabilidades(res)
    alertas, omit_al, sev_defecto = xa.filas_alertas(res)
    _csv(out / "activos_xdome.csv", xa.CAB_ACTIVOS, activos)
    _csv(out / "vulnerabilidades_xdome.csv", xa.CAB_VULNS, vulns)
    _csv(out / "alertas_xdome.csv", xa.CAB_ALERTAS, alertas)
    print(f"activos_xdome.csv: {len(activos)} filas")
    print(f"vulnerabilidades_xdome.csv: {len(vulns)} filas; pares sin CVE omitidos: {sin_cve}")
    print(f"alertas_xdome.csv: {len(alertas)} filas; omitidas: "
          f"{', '.join(f'{k} {v}' for k, v in omit_al.items()) or 'ninguna'}; "
          f"con severidad por defecto (no es dato de xDome): {sev_defecto}")
    print(f"Salida: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
