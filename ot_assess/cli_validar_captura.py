"""Subcomando `validar-captura`: el sensor sirve? Validacion de cobertura en una sola pasada de tshark (C1, D80).

Pensado para el primer dia en sitio: sin inventario, hallazgos ni reportes completos; solo la validacion de
`cobertura_captura.py` con los campos minimos de `fields.COBERTURA_FIELDS`.
"""
from __future__ import annotations

import argparse
import shutil
import sys
import time
from pathlib import Path

from . import __version__, i18n
from . import cobertura_captura as cc
from .cli import collect_inputs
from .fields import COBERTURA_FIELDS
from .perfil import cargar as cargar_perfil
from .permisos import salida_privada
from .report.common import escritor_csv
from .report.validacion import write_validacion
from .tools import CapturaIlegible, Tshark, find_tool
from .util import human

AYUDA = """
Ejemplo (primer dia, carpeta con los archivos rotados del sensor):
  python ot_pcap_assess.py validar-captura capturas_sitio_a/ -o validacion --perfil perfil.json \\
      --switch sw1.txt --vlans-esperadas 10,20

Una carpeta es un punto de captura (con un solo archivo suelto, el punto es el archivo). Escribe
cobertura_captura.csv (una fila por punto y una por archivo), cobertura_zonas.csv y validacion_captura.html.
Veredicto por punto: apta, apta con limitaciones o no apta, con los motivos (constantes en D80, sin calibrar).
No es un resultado de cumplimiento. Sin muestreo: lee todos los paquetes.
"""


def crear_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="ot_pcap_assess.py validar-captura",
        description="Valida si la captura sirve: perdidas del espejo, un solo sentido, huecos, truncamiento, VLAN y "
                    "zonas sin trafico y protocolos industriales vistos. Una sola pasada de tshark.",
        epilog=AYUDA, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="+", metavar="CAPTURAS", help="Archivos pcap/pcapng o carpetas con ellos.")
    ap.add_argument("-o", "--out", default="validacion_captura", metavar="CARPETA",
                    help="Carpeta de salida (datos del cliente). Por defecto: %(default)s")
    ap.add_argument("--perfil", metavar="JSON", help="Perfil del proyecto: zonas y vlans_esperadas.")
    ap.add_argument("--switch", action="append", default=[], metavar="ARCHIVO",
                    help="Salida de la CLI de un switch Cisco IOS/IOS-XE: las VLAN que su SPAN espeja se esperan.")
    ap.add_argument("--vlans-esperadas", default="", metavar="10,20", help="VLAN que deben verse (separadas por coma).")
    ap.add_argument("--tshark", metavar="RUTA", help="Carpeta o ejecutable de tshark.")
    ap.add_argument("--idioma", choices=i18n.IDIOMAS, help="Idioma de la salida (por defecto, el del perfil o es).")
    ap.add_argument("--version", action="version", version=f"ot_assess {__version__}")
    return ap


def leer_archivo(ts: Tshark, f: Path, campos: list) -> dict:
    """Una pasada de tshark; devuelve cobertura_captura.Acumulador.cerrar()."""
    acum = cc.Acumulador({c: i for i, c in enumerate(campos)})
    for row in ts.fields_pass(f, campos, None, 0):
        acum.fila(row)
    return acum.cerrar()


@salida_privada
def main(argv=None) -> int:
    t0 = time.monotonic()
    ap = crear_parser()
    args = ap.parse_args(argv)
    vlans = []
    for v in (x.strip() for x in args.vlans_esperadas.split(",") if x.strip()):
        if not v.isdigit() or not 1 <= int(v) <= 4094:
            ap.error(f"--vlans-esperadas: '{v}' no es una VLAN (1 a 4094)")
        vlans.append(str(int(v)))
    for f in args.switch:
        if not Path(f).is_file():
            ap.error(f"--switch espera un archivo existente: '{f}'")
    perfil = cargar_perfil(args.perfil) if args.perfil else {}
    i18n.usar(args.idioma or perfil.get("idioma", "es"))
    span = set()
    if args.switch:
        from .switches import integracion as _sw
        try:
            span = cc.vlans_del_span(_sw.integrar(args.switch, {}))
        except ValueError as e:
            ap.error(str(e))
    files = collect_inputs(args.inputs)
    if not files:
        print("[!] No hay capturas que analizar.", file=sys.stderr)
        return 1
    out = Path(args.out).expanduser()
    if out.exists() and not out.is_dir():
        print(f"[!] '{out.name}' existe y no es una carpeta.", file=sys.stderr)
        return 2
    out.mkdir(parents=True, exist_ok=True)
    ts = Tshark(find_tool("tshark", args.tshark), find_tool("capinfos", args.tshark),
                find_tool("editcap", args.tshark), out / ".probe")
    ts.make_probe(files[0])
    campos = ts.valid_fields(COBERTURA_FIELDS)
    shutil.rmtree(out / ".probe", ignore_errors=True)
    archivos = []
    for i, f in enumerate(files, 1):
        print(f"[{i}/{len(files)}] {f.name} ({human(f.stat().st_size)})")
        try:
            archivos.append({"path": f, "dato": leer_archivo(ts, f, campos), "error": ""})
        except CapturaIlegible as e:
            print(f"    [!] ILEGIBLE, no se valida: {e}", file=sys.stderr)
            archivos.append({"path": f, "dato": {}, "error": str(e)})
    rep = cc.construir(archivos, perfil, vlans, span)
    if not rep:
        print("[!] Ninguna captura legible con paquetes; no se genera salida.", file=sys.stderr)
        return 1
    for nombre, _hoja, cab, filas in cc.tablas(rep):
        with open(out / nombre, "w", newline="", encoding="utf-8-sig") as fh:
            w = escritor_csv(fh)
            w.writerow([i18n.t(c) for c in cab])
            w.writerows(filas)
    pagina = write_validacion(rep, out, perfil)
    for p in rep["puntos"]:
        print(f"{p['punto']}: {p['veredicto'].upper()}")
        for m in p["motivos"]:
            print(f"    - {m}")
    print(f"Escrito en {out}: {cc.ARCHIVO}, {cc.ARCHIVO_ZONAS}, {pagina.name}")
    print(f"Tiempo: {time.monotonic() - t0:.1f} s. {i18n.t(cc.NOTA)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
