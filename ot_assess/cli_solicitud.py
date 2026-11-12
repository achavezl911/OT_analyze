"""Subcomando `solicitud-cambio`: arma la Solicitud de Cambio (RFC) desde la politica y las rutas propuestas (SC1, D61)."""
from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from . import __version__, perfil
from . import solicitud_cambio as sc
from .firewalls import exportar, fmc
from .permisos import salida_privada

AYUDA = """
Ejemplo:
  python ot_pcap_assess.py solicitud-cambio --propuesta salida/politica_propuesta.csv \\
      --objetos salida/politica_objetos.csv --comparacion salida/politica_comparacion.csv \\
      --rutas salida/rutas_propuestas.csv --bloqueados salida/politica_bloqueados.csv \\
      --firewall-nombre FTD-01 --solicitante "Nombre" --ventana "sabado 22:00" -o ~/datos/cliente_sc

Escribe solicitud_cambio.docx, solicitud_cambio.md y solicitud_cambio_cambios.csv. La estructura (secciones,
titulos, columnas, textos) esta en ot_assess/data/solicitud_cambio.json; --plantilla la reemplaza. El documento
es una propuesta a validar por el comite de cambios; no se conecta a ningun equipo ni a ningun sistema de cambios.
"""


def crear_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="ot_pcap_assess.py solicitud-cambio",
        description="Arma la Solicitud de Cambio (RFC) para el comite de cambios del cliente a partir de los CSV "
                    "ya revisados de la politica propuesta y las rutas propuestas.",
        epilog=AYUDA, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--propuesta", required=True, metavar="CSV", help="politica_propuesta.csv (revisado)")
    ap.add_argument("--objetos", required=True, metavar="CSV", help="politica_objetos.csv (revisado)")
    ap.add_argument("--comparacion", metavar="CSV", help="politica_comparacion.csv (reglas actuales)")
    ap.add_argument("--rutas", metavar="CSV", help="rutas_propuestas.csv")
    ap.add_argument("--bloqueados", metavar="CSV", help="politica_bloqueados.csv (lo observado que no se permitiria)")
    ap.add_argument("--perfil", metavar="JSON", help="Perfil del proyecto (cliente, sitio).")
    ap.add_argument("--firewall-nombre", metavar="TEXTO", help="Equipo afectado (p. ej. el nombre del FTD).")
    ap.add_argument("--solicitante", metavar="TEXTO", help="Quien solicita el cambio.")
    ap.add_argument("--ventana", metavar="TEXTO", help="Fecha y hora propuestas (texto libre).")
    ap.add_argument("--formato-carga", choices=exportar.FORMATOS, default="fmc",
                    help="Formato de los archivos de carga de politica-fmc que se citan en el plan (defecto: fmc).")
    ap.add_argument("--plantilla", metavar="JSON", help="Reemplaza la estructura por defecto (misma forma).")
    ap.add_argument("-o", "--out", required=True, metavar="CARPETA", help="Carpeta de salida (datos del cliente).")
    ap.add_argument("--version", action="version", version=f"ot_assess {__version__}")
    return ap


@salida_privada
def main(argv=None) -> int:
    args = crear_parser().parse_args(argv)
    cliente = sitio = ""
    try:
        try:
            msg = perfil.deshabilitado("solicitud-cambio", args.propuesta, args.perfil)
        except SystemExit as e:
            raise sc.ErrorSC(str(e))
        if msg:
            raise sc.ErrorSC(msg)
        if args.perfil:
            try:
                p = perfil.cargar(args.perfil)
            except SystemExit as e:
                raise sc.ErrorSC(str(e))
            cliente, sitio = p.get("cliente", ""), p.get("sitio", "")
        tpl = sc.cargar_plantilla(args.plantilla)
        ent = sc.leer_entradas(args.propuesta, args.objetos, args.comparacion, args.rutas, args.bloqueados)
        nombre = fmc.nombre_politica_defecto(args.propuesta, datetime.now().strftime("%Y%m%d"))
        entradas = [Path(x).name for x in (args.propuesta, args.objetos, args.comparacion, args.rutas,
                                           args.bloqueados) if x]
        r = sc.generar(ent, tpl, nombre, args.formato_carga, cliente, sitio, args.firewall_nombre or "",
                       args.solicitante or "", args.ventana or "", entradas=entradas)
    except sc.ErrorSC as e:
        print("[!] No se genero nada:\n" + str(e), file=sys.stderr)
        return 2
    out = Path(args.out).expanduser()
    if out.exists() and not out.is_dir():
        print(f"[!] '{args.out}' existe y no es una carpeta.", file=sys.stderr)
        return 2
    archivos = sc.escribir(out, r["bloques"], r["cambios"], tpl)
    por_fase = {}
    for c in r["cambios"]:
        por_fase[c["fase"]] = por_fase.get(c["fase"], 0) + 1
    print(f"Solicitud de cambio: {len(r['cambios'])} cambios (" + ", ".join(
        f"fase {k}: {v}" for k, v in sorted(por_fase.items())) + ").")
    print("Escrito en " + str(out) + ": " + ", ".join(archivos))
    print("Siguiente paso: completar folio, duracion y firmas; el comite valida el riesgo.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
