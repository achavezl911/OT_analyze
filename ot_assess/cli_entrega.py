"""Subcomando `empaquetar`: paquete de entrega con manifiesto y verificacion (B6, D64)."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, cli_secretos
from . import entrega as ent
from .i18n import t
from .permisos import salida_privada

AYUDA = """
Ejemplos:
  python ot_pcap_assess.py empaquetar ~/datos/cliente_capturas ~/datos/cliente_cambios \\
      -o ~/entregas/cliente_2026-11 --titulo "Evaluacion OT, sitio X" [--zip]
  python ot_pcap_assess.py empaquetar --verificar ~/entregas/cliente_2026-11     (carpeta o .zip)

Siempre quedan fuera: enlaces simbolicos, archivos ocultos, *.log, carpetas crudo/, la cache de capturas (E6) y
los mapas o listas de terminos de anonimizacion (permiten revertirla). Las entradas originales (pcaps,
exportaciones, configuraciones) nunca se copian: el manifiesto lleva solo su nombre y SHA-256.
Es evidencia tecnica de integridad; no firma el paquete ni es dictamen de cumplimiento.
"""


def crear_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="ot_pcap_assess.py empaquetar",
        description="Arma el paquete de entrega (carpeta o ZIP) con manifiesto.json y manifiesto.sha256, o lo verifica.",
        epilog=AYUDA, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("carpetas", nargs="*", metavar="CARPETA_SALIDA",
                    help="Carpetas de salida de la herramienta (cada una va en su subcarpeta).")
    ap.add_argument("-o", "--out", metavar="CARPETA_ENTREGA",
                    help="Carpeta de entrega (con --zip, el ZIP se llama <CARPETA_ENTREGA>.zip). No debe existir con contenido.")
    ap.add_argument("--zip", action="store_true", help="Entregar un ZIP determinista en vez de una carpeta.")
    ap.add_argument("--excluir", action="append", default=[], metavar="PATRON",
                    help="Patron glob extra a excluir (ruta relativa o nombre). Repetible.")
    ap.add_argument("--titulo", default="", metavar="TEXTO", help="Titulo del paquete (va en el manifiesto).")
    ap.add_argument("--cache", metavar="CARPETA",
                    help="Carpeta de cache de E6 (--cache del analisis) si esta dentro de una salida: se excluye.")
    ap.add_argument("--sin-escaneo-secretos", action="store_true",
                    help="Arma el paquete sin buscar secretos (queda una linea en el manifiesto). Por defecto, con "
                         "coincidencias no se arma el paquete y el codigo es 3.")
    ap.add_argument("--verificar", metavar="CARPETA_O_ZIP",
                    help="Comprueba un paquete: modificados, faltantes y sobrantes. Codigo 0 si coincide, 1 si no.")
    ap.add_argument("--version", action="version", version=f"ot_assess {__version__}")
    return ap


def _verificar(ruta: str) -> int:
    try:
        r = ent.verificar(ruta)
    except ent.ErrorEntrega as e:
        print(f"[!] No se pudo verificar: {e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"[!] No se pudo leer '{ruta}': {e}", file=sys.stderr)
        return 2
    malo = r["modificados"] or r["faltantes"] or r["sobrantes"]
    for etiqueta, clave in (("MODIFICADO", "modificados"), ("FALTANTE", "faltantes"), ("SOBRANTE", "sobrantes")):
        for a in r[clave]:
            print(f"[!] {etiqueta}: {a}")
    if malo:
        print(f"NO COINCIDE: {len(r['modificados'])} modificados, {len(r['faltantes'])} faltantes, "
              f"{len(r['sobrantes'])} sobrantes.")
        return 1
    print(f"OK: {r['archivos']} archivos coinciden con {ent.SUMAS}.")
    return 0


@salida_privada
def main(argv=None) -> int:
    ap = crear_parser()
    args = ap.parse_args(argv)
    if args.verificar:
        if args.carpetas or args.out or args.zip:
            ap.error("--verificar no se combina con carpetas de salida, -o ni --zip")
        return _verificar(args.verificar)
    if not args.carpetas or not args.out:
        ap.error("indica al menos una CARPETA_SALIDA y -o CARPETA_ENTREGA (o usa --verificar)")
    fecha = ent.ahora_utc()
    cache = Path(args.cache).expanduser() if args.cache else None
    try:
        contenidos, man, omitidos, avisos = ent.construir(
            args.carpetas, args.excluir, args.titulo, fecha, cache,
            escanear_secretos=not args.sin_escaneo_secretos)
        out = Path(args.out).expanduser()
        if args.zip:
            destino = out if out.suffix.lower() == ".zip" else out.with_name(out.name + ".zip")
            ent.escribir_zip(destino, contenidos, fecha)
        else:
            destino = out
            ent.escribir_carpeta(destino, contenidos)
    except ent.SecretosEnPaquete as e:
        cli_secretos.imprimir(e.coincidencias)
        print(t("[!] No se genero el paquete: {n} coincidencias de secretos. Limpia las salidas o usa "
                "--sin-escaneo-secretos.", n=len(e.coincidencias)), file=sys.stderr)
        return 3
    except ent.ErrorEntrega as e:
        print(f"[!] No se genero el paquete: {e}", file=sys.stderr)
        return 2
    n = sum(len(c["salidas"]) for c in man["carpetas"])
    print(f"Paquete: {n} archivos de {len(man['carpetas'])} carpeta(s) + manifiesto en {destino}")
    for sub, rel, motivo in omitidos:
        print(f"     excluido: {sub}/{rel} ({motivo})")
    for a in avisos:
        print(f"[!] {a}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
