"""Subcomando `anonimizar`: copias seudonimizadas de exportaciones y configuraciones."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .anonimizar import Anonimizador, Mapa, MapaError, Omitir
from .anonimizar_pcap import (
    CONTADORES,
    Carga,
    anonimizar_captura,
    es_captura,
    nombre_salida,
    prepasar,
)
from .importers.lector import _texto
from .permisos import salida_privada
from .report.common import escritor_csv

RAIZ_REPO = Path(__file__).resolve().parent.parent
CAB_RESUMEN = ["archivo", "tipo", "ips", "macs", "nombres", "terminos", "lineas_omitidas",
               "ipv6_sin_cambio", "paquetes", "sumas_sin_recalcular", "carga_recortada", *CONTADORES]
VACIO = [""] * (len(CAB_RESUMEN) - 8)       # columnas de captura de un archivo que no lo es

AYUDA = """
Ejemplo:
  python ot_pcap_assess.py anonimizar exportaciones/ config_fw.txt -o muestra/ \\
      --mapa ~/mapas/cliente.json --terminos terminos.txt

Es seudonimizacion reversible con el mapa, no anonimato garantizado. Guarde el mapa FUERA
del repositorio y de la carpeta de salida: con el se revierte todo. Revise la salida antes de
compartirla (docs/DECISIONES.md, D41).
"""


def crear_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="ot_pcap_assess.py anonimizar",
        description="Copias seudonimizadas de exportaciones (CSV, XLSX, JSON) y configuraciones "
                    "de firewall en texto, conservando subredes, rutas, fabricantes y conteos.",
        epilog=AYUDA, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("entradas", nargs="+", metavar="ENTRADA",
                    help="Archivos o carpetas (recursivo).")
    ap.add_argument("-o", "--out", required=True, metavar="CARPETA",
                    help="Carpeta de salida (mismos nombres relativos).")
    ap.add_argument("--mapa", required=True, metavar="MAPA.json",
                    help="Mapa real -> seudonimo; se crea (0600) si no existe y se reutiliza si existe.")
    ap.add_argument("--terminos", metavar="TERMINOS.txt",
                    help="Un termino por linea (cliente, sitios, dominios internos); # comenta.")
    ap.add_argument("--carga", choices=("mantener", "recortar"), default="mantener",
                    help="Capturas: mantener la carga util seudonimizando IP, MAC, terminos y nombres "
                         "conocidos sin cambiar longitudes, o recortar cada paquete tras la cabecera L4 "
                         "(se pierde la deteccion OT, DNS y TLS).")
    ap.add_argument("--version", action="version", version=f"ot_assess {__version__}")
    return ap


def _dentro(hijo: Path, padre: Path) -> bool:
    return hijo == padre or padre in hijo.parents


def _error(msg: str) -> int:
    print(f"[!] {msg}", file=sys.stderr)
    return 2


def _recolectar(entradas, excluir: set) -> tuple:
    """-> ([(ruta, relativa)], error). Las carpetas se recorren en orden; se excluyen mapa y terminos."""
    archivos = []
    for e in entradas:
        p = Path(e)
        if p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.is_symlink():
                    print(f"[!] Se salta el enlace simbolico {f}")
                elif f.is_file() and f.resolve() not in excluir:
                    archivos.append((f, f.relative_to(p)))
        elif p.is_file():
            if p.resolve() not in excluir:
                archivos.append((p, Path(p.name)))
        else:
            return None, f"No existe la entrada '{e}'"
    return archivos, None


@salida_privada
def main(argv=None) -> int:
    args = crear_parser().parse_args(argv)
    out = Path(args.out).resolve()
    mapa_ruta = Path(args.mapa).resolve()
    entradas = [Path(e).resolve() for e in args.entradas]
    for e in entradas:
        if _dentro(out, e) or _dentro(e, out):
            return _error(f"CARPETA '{args.out}' coincide con la entrada '{e}' o esta dentro de ella (o al reves): "
                          "se sobrescribirian los originales. Use una carpeta de salida aparte.")
    if _dentro(mapa_ruta, RAIZ_REPO):
        return _error(f"El mapa '{args.mapa}' esta dentro del repositorio. El mapa revierte la "
                      "seudonimizacion: es tan sensible como los datos; guardelo fuera del repo.")
    if _dentro(mapa_ruta, out):
        return _error(f"El mapa '{args.mapa}' esta dentro de la carpeta de salida, que se va a compartir. "
                      "Guardelo en otro lugar.")
    if mapa_ruta.is_dir():
        return _error(f"El mapa '{args.mapa}' es una carpeta.")
    excluir = {mapa_ruta}
    terminos = []
    if args.terminos:
        ruta_t = Path(args.terminos)
        try:
            terminos = [ln.strip() for ln in _texto(ruta_t.read_bytes()).splitlines()
                        if ln.strip() and not ln.strip().startswith("#")]
        except OSError as e:
            return _error(f"No pude leer los terminos '{args.terminos}': {e}")
        excluir.add(ruta_t.resolve())
    try:
        mapa = Mapa(mapa_ruta)
    except MapaError as e:
        return _error(str(e))
    archivos, falla = _recolectar(args.entradas, excluir)
    if falla:
        return _error(falla)
    destinos = {}
    for origen, rel in archivos:
        sal = nombre_salida(rel) if es_captura(origen) else rel
        if sal in destinos:
            return _error(f"Dos entradas producen la misma salida '{sal}': {destinos[sal]} y {origen}")
        destinos[sal] = origen
    if not archivos:
        return _error("No hay archivos que anonimizar en las entradas.")
    try:
        if mapa.nuevo:
            mapa_ruta.parent.mkdir(parents=True, exist_ok=True)
            mapa.guardar()           # la clave queda en disco antes de escribir ninguna salida
        for t in terminos:
            mapa.agregar_termino(t)
        an = Anonimizador(mapa)
        # Pasada previa: registra todos los nombres de columnas y hostnames para que el resultado
        # no dependa del orden de los archivos ni de si el mapa ya existia. Las capturas no se
        # leen aqui (pueden pesar GB): se procesan en flujo despues.
        datos = []
        for origen, rel in archivos:
            if es_captura(origen):
                datos.append((origen, rel, None))
                continue
            try:
                datos.append((origen, rel, origen.read_bytes()))
            except OSError as e:
                print(f"[!] Se salta {origen}: {e}")
        an.seco = True
        for origen, rel, raw in datos:
            if raw is None:
                continue
            try:
                an.transformar(origen.suffix, raw)
            except Omitir:
                pass
        an.seco = False
        out.mkdir(parents=True, exist_ok=True)
        recortar = args.carga == "recortar"
        filas, ipv6 = {}, 0
        capturas = 0
        ot_mod = 0
        enmascaradas = 0
        # Primero lo que no es captura (registra sus IP en el mapa) y luego las capturas: el conjunto
        # de IP conocidas para la carga es el mismo en la primera corrida y al reutilizar el mapa.
        for n, (origen, rel, raw) in enumerate(datos):
            if raw is None:
                continue
            an.reiniciar()
            try:
                tipo, contenido = an.transformar(origen.suffix, raw)
            except Omitir as e:
                print(f"[!] Se salta {rel}: {e}")
                filas[n] = [str(rel), "omitido", 0, 0, 0, 0, 0, 0, *VACIO]
                continue
            destino = out / rel
            destino.parent.mkdir(parents=True, exist_ok=True)
            destino.write_bytes(contenido)
            c = an.c
            ipv6 += c["ipv6"]
            filas[n] = [str(rel), tipo, c["ips"], c["macs"], c["nombres"], c["terminos"],
                        c["omitidas"], c["ipv6"], *VACIO]
            print(f"[OK] {rel} ({tipo}): {c['ips']} IP, {c['macs']} MAC, {c['nombres']} nombres, "
                  f"{c['terminos']} terminos, {c['omitidas']} lineas omitidas")
        plan = None
        if not recortar:
            for origen, rel, raw in datos:
                if raw is None:
                    try:
                        prepasar(mapa, origen)
                    except Omitir:
                        pass             # se reporta al escribirla
            plan = Carga(mapa)
        for n, (origen, rel, raw) in enumerate(datos):
            if raw is not None:
                continue
            rel_sal = nombre_salida(rel)
            try:
                c = anonimizar_captura(mapa, origen, out / rel_sal, recortar, plan)
            except Omitir as e:
                print(f"[!] Se salta {rel}: {e}")
                filas[n] = [str(rel), "omitido", 0, 0, 0, 0, 0, 0, *VACIO]
                continue
            capturas += 1
            ipv6 += c["ipv6"]
            ot_mod += c["carga_ot_modificada"]
            enmascaradas += c["ip_texto_enmascaradas"]
            filas[n] = [str(rel_sal), "pcap", c["ips"], c["macs"], 0, 0, 0, c["ipv6"],
                        c["paquetes"], c["sin_recalcular"], "si" if recortar else "no",
                        *[c[k] for k in CONTADORES]]
            cambio = f" (antes {rel})" if rel_sal != rel else ""
            print(f"[OK] {rel_sal}{cambio} (pcap): {c['paquetes']} paquetes, {c['ips']} IP, "
                  f"{c['macs']} MAC, {c['sin_recalcular']} sumas sin recalcular, "
                  f"{c['recortados']} paquetes recortados")
            if not recortar:
                print(f"     carga: {c['ip_binarias']} IP binarias, {c['mac_binarias']} MAC binarias, "
                      f"{c['ip_texto']} IP en texto ({c['ip_texto_enmascaradas']} enmascaradas), "
                      f"{c['terminos_carga']} terminos o nombres")
        with open(out / "anonimizacion.csv", "w", newline="", encoding="utf-8") as fh:
            w = escritor_csv(fh)
            w.writerow(CAB_RESUMEN)
            w.writerows(filas[k] for k in sorted(filas))
    finally:
        mapa.guardar()
    if ipv6:
        print(f"[!] {ipv6} direcciones o paquetes IPv6 sin cambio (esta version no los seudonimiza)")
    if capturas and recortar:
        print("[!] Con --carga recortar se pierde la deteccion de protocolos OT, DNS y TLS en el analisis: "
              "solo quedan flujos, puertos y volumenes")
    elif capturas:
        print("[!] Con --carga mantener la carga conserva el texto libre que no sea IP, MAC, termino o nombre "
              "conocido (p. ej. nombres DNS internos que no esten en --terminos): para compartir fuera, "
              "revise la salida o use --carga recortar")
        if ot_mod:
            print(f"[!] {ot_mod} secuencias de 4 o 6 bytes en cargas de protocolos OT coincidieron con una IP o "
                  "MAC conocida y se cambiaron (puede ser un valor de proceso, p. ej. un registro Modbus): "
                  "el analisis de esos valores ya no es fiel")
        if enmascaradas:
            print(f"[!] {enmascaradas} IP en texto cambiaron de longitud al seudonimizarse y se enmascararon "
                  "(digitos -> x): no se pueden revertir con el mapa")
    print(f"[OK] Mapa: {mapa_ruta} (sensible: guardelo fuera del repo y no lo comparta)")
    print("[!] Revise la salida antes de compartirla: los nombres de archivo y el texto libre "
          "fuera de los terminos dados no se tocan")
    return 0
