"""T5 (D65): periodicidad de las comunicaciones de control a partir de los intervalos que guarda flows.py.

Clasifica cada conducto OT de sondeo (peticion/respuesta) como periodico, variable, irregular o esporadico y
marca huecos, fin temprano y aparicion tardia. Los protocolos de eventos espontaneos (DNP3, IEC 60870-5-104)
no se clasifican por regularidad: solo cuentan para huecos y fin temprano. Es evidencia tecnica de una
captura: un hueco puede ser una falla, una maniobra o el corte de la propia captura.
"""
from __future__ import annotations

import datetime
import math

from .catalog import OT_PORTS
from .detail.control import op_visible
from .flows import (  # hueco: mayor que max(HUECO_FACTOR x media, HUECO_MIN_S)
    HUECO_FACTOR,
    HUECO_MIN_S,
)

# Umbrales (documentados en D65).
MIN_INTERVALOS = 30           # intervalos normales para clasificar
MIN_PERIODOS = 10             # duracion minima del flujo, en periodos medios
CV_PERIODICO = 0.3            # CV < este valor: periodico
CV_IRREGULAR = 0.6            # CV >= este valor: irregular; entre ambos, variable
FIN_FACTOR = 10               # termina_antes: silencio final mayor que max(FIN_FACTOR x media, FIN_MIN_S)
FIN_MIN_S = 30.0
TARDE_FRACCION = 0.2          # aparece_tarde: despues de esta fraccion de la ventana
VENTANA_MIN_S = 600.0         # ... y solo en capturas de al menos esta duracion

SONDEO = frozenset({(502, "tcp"), (802, "tcp"), (102, "tcp"), (44818, "tcp"), (2222, "udp"),
                    (47808, "udp"), (4840, "tcp"), (4843, "tcp"), (9600, "tcp"), (5007, "tcp")})
EVENTOS = frozenset({(20000, "tcp"), (20000, "udp"), (2404, "tcp")})

COLUMNAS = ["captura", "origen", "origen_ip", "destino", "destino_ip", "servicio", "l4", "puerto",
            "peticiones", "periodo_medio_s", "cv", "hueco_max_s", "hueco_en", "primera", "ultima",
            "patron", "marcas"]


def iso(epoch: float) -> str:
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ventana_util(cap):
    """(inicio, fin, duracion) de la captura leida, o None si no hay ventana."""
    if len(cap.ventana) != 2 or cap.ventana[1] <= cap.ventana[0]:
        return None
    return cap.ventana[0], cap.ventana[1], cap.ventana[1] - cap.ventana[0]


def _cv(f: dict) -> float:
    n, media = f["pl_n"], f["pl_mean"]
    if n < 2 or media <= 0:
        return 0.0
    return math.sqrt(f["pl_m2"] / (n - 1)) / media


def conductos(cap) -> list:
    """Un dict por conducto de sondeo o de eventos con carga util, ordenado por (origen, destino, puerto)."""
    ven = ventana_util(cap)
    out = []
    for f in cap.flows.values():
        if "pl_first" not in f:
            continue
        try:
            clave = (int(f["dport"]), f["l4"])
        except ValueError:
            continue
        if clave not in SONDEO and clave not in EVENTOS:
            continue
        evento = clave in EVENTOS
        n, media = f["pl_n"], f["pl_mean"]
        cv = _cv(f)
        duracion = f["pl_last"] - f["pl_first"]
        suficiente = n >= MIN_INTERVALOS and media > 0 and duracion >= MIN_PERIODOS * media
        if evento:
            patron = "evento"
        elif not suficiente:
            patron = "esporadico"
        elif cv < CV_PERIODICO:
            patron = "periodico"
        elif cv >= CV_IRREGULAR:
            patron = "irregular"
        else:
            patron = "variable"
        marcas = []
        if suficiente and f["pl_max"] > max(HUECO_FACTOR * media, HUECO_MIN_S):
            marcas.append("hueco")
        if ven and suficiente and (patron in ("periodico", "evento")) and \
                ven[1] - f["pl_last"] > max(FIN_FACTOR * media, FIN_MIN_S):
            marcas.append("termina_antes")
        if ven and ven[2] >= VENTANA_MIN_S and f["first"] - ven[0] > TARDE_FRACCION * ven[2]:
            marcas.append("aparece_tarde")
        out.append({
            "src": f["src"], "dst": f["dst"], "dport": f["dport"], "l4": f["l4"],
            "servicio": OT_PORTS[clave][0], "peticiones": n + f["pl_huecos"] + 1,
            "media": media, "cv": cv, "hueco_max": f["pl_max"], "hueco_en": f["pl_max_en"],
            "primera": f["pl_first"], "ultima": f["pl_last"], "patron": patron, "marcas": marcas,
        })
    out.sort(key=lambda c: (c["src"], c["dst"], int(c["dport"]), c["l4"]))
    return out


def escritores_tardios(cap) -> list:
    """Pares (origen, destino) con operaciones de escritura o control cuyo primer trafico entre ambos
    ocurre despues del 20 % de la ventana (captura de al menos 10 minutos)."""
    ven = ventana_util(cap)
    if not ven or ven[2] < VENTANA_MIN_S:
        return []
    limite = ven[0] + TARDE_FRACCION * ven[2]
    primero = {}
    for f in cap.flows.values():
        for par in ((f["src"], f["dst"]), (f["dst"], f["src"])):
            if par not in primero or f["first"] < primero[par]:
                primero[par] = f["first"]
    pares = {}
    for o in cap.control_ops:
        if not o.get("t") or not o["src"] or not o["dst"]:
            continue
        p = pares.setdefault((o["src"], o["dst"]), {"t": o["t"], "ops": set(), "n": 0})
        p["t"] = min(p["t"], o["t"])
        p["ops"].add(f"{o['proto']}: {op_visible(o)}")
        p["n"] += 1
    out = []
    for (src, dst), p in sorted(pares.items()):
        if primero.get((src, dst), p["t"]) > limite and p["t"] > limite:
            out.append({"src": src, "dst": dst, "t": p["t"], "ops": sorted(p["ops"]), "n": p["n"]})
    return out


def filas(res) -> list:
    """Filas de periodicidad.csv."""
    nombre = {}
    for a in res.assets.values():
        for ip in a["ips"]:
            if ip not in nombre or a["pkts"] > nombre[ip][1]:
                nombre[ip] = (a["nombre"], a["pkts"])
    out = []
    for c in res.caps:
        for k in conductos(c):
            out.append([
                c.name, nombre.get(k["src"], (k["src"],))[0], k["src"],
                nombre.get(k["dst"], (k["dst"],))[0], k["dst"], k["servicio"], k["l4"], k["dport"],
                k["peticiones"], f"{k['media']:.3f}", f"{k['cv']:.3f}",
                f"{k['hueco_max']:.3f}", iso(k["hueco_en"]) if k["hueco_max"] else "",
                iso(k["primera"]), iso(k["ultima"]), k["patron"], ";".join(k["marcas"]),
            ])
    return out
