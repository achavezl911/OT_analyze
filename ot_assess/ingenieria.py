"""D1 (D92): clases de ingenieria de las operaciones de control y sesiones de ingenieria.

La clase de cada operacion la calcula el colector (detail/control.py) y viaja en `cap.control_ops[i]["clase"]`.
Aqui se agrupan las operaciones de ingenieria en sesiones (misma captura, origen, destino, protocolo y clase, sin
huecos de mas de 300 s) para la regla `actividad_ingenieria` y para `eventos_ingenieria.csv`.
Evidencia tecnica de una captura pasiva, no un veredicto de cumplimiento.
"""
from __future__ import annotations

import collections
import datetime

from .detail.control import op_visible
from .i18n import t

ARCHIVO = "eventos_ingenieria.csv"
HUECO_S = 300.0
MAX_OPERACIONES = 5
COLUMNAS = ["captura", "inicio", "fin", "origen", "destino", "protocolo", "clase", "operaciones", "tramas",
            "primera_trama", "tecnica_mitre"]

# Clases que cuentan como ingenieria (no "escritura", que es dato de proceso).
CLASES = ("descarga", "carga", "modo", "reinicio", "firmware", "forzado", "configuracion")
TECNICA = {
    "descarga": "T0843 Program Download", "carga": "T0845 Program Upload",
    "modo": "T0858 Change Operating Mode", "reinicio": "T0816 Device Restart/Shutdown",
    "firmware": "T1693.001 Modify Firmware: System Firmware", "forzado": "T0836 Modify Parameter", "configuracion": "",
}


def iso(epoch: float) -> str:
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _num(trama) -> int:
    try:
        return int(trama)
    except (TypeError, ValueError):
        return 0


def sesiones(cap) -> list:
    """Sesiones de ingenieria de una captura, ordenadas por inicio."""
    grupos: dict = collections.defaultdict(list)
    for o in cap.control_ops:
        if o.get("clase") in CLASES:
            grupos[(o["src"], o["dst"], o["proto"], o["clase"])].append(o)
    out = []
    for (src, dst, proto, clase), ops in grupos.items():
        ops.sort(key=lambda o: (o["t"], _num(o["frame"])))
        actual = [ops[0]]
        for o in ops[1:]:
            if o["t"] - actual[-1]["t"] > HUECO_S:
                out.append(_sesion(cap.name, src, dst, proto, clase, actual))
                actual = []
            actual.append(o)
        out.append(_sesion(cap.name, src, dst, proto, clase, actual))
    out.sort(key=lambda s: (s["inicio"], s["src"], s["dst"], s["proto"], s["clase"]))
    return out


def _sesion(captura, src, dst, proto, clase, ops) -> dict:
    cuenta = collections.Counter(o["op"] for o in ops)
    top = sorted(cuenta.items(), key=lambda kv: (-kv[1], kv[0]))[:MAX_OPERACIONES]
    return {"captura": captura, "inicio": ops[0]["t"], "fin": ops[-1]["t"], "src": src, "dst": dst,
            "proto": proto, "clase": clase, "ops": top, "tramas": len(ops), "primera": ops[0]["frame"]}


def filas(caps) -> list:
    """Filas de eventos_ingenieria.csv: una por sesion, por captura y luego por inicio."""
    out = []
    for c in caps:
        for s in sesiones(c):
            out.append([c.name, iso(s["inicio"]), iso(s["fin"]), s["src"], s["dst"], s["proto"], t(s["clase"]),
                        "; ".join(f"{op_visible({'proto': s['proto'], 'op': op})} ({n})" for op, n in s["ops"]), s["tramas"], s["primera"],
                        TECNICA[s["clase"]]])
    return out
