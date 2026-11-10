"""S1 (D96): plan de ubicacion de sensores a partir de los puntos de captura ya medidos.

Junta lo que la corrida ya calculo: conductos OT que vio cada punto, veredicto de C1, zonas con estado por punto,
VLAN sin espejo de los switches y segmentos sin cobertura de las fuentes importadas (M2). Funciones puras, sin
leer flujos de otra forma: los conductos de un punto salen de `salud_red._conductos_de`. No es un hallazgo ni un
dimensionamiento del fabricante.
"""
from __future__ import annotations

from . import cobertura_captura as _cc
from . import salud_red as _sr
from .i18n import t

TITULO = "Ubicacion de sensores"
NOTA = ("Aproximacion voraz (cobertura de conjuntos): no garantiza el minimo exacto y solo cuenta lo que hablo "
        "durante la ventana de la captura. No es dimensionamiento del fabricante: compara los Mbps y los activos "
        "con la hoja de datos del sensor. Detalle en sensores_puntos.csv y sensores_brechas.csv.")

A_PUNTOS, H_PUNTOS = "sensores_puntos.csv", "Sensores"
A_BRECHAS, H_BRECHAS = "sensores_brechas.csv", "Brechas de sensores"
C_PUNTOS = ["punto", "veredicto", "conductos_ot", "conductos_ot_unicos", "activos_ot", "zonas_vistas",
            "protocolos_industriales", "mbps_p95_minuto", "mbps_max_minuto", "orden_cobertura",
            "cobertura_acumulada_pct", "recomendacion"]
C_BRECHAS = ["tipo", "nombre", "detalle", "activos", "recomendacion"]

R_CORREGIR = "corregir el espejo y repetir la captura antes de decidir"
R_SIN_OT = "sin trafico OT: no prioritario para un sensor"
R_CANDIDATO = "candidato a sensor permanente"
R_REDUNDANTE = "redundante: otros puntos ven sus conductos OT"
R_ZONA_SIN = "agregar un SPAN o sensor que vea esta zona"
R_ZONA_DIF = "el espejo solo ve difusion de esta zona: revisar el SPAN para ver su trafico unicast"
R_VLAN = "agregar la VLAN a una sesion SPAN o poner un sensor en ese switch"
R_SEGMENTO = "agregar una fuente de trafico o sensor que vea este segmento"


def hay(rep: dict) -> bool:
    return bool(rep and rep.get("puntos"))


def _voraz(conjuntos: dict) -> list:
    """[(punto, cubiertos_acumulados)] en el orden en que el voraz elige; empate por nombre."""
    cubierto: set = set()
    orden = []
    restantes = dict(conjuntos)
    while restantes:
        mejor, ganancia = None, 0
        for nombre in sorted(restantes):
            g = len(restantes[nombre] - cubierto)
            if g > ganancia:
                mejor, ganancia = nombre, g
        if mejor is None:
            break
        cubierto |= restantes.pop(mejor)
        orden.append((mejor, len(cubierto)))
    return orden


def _brechas_zonas(zonas: list) -> list:
    por: dict = {}
    for f in zonas:
        if f["tipo"] == "zona":
            por.setdefault(f["nombre"], []).append(f)
    out = []
    for nombre in sorted(por):
        filas = por[nombre]
        estados = {f["estado"] for f in filas}
        if _cc.ESTADO_VISTA in estados:
            continue
        rec = R_ZONA_SIN if estados == {_cc.ESTADO_SIN} else R_ZONA_DIF
        out.append({"tipo": "zona", "nombre": nombre, "detalle": filas[0]["redes"],
                    "activos": max(f["activos"] for f in filas), "recomendacion": rec})
    return out


def construir(cobertura: dict, caps: list, conductos: list, switches: dict | None = None,
              fuentes: dict | None = None) -> dict:
    """{'puntos': [...], 'brechas': [...], 'resumen': {...}}; {} sin puntos de captura."""
    if not (cobertura or {}).get("puntos"):
        return {}
    ot = {(k["src"], k["dst"], k["l4"], k["port"]) for k in conductos if k.get("categoria") == "ot"}
    por_path = {str(c.path): c for c in caps}
    conj: dict = {}
    for p in cobertura["puntos"]:
        cond = _sr._conductos_de([por_path[x] for x in p["paths"] if x in por_path])
        conj[p["punto"]] = ot & set(cond)
    todos = set().union(*conj.values())
    orden = _voraz(conj)
    elegido = {n: (i, acum) for i, (n, acum) in enumerate(orden, 1)}
    cuenta: dict = {}
    for s in conj.values():
        for k in s:
            cuenta[k] = cuenta.get(k, 0) + 1
    zonas = cobertura.get("zonas", [])
    puntos = []
    for p in sorted(cobertura["puntos"], key=lambda x: x["punto"]):
        nombre = p["punto"]
        s = conj[nombre]
        m = p["m"]
        if p["veredicto"] == _cc.NO_APTA:
            rec = R_CORREGIR
        elif not s:
            rec = R_SIN_OT
        elif nombre in elegido:
            rec = R_CANDIDATO
        else:
            rec = R_REDUNDANTE
        ips = {k[0] for k in s} | {k[1] for k in s}
        vistas = sorted(f["nombre"] for f in zonas
                        if f["punto"] == nombre and f["tipo"] == "zona" and f["estado"] == _cc.ESTADO_VISTA)
        el = elegido.get(nombre)
        puntos.append({
            "punto": nombre, "veredicto": p["veredicto"], "conductos_ot": len(s),
            "conductos_ot_unicos": sum(1 for k in s if cuenta[k] == 1), "activos_ot": len(ips),
            "zonas_vistas": "; ".join(vistas), "protocolos_industriales": ";".join(m["industriales"]),
            "mbps_p95_minuto": m["mbps_p95"], "mbps_max_minuto": m["mbps_max"],
            "orden_cobertura": el[0] if el else None,
            "cobertura_acumulada_pct": round(100.0 * el[1] / len(todos), 1) if el else None,
            "recomendacion": rec})
    brechas = _brechas_zonas(zonas)
    for h, v, nom, n in (switches or {}).get("sin_espejo", ()):
        brechas.append({"tipo": "vlan", "nombre": f"VLAN {v}", "detalle": f"{h} {nom}".strip(), "activos": n,
                        "recomendacion": R_VLAN})
    for seg in (fuentes or {}).get("sin_cobertura", ()):
        brechas.append({"tipo": "segmento", "nombre": str(seg), "detalle": "", "activos": None,
                        "recomendacion": R_SEGMENTO})
    brechas.sort(key=lambda b: (b["tipo"], b["nombre"], b["detalle"]))
    resumen = {"puntos": len(puntos), "elegidos": len(orden), "conductos_ot": len(todos),
               "redundantes": sum(1 for x in puntos if x["recomendacion"] == R_REDUNDANTE),
               "brechas": len(brechas)}
    return {"puntos": puntos, "brechas": brechas, "resumen": resumen}


def _num(x, nd: int) -> str:
    return "" if x is None else f"{x:.{nd}f}"


def tablas(rep: dict) -> list:
    """[(archivo_csv, hoja, cabecera, filas)]."""
    if not hay(rep):
        return []
    pf = [[p["punto"], t(p["veredicto"]), p["conductos_ot"], p["conductos_ot_unicos"], p["activos_ot"],
           p["zonas_vistas"], p["protocolos_industriales"], f"{p['mbps_p95_minuto']:.3f}",
           f"{p['mbps_max_minuto']:.3f}", "" if p["orden_cobertura"] is None else p["orden_cobertura"],
           _num(p["cobertura_acumulada_pct"], 1), t(p["recomendacion"])] for p in rep["puntos"]]
    bf = [[t(b["tipo"]), b["nombre"], b["detalle"], "" if b["activos"] is None else b["activos"],
           t(b["recomendacion"])] for b in rep["brechas"]]
    return [(A_PUNTOS, H_PUNTOS, C_PUNTOS, pf), (A_BRECHAS, H_BRECHAS, C_BRECHAS, bf)]


def seccion(rep: dict) -> dict:
    """Seccion de los reportes: resumen, las dos tablas y la nota."""
    r = rep["resumen"]
    resumen = t("Con {k} de {n} puntos se ven los {c} conductos OT observados; {r} redundantes; "
                "{b} brechas de cobertura", k=r["elegidos"], n=r["puntos"], c=r["conductos_ot"],
                r=r["redundantes"], b=r["brechas"])
    (_a, _h, cp, fp), (_b, _g, cb, fb) = tablas(rep)
    return {"titulo": t(TITULO), "nota": t(NOTA), "resumen": resumen + ".",
            "tablas": [(t(H_PUNTOS), [t(c) for c in cp], fp), (t(H_BRECHAS), [t(c) for c in cb], fb)]}


def para_json(rep: dict) -> dict:
    """Contenido de `sensores` en resultado.json ({} sin puntos)."""
    if not hay(rep):
        return {}
    return {"puntos": [{**p, "mbps_p95_minuto": round(p["mbps_p95_minuto"], 3),
                        "mbps_max_minuto": round(p["mbps_max_minuto"], 3)} for p in rep["puntos"]],
            "brechas": rep["brechas"], "resumen": rep["resumen"]}
