"""Plan de remediacion (S4a): prioriza los hallazgos por severidad x criticidad del activo.

Metodo propio aprobado por el propietario, no de un estandar. Sin tshark: solo lee el modelo.
"""
from __future__ import annotations

import re

from . import playbooks
from . import trazabilidad as _tz
from .catalog import CRIT_ORDER, SEV_ORDER
from .i18n import t

NOTA = ("Priorizacion por metodo propio (severidad x criticidad del activo), no de un estandar. "
        "La criticidad inferida del rol y la no determinada requieren validacion del analista.")

COLUMNAS = ["id_hallazgo", "fase", "puntuacion", "severidad", "criticidad", "origen_criticidad", "activos",
            "titulo", "recomendacion", "capturas", "playbook", "esfuerzo"]

PESO_SEV = {"Alta": 3, "Media": 2, "Baja": 1}
PESO_CRIT = {"Critica": 3, "Alta": 2, "Media": 1, "Baja": 1}
MAX_ACTIVOS = 10
NO_DETERMINADA ="No determinada"
SIN_ACTIVO = "sin activo en la evidencia"

_CRITICA = ("Controlador", "Dispositivo CIP")
_ALTA = ("HMI", "Cliente de control", "Nodo EtherNet/IP", "Dispositivo OT", "Equipo de red")
_IPV4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?!\d)")


def fase(puntuacion: int) -> str:
    if puntuacion >= 6:
        return "Inmediato"
    return "Corto plazo" if puntuacion >= 3 else "Mediano plazo"


# Activos importados de una plataforma (D35, ampliacion 2026-11-05): su "rol" es el tipo que da la plataforma
# (PLC, RTU, HMI...) y el importador lo normaliza en `tipo` (controlador, supervision, red...).
_CRITICA_PLAT = ("plc", "rtu", "dcs", "controller", "controlador", "ied", "safety", "sis")
_ALTA_PLAT = ("hmi", "scada", "engineering", "historian", "estacion de ingenieria")
_TIPO_IMPORTADO = {"controlador": "Critica", "supervision": "Alta", "red": "Alta", "firewall": "Alta"}


def criticidad_por_rol(rol: str) -> str:
    if rol.startswith(_CRITICA):
        return "Critica"
    if rol.startswith(_ALTA):
        return "Alta"
    bajo = rol.strip().lower()
    if bajo.startswith(_CRITICA_PLAT):
        return "Critica"
    return "Alta" if bajo.startswith(_ALTA_PLAT) else "Media"


def criticidad_activo(activo: dict, declaradas: dict) -> tuple:
    """(nivel, origen) de un activo: la declarada mas alta de sus IP, o la inferida del rol (o, en activos
    importados de una plataforma, de su tipo normalizado si el rol no dice mas)."""
    niv = [declaradas[ip] for ip in activo["ips"] if ip in declaradas]
    if niv:
        return min(niv, key=CRIT_ORDER.get), "declarada"
    nivel = criticidad_por_rol(activo.get("role", ""))
    por_tipo = _TIPO_IMPORTADO.get(str(activo.get("tipo", "")).lower())
    if por_tipo and CRIT_ORDER[por_tipo] < CRIT_ORDER[nivel]:
        nivel = por_tipo
    return nivel, "inferida"


def _lista_activos(ips: list) -> str:
    if len(ips) <= MAX_ACTIVOS:
        return ";".join(ips)
    return ";".join(ips[:MAX_ACTIVOS]) + t(" y {n} mas", n=len(ips) - MAX_ACTIVOS)


def plan(res) -> list:
    """Filas del plan (dicts con las claves de COLUMNAS salvo esfuerzo), ya ordenadas."""
    from .report.common import agrupar_hallazgos

    declaradas = res.perfil.get("criticidad_activos", {})
    por_ip: dict = {}
    for a in res.assets.values():
        crit = criticidad_activo(a, declaradas)
        for ip in a["ips"]:
            por_ip[ip] = crit
    filas = []
    for f in agrupar_hallazgos([*res.caps, *res.extras]):
        if f["severidad"] not in PESO_SEV:
            continue
        # si el hallazgo trae su lista de activos, manda; si no, las IPv4 de la evidencia (recortada)
        ips = sorted({ip for ip in (f.get("activos") or _IPV4.findall(f["evidencia"])) if ip in por_ip})
        if ips:
            # la mayor criticidad; a igualdad gana la declarada
            nivel, origen = min((por_ip[ip] for ip in ips),
                                key=lambda c: (CRIT_ORDER[c[0]], c[1] != "declarada"))
        else:
            nivel, origen = NO_DETERMINADA, SIN_ACTIVO
        pts = PESO_SEV[f["severidad"]] * PESO_CRIT.get(nivel, 1)
        filas.append({"id_hallazgo": f["id"], "fase": fase(pts), "puntuacion": pts, "severidad": f["severidad"],
                      "criticidad": nivel, "origen_criticidad": origen,
                      "activos": _lista_activos(ips), "titulo": f["titulo"],
                      "recomendacion": f["recomendacion"],
                      "capturas": ";".join(sorted(set(f["capturas"]))),
                      "playbook": playbooks.para_titulo(f["titulo"])})
    filas.sort(key=lambda r: (-r["puntuacion"], SEV_ORDER[r["severidad"]], r["titulo"]))
    return filas


def _mostrar(r: dict) -> dict:
    """Copia de la fila con fase, severidad, titulo y recomendacion traducidos (la logica sigue en espanol)."""
    return dict(r, **{c: t(r[c]) for c in ("fase", "severidad", "titulo", "recomendacion",
                                           "criticidad", "origen_criticidad")})


def columnas(res) -> list:
    """COLUMNAS, mas id_recomendacion al final con la clave de perfil 'trazabilidad' (IDS1, D136)."""
    return COLUMNAS + ([_tz.COL_REC] if _tz.activa(res.perfil) else [])


def tabla(res) -> list:
    ids = _tz.activa(res.perfil)
    filas = plan(res)
    return [[r.get(c, "") for c in COLUMNAS] + ([_tz.id_recomendacion(o["recomendacion"])] if ids else [])
            for r, o in zip(map(_mostrar, filas), filas)]


FASES = ("Inmediato", "Corto plazo", "Mediano plazo")
SIN_PRIORIZAR = "Sin hallazgos que priorizar."
NOTA_ESFUERZO = "El esfuerzo lo anota el analista en plan_remediacion.csv o en la hoja del libro de Excel."
CAB_REPORTE = ["Fase", "Puntuacion", "Severidad", "Criticidad", "Activos", "Hallazgo"]


def resumen(res) -> dict:
    """Datos para los reportes: conteo por fase (todas, incluso con 0), filas de la tabla y los playbooks
    de los hallazgos presentes (en el orden del plan; None si no hay)."""
    filas = plan(res)
    return {"playbooks": playbooks.seccion(filas),
            "conteo": {t(f): sum(1 for r in filas if r["fase"] == f) for f in FASES},
            "filas": [[t(r["fase"]), r["puntuacion"], t(r["severidad"]),
                       f"{t(r['criticidad'])} ({t(r['origen_criticidad'])})", r["activos"] or "-",
                       t(r["titulo"])] for r in filas]}
