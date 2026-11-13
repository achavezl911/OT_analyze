"""Trazabilidad (IDS1, D136): ids estables de recomendacion, vulnerabilidad y flujo, y la cadena
activo -> evidencia -> hallazgo -> riesgo -> control -> recomendacion -> entregable.

Clave opcional de perfil "trazabilidad" ({} vale). No crea ids de activo, hallazgo, riesgo, evidencia,
vulnerabilidad ni flujo: junta los que ya existen (A-, H-, R-, EV-, VU-, FL-) y agrega el de la recomendacion
(REC-, de su texto en espanol). Es trazabilidad documental: no dictamina cumplimiento. Sin la clave, nada cambia.
"""
from __future__ import annotations

import hashlib
import sys

from .i18n import t

CLAVE = "trazabilidad"
ARCHIVO = "trazabilidad.csv"
HOJA = "Trazabilidad"
TITULO = "Trazabilidad"
NOTA = "Cadena para trazar cada hallazgo hasta su entregable; no es una determinacion de cumplimiento."
COLUMNAS = ["id_activo", "activo", "ips", "evidencias", "id_hallazgo", "titulo", "severidad", "id_riesgo",
            "controles", "id_recomendacion", "playbook", "entregables", "ids_flujo", "ids_vulnerabilidad"]
COL_REC = "id_recomendacion"
FILAS_DEFECTO = 20000
FILAS_MIN, FILAS_MAX = 100, 100000
_ATRIBUTO = "_trazabilidad_calculada"


def activa(perfil) -> bool:
    return CLAVE in (perfil or {})


def id_recomendacion(texto: str) -> str:
    """REC- y 8 hex del sha256 del texto en espanol sin traducir, con los espacios colapsados."""
    return "REC-" + hashlib.sha256(" ".join(str(texto).split()).encode("utf-8")).hexdigest()[:8]


def validar(v, fallo) -> dict:
    """Perfil -> {"por_activo": bool, "max_filas": int}; `fallo(msg)` termina con error de perfil."""
    if not isinstance(v, dict):
        fallo("'trazabilidad' debe ser un objeto (puede ser {}).")
    for k in v:
        if k not in ("por_activo", "max_filas"):
            fallo(f"clave desconocida '{k}' en 'trazabilidad'.")
    por_activo = v.get("por_activo", True)
    if not isinstance(por_activo, bool):
        fallo("'trazabilidad.por_activo' debe ser true o false.")
    maximo = v.get("max_filas", FILAS_DEFECTO)
    if isinstance(maximo, bool) or not isinstance(maximo, int) or not FILAS_MIN <= maximo <= FILAS_MAX:
        fallo(f"'trazabilidad.max_filas' debe ser un entero de {FILAS_MIN} a {FILAS_MAX}.")
    return {"por_activo": por_activo, "max_filas": maximo}


# ---- construccion -----------------------------------------------------------------------------------------

def _ids_activo(res) -> dict:
    """{ip: A-id} del inventario normalizado."""
    out: dict = {}
    for f in (getattr(res, "inventario_normalizado", None) or {}).get("filas", ()):
        for ip in str((f["campos"].get("ips") or {}).get("valor", "")).split(";"):
            if ip:
                out.setdefault(ip, f["id"])
    return out


def _evidencias(res) -> tuple:
    """({nombre de archivo: [id_evidencia]}, hay_registro)."""
    from . import registro_evidencias as _registro
    tabla = _registro.tablas(getattr(res, "args", None))
    por_archivo: dict = {}
    if tabla:
        for fila in tabla[0][3]:
            for nombre in str(fila[1]).split("; "):
                por_archivo.setdefault(nombre, []).append(fila[0])
    return por_archivo, bool(tabla)


def _vulnerabilidades(res, assets: dict) -> tuple:
    """({id(activo del modelo): {VU-}}, generador de ids, candidatas de firmware)."""
    from . import confirmacion_vulns as _vconf
    from . import vuln_firmware as _vf
    plan = _vconf.de_args(getattr(res, "args", None))
    ident = plan or _vconf.Plan({}, {})
    out: dict = {}
    for c in getattr(res, "vulns_cruces", None) or ():
        a = assets.get(c["activo"]) if c.get("activo") is not None else None
        if a is None:
            continue
        vu = ident.id_plataforma(c["vuln"], a)
        if not (plan and plan.excluye and plan.descartada(vu)):
            out.setdefault(id(a), set()).add(vu)
    return out, ident, (_vf._candidatas(res.vuln_firmware) if _vf.hay(res.vuln_firmware) else [])


def _flujos(res) -> dict:
    """{id_hallazgo: {FL-}} de los conductos TO-BE que lo citan (mismo id que allowlist_tobe.csv)."""
    from . import allowlist_proyecto as _alp
    out: dict = {}
    tobe = getattr(res, "tobe", None) or {}
    for f in tobe.get("filas", ()):
        ident = _alp.id_flujo(f["zona_origen"], f["zona_destino"], f["servicio"])
        for h in f["ids_hallazgo"]:
            out.setdefault(h, set()).add(ident)
    return out


def _controles(f: dict, estandares: list) -> str:
    from .standards import traducir_refs
    return " | ".join(f"{e.clave}: {traducir_refs(f['referencias'][e.clave])}"
                      for e in estandares if f.get("referencias", {}).get(e.clave))


def _activos_de(f: dict, por_ip: dict) -> list:
    """[(activo del modelo, [ips del hallazgo])] como en el plan de remediacion; vacio si ninguna IP esta."""
    from .remediacion import _IPV4
    ips = sorted({ip for ip in (f.get("activos") or _IPV4.findall(f["evidencia"])) if ip in por_ip})
    grupos: dict = {}
    for ip in ips:
        a = por_ip[ip]
        grupos.setdefault(id(a), (a, []))[1].append(ip)
    return sorted(grupos.values(), key=lambda x: (str(x[0].get("nombre") or x[1][0]), x[1][0]))


def _fila(ctx: tuple, a_modelo, ips: list) -> dict:
    """Fila de un hallazgo para un activo del modelo (None: sin activo en la evidencia)."""
    base, a_id, es_vuln, vu_activo, ident_vu, vu_fw = ctx
    aid = next((a_id[ip] for ip in ips if ip in a_id), "")
    nombre = (a_modelo.get("nombre") if a_modelo else "") or (ips[0] if ips else "")
    vus: set = set()
    if es_vuln and a_modelo is not None:
        vus.update(vu_activo.get(id(a_modelo), ()))
        vus.update(x.get("id_vuln") or ident_vu.id_firmware(x) for x in vu_fw if aid and x["id"] == aid)
    return dict(base, id_activo=aid, activo=nombre, ips=";".join(ips), ids_vulnerabilidad="; ".join(sorted(vus)))


def construir(res) -> dict:
    """{"filas": [dict por COLUMNAS], "resumen": {...}, "cfg": {...}}; calculado una vez por corrida."""
    previo = res.__dict__.get(_ATRIBUTO)
    if previo is not None:
        return previo
    from . import entregables as _en
    from . import playbooks
    from . import riesgo as _rg
    from .catalog import SEV_ORDER
    from .report.common import agrupar_hallazgos
    from .standards import ESTANDARES

    cfg = (res.perfil or {}).get(CLAVE) or {}
    por_activo = cfg.get("por_activo", True)
    maximo = cfg.get("max_filas", FILAS_DEFECTO)
    assets = res.assets or {}
    por_ip: dict = {}
    for a in assets.values():
        for ip in sorted(a["ips"]):
            por_ip.setdefault(ip, a)
    a_id = _ids_activo(res)
    ev_archivo, hay_registro = _evidencias(res)
    riesgos = {r["id_hallazgo"]: r["id_riesgo"] for r in (_rg.de(res) or {}).get("filas", ())}
    plan_ent = _en.plan(res.perfil)
    flujos = _flujos(res)
    vu_activo, ident_vu, vu_fw = _vulnerabilidades(res, assets)
    estandares = res.estandares or [ESTANDARES["iec62443"]]
    origenes: dict = {}
    for c in [*res.caps, *res.extras]:
        for f in c.findings:
            origenes.setdefault((f["titulo"], f["severidad"]), set()).add(f["captura"])
    filas = []
    for f in agrupar_hallazgos([*res.caps, *res.extras]):
        raw = sorted(origenes.get((f["titulo"], f["severidad"]), ()))
        ev_ids = sorted({i for n in raw for i in ev_archivo.get(n, ())})
        evid = "; ".join(ev_ids) if hay_registro else "; ".join(raw)
        es_vuln = f.get("categoria") == "Vulnerabilidades"
        base = {"evidencias": evid, "id_hallazgo": f["id"], "titulo": f["titulo"], "severidad": f["severidad"],
                "id_riesgo": riesgos.get(f["id"], ""), "controles": _controles(f, estandares),
                COL_REC: id_recomendacion(f["recomendacion"]),
                "playbook": playbooks.para_titulo(f["titulo"]),
                "entregables": _en.texto_hallazgo(plan_ent, f) if plan_ent else "",
                "ids_flujo": "; ".join(sorted(flujos.get(f["id"], ()))),
                "_ev": bool(ev_ids), "_sev": SEV_ORDER.get(f["severidad"], 9)}

        ctx = (base, a_id, es_vuln, vu_activo, ident_vu, vu_fw)
        activos = _activos_de(f, por_ip)
        if not activos:
            filas.append(_fila(ctx, None, []))
        elif por_activo:
            filas.extend(_fila(ctx, a, sorted(a["ips"])) for a, _ips in activos)
        else:
            partes = [_fila(ctx, a, sorted(a["ips"])) for a, _ips in activos]
            union = dict(base, id_activo="; ".join(p["id_activo"] for p in partes if p["id_activo"]),
                         activo="; ".join(p["activo"] for p in partes),
                         ips=";".join(p["ips"] for p in partes),
                         ids_vulnerabilidad="; ".join(sorted({i for p in partes
                                                              for i in p["ids_vulnerabilidad"].split("; ") if i})))
            filas.append(union)
    filas.sort(key=lambda r: (r["_sev"], r["titulo"], r["activo"]))
    total = len(filas)
    cortado = total > maximo
    if cortado:
        filas = filas[:maximo]
        print(f"[!] trazabilidad: {total} filas; se cortan a max_filas={maximo}.", file=sys.stderr)
    resumen = {"cantidad_filas": len(filas), "filas_totales": total, "cortado": cortado,
               "hallazgos": len({r["id_hallazgo"] for r in filas}),
               "activos": len({r["activo"] for r in filas if r["activo"]}),
               "sin_evidencia_registrada": sum(1 for r in filas if not r["_ev"]),
               "sin_riesgo": sum(1 for r in filas if not r["id_riesgo"]),
               "sin_entregable": sum(1 for r in filas if not r["entregables"])}
    out = {"filas": filas, "resumen": resumen, "cfg": {"por_activo": por_activo, "max_filas": maximo}}
    res.__dict__[_ATRIBUTO] = out
    return out


# ---- salidas ----------------------------------------------------------------------------------------------

def hay(res) -> bool:
    return activa(getattr(res, "perfil", None))


def tablas(res) -> list:
    if not hay(res):
        return []
    filas = [[r["id_activo"], r["activo"], r["ips"], r["evidencias"], r["id_hallazgo"], t(r["titulo"]),
              t(r["severidad"]), r["id_riesgo"], r["controles"], r[COL_REC], r["playbook"], r["entregables"],
              r["ids_flujo"], r["ids_vulnerabilidad"]] for r in construir(res)["filas"]]
    return [(ARCHIVO, HOJA, COLUMNAS, filas)]


def seccion(res) -> dict:
    """Seccion corta de los reportes: conteos y la nota (la tabla completa va en trazabilidad.csv)."""
    r = construir(res)["resumen"]
    texto = t("Filas: {f}; hallazgos: {h}; activos: {a}; sin evidencia registrada: {e}; sin riesgo: {r}; "
              "sin entregable: {d}. Detalle en trazabilidad.csv.",
              f=r["cantidad_filas"], h=r["hallazgos"], a=r["activos"], e=r["sin_evidencia_registrada"],
              r=r["sin_riesgo"], d=r["sin_entregable"])
    if r["cortado"]:
        texto += " " + t("Se cortaron a {n} de {m} filas por max_filas.", n=r["cantidad_filas"], m=r["filas_totales"])
    return {"titulo": t(TITULO), "nota": t(NOTA), "resumen": texto}


def para_json(res):
    """Bloque 'trazabilidad' de resultado.json, o None sin la clave."""
    if not hay(res):
        return None
    d = construir(res)
    return {**d["resumen"], **d["cfg"],
            "filas": [{c: r[c] for c in COLUMNAS} for r in d["filas"]]}
