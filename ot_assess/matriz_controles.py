"""B7c (D77): matriz de controles ISA/IEC 62443 + NIST SP 800-82r3 con estado as-is y columnas de validacion.

Filas 62443 = las de la linea base de B7b (linea_base.py, sin duplicar reglas). Filas NIST = controles y
mejoras de la linea base OT elegida (baja, moderada o alta; Tabla 22 del Apendice F.3 de SP 800-82r3, catalogo
en marcos/nist80082_overlay.json). El estado sale solo de la evidencia de la corrida y nunca dice "cumple" ni
"no cumple". Las columnas de validacion quedan vacias: las llena el analista. Funciones puras; los textos se
traducen al escribir las tablas.
"""
from __future__ import annotations

import collections
import json
import re
from pathlib import Path

from . import cis_controles as _cis
from . import linea_base as _lb
from . import niveles62443 as _n
from . import playbooks
from . import spe62443 as _spe
from .catalog import SEV_ORDER
from .i18n import idioma, t
from .standards import ESTANDARES
from .switches.higiene import TIT_HORA

ARCHIVO, HOJA = "matriz_controles.csv", "Matriz de controles"
TITULO = "Matriz de controles (ISA/IEC 62443 y NIST SP 800-82r3)"
RUTA_CATALOGO = Path(__file__).parent / "marcos" / "nist80082_overlay.json"
CLAVE_NIST = "nist-800-82"
LINEAS_BASE = ("baja", "moderada", "alta")
BASE_DEFECTO = "moderada"
ORIGEN_BASE_PERFIL = "declarado en el perfil"
ORIGEN_BASE_PROPUESTA = "propuesto por la herramienta; lo fija el cliente"
ORIGEN_ZONA_HEREDADA = "heredada del sitio"
ORIGEN_ZONA_PROPUESTA = "propuesta por la herramienta; lo fija el cliente"
ZONA_OTRAS = "fuera de las zonas del perfil"      # activos en zonas no declaradas (subred, VLAN, plataforma)
ZONA_INTERNET = "Internet"
ARCHIVO_ZONAS, HOJA_ZONAS = "linea_base_nist_zonas.csv", "Linea base NIST por zona"
COL_ZONAS = ["zona", "linea_base", "origen", "controles", "mejoras", "activos", "brecha", "control_observado",
             "sin_evidencia", "no_evaluable"]
M_62443, M_NIST = "ISA/IEC 62443", "NIST SP 800-82r3"
M_62443_21 = "ISA/IEC 62443-2-1:2024"
M_CIS = "CIS Controls v8.1"
GRUPOS_CIS = _cis.GRUPOS
GRUPO_CIS_DEFECTO = "IG2"
RUTA_CSF = Path(__file__).parent / "marcos" / "csf2_referencias.json"
RUTA_TSA = Path(__file__).parent / "marcos" / "tsa_sd_1580_82.json"
M_TSA = "TSA SD 1580/82-2022-01E"
EDICION_TSA = "01E"
EDICIONES_TSA = (EDICION_TSA,)
ALC_ORG, ALC_SITIO = "organizacion", "sitio"
FUERA = "fuera de las lineas base OT"
FUENTES_VALIDACION = ("entrevista", "documento", "observacion en sitio", "evidencia tecnica")

COLUMNAS = ["marco", "alcance", "zona_o_conducto", "id", "titulo", "objetivo", "origen_objetivo", "estado_as_is",
            "evidencia", "hallazgos", "playbooks", "prioridad", "estado_validado", "fuente_validacion",
            "validado_por", "revisado_por", "fecha_validacion", "comentario"]
N_VALIDACION = 6            # las ultimas columnas, vacias hasta que el analista las llena

C_SC7 = "firewall observado con reglas especificas en todos los conductos entre zonas"
C_AU8 = "switch analizado sin hallazgo de hora sin sincronizar"

NOTA = ("La matriz junta los requisitos ISA/IEC 62443 de la linea base por zona y conducto (SL-T) y los controles "
        "de la linea base OT elegida de NIST SP 800-82 Rev. 3 (Apendice F.3, Tabla 22, sobre NIST SP 800-53 Rev. 5). "
        "El estado (as-is) sale solo de la evidencia de esta corrida; las columnas de validacion las llena el "
        "analista con entrevista, documento, observacion en sitio o evidencia tecnica. La linea base NIST no "
        "declarada en el perfil es una propuesta de la herramienta que fija el cliente. Incluye una fila por "
        "requisito de ISA/IEC 62443-2-1:2024 (catalogo propio del propietario) con el estado agregado de los SR de "
        "3-3 que cita; una correspondencia no es equivalencia ni prueba de cumplimiento. Esto es evidencia tecnica, "
        "no una determinacion de cumplimiento. Detalle en " + ARCHIVO + ".")

NOTA_CIS = ("Con --cis incluye las salvaguardas de CIS Controls v8.1 del grupo elegido, leidas del archivo del "
            "analista, con estado agregado de las filas NIST por las referencias informativas de CSF 2.0 de NIST; "
            "una correspondencia no es equivalencia ni prueba de cumplimiento; referencia " + _cis.REFERENCIA)

NOTA_CIS_MAPEO = ("Con --cis incluye las salvaguardas de CIS Controls v8.1 del grupo elegido, leidas del archivo "
                  "del analista; con --cis-mapeo el estado agregado de las filas NIST sale del mapeo oficial de CIS "
                  "({a}), entregado por el analista, en lugar de las referencias informativas de CSF 2.0 de NIST; "
                  "una correspondencia no es equivalencia ni prueba de cumplimiento; referencia "
                  + _cis.REFERENCIA)

NOTA_TSA = ("Con tsa_sd en el perfil incluye las medidas de la seccion III de la directiva TSA SD 1580/82-2022-01E "
            "con un mapeo propio a SP 800-53 sin revisar por el propietario; una correspondencia no es equivalencia "
            "ni prueba de cumplimiento; el plan de implementacion del cliente (CIP) se contrasta a mano y es SSI.")

_CTL = re.compile(r"(?<![A-Za-z])([A-Z]{2}-\d+)(?:\((\d+)\))?")
_NUM = re.compile(r"\d+")
_cache: dict = {}


def cargar() -> dict:
    """Catalogo de lineas base del overlay OT (marcos/nist80082_overlay.json), leido una vez."""
    if "cat" not in _cache:
        _cache["cat"] = json.loads(RUTA_CATALOGO.read_text(encoding="utf-8"))
    return _cache["cat"]


def es_mejora(ident: str) -> bool:
    return "(" in ident


def base_de(ident: str) -> str:
    return ident.split("(")[0]


def _orden(ident: str) -> tuple:
    fam = ident.split("-")[0]
    return (fam, tuple(int(x) for x in _NUM.findall(ident.split("-", 1)[1])))


def controles_de(nivel: str) -> list:
    """Ids (controles y mejoras) que la linea base `nivel` incluye; lo quitado por el overlay no cuenta."""
    if nivel not in LINEAS_BASE:
        raise ValueError(f"linea base desconocida: {nivel}")
    return sorted((i for i, c in cargar()["controles"].items() if c["niveles"][nivel]["incluido"]), key=_orden)


def conteo(nivel: str) -> tuple:
    """(controles, mejoras) de la linea base `nivel`."""
    ids = controles_de(nivel)
    mejoras = sum(1 for i in ids if es_mejora(i))
    return len(ids) - mejoras, mejoras


def linea_base_nist(perfil: dict | None) -> tuple:
    """(linea base, origen): la del perfil o 'moderada' propuesta por la herramienta."""
    v = (perfil or {}).get("linea_base_nist")
    if v in LINEAS_BASE:
        return v, ORIGEN_BASE_PERFIL
    return BASE_DEFECTO, ORIGEN_BASE_PROPUESTA


def _bases_zonas(perfil: dict | None, nivel: str, origen: str) -> list:
    """Modo por zona (NBZ1): [{zona, linea_base, origen}] si alguna zona del perfil declara `linea_base_nist`;
    [] si no. Las zonas sin ella heredan la del sitio (declarada o propuesta)."""
    zonas = (perfil or {}).get("zonas") or []
    if not any(z.get("linea_base_nist") for z in zonas):
        return []
    heredada = ORIGEN_ZONA_HEREDADA if origen == ORIGEN_BASE_PERFIL else ORIGEN_ZONA_PROPUESTA
    return [{"zona": z["nombre"], "linea_base": z.get("linea_base_nist") or nivel,
             "origen": ORIGEN_BASE_PERFIL if z.get("linea_base_nist") else heredada} for z in zonas]


def _citas(texto: str) -> set:
    return {m.group(1) + (f"({m.group(2)})" if m.group(2) else "") for m in _CTL.finditer(texto or "")}


def _cita(ident: str, citas: set) -> bool:
    """El texto cita el control; una mejora hereda la cita de su control base si no distingue mejoras."""
    if ident in citas:
        return True
    b = base_de(ident)
    return es_mejora(ident) and b in citas and not any(c.startswith(b + "(") for c in citas)


def contraste_refs() -> list:
    """Controles que citan las referencias de nist-800-82.json y no estan en el catalogo (D77); ordenados."""
    cat = cargar()["controles"]
    e = ESTANDARES[CLAVE_NIST]
    citados = set()
    for txt in e.refs.values():
        citados |= _citas(txt)
    return sorted((c for c in citados if c not in cat), key=_orden)


def _zona_de(zona: str, declaradas: set) -> str:
    """Zona de la matriz para la zona asignada de un activo: la declarada, ZONA_OTRAS o '' (Internet o sin)."""
    if zona in declaradas:
        return zona
    return ZONA_OTRAS if zona and zona != ZONA_INTERNET else ""


def _nz(zona: str) -> str:
    return t(zona) if zona == ZONA_OTRAS else zona


def _hallazgos(findings: list, por_ip: dict | None = None, declaradas: set = frozenset()) -> list:
    """Hallazgos agrupados por (titulo, severidad) que citan algun control NIST. Con `por_ip` (modo por zona,
    NBZ1) cada grupo lleva las zonas de sus activos y `global` si algun hallazgo no trae activos."""
    grupos: dict = {}
    for f in findings:
        citas = _citas((f.get("referencias") or {}).get(CLAVE_NIST, ""))
        if citas:
            g = grupos.setdefault((f["titulo"], f["severidad"]), {"titulo": f["titulo"], "sev": f["severidad"],
                                                                  "citas": set()})
            g["citas"] |= citas
            if por_ip is not None:
                from .riesgo import _ips_hallazgo
                ips = _ips_hallazgo(f, por_ip)
                zonas = {_zona_de(por_ip[ip].get("zona_asignada") or "", declaradas) for ip in ips} - {""}
                g.setdefault("zonas", set())
                g["global"] = g.get("global", False) or not zonas     # sin activos, o solo Internet
                g["zonas"] |= zonas
    return sorted(grupos.values(), key=lambda g: (g["titulo"], g["sev"]))


def _controles_observados(assets: dict, zcr: dict, firewall: dict, findings: list) -> dict:
    """{control: texto}: SC-7 y AU-8 con reglas explicitas equivalentes a las de B7b (D76)."""
    out = {}
    filas = (zcr or {}).get("filas") or []
    marcas = _lb._marcas_reglas(firewall)
    if filas and all(_lb._ctl_firewall(f, marcas) for f in filas):
        out["SC-7"] = C_SC7
    if any(a.get("switch_puerto") for a in assets.values()) and not any(f["titulo"] == TIT_HORA for f in findings):
        out["AU-8"] = C_AU8
    return out


def grupo_cis(perfil: dict | None) -> tuple:
    """(grupo IG, origen): el de `cis_ig` en el perfil o 'IG2' propuesto por la herramienta."""
    v = (perfil or {}).get("cis_ig")
    if v in GRUPOS_CIS:
        return v, ORIGEN_BASE_PERFIL
    return GRUPO_CIS_DEFECTO, ORIGEN_BASE_PROPUESTA


def _csf() -> dict:
    if "csf" not in _cache:
        _cache["csf"] = json.loads(RUTA_CSF.read_text(encoding="utf-8"))["subcategorias"]
    return _cache["csf"]


def referencias_csf() -> dict:
    """{subcategoria CSF 2.0: {"cis_v8_1": [...], "sp800_53": [...]}} (marcos/csf2_referencias.json), solo ids."""
    return _csf()


def _por_base(filas_nist: list) -> dict:
    por_base: dict = {}
    for r in filas_nist:
        por_base.setdefault(base_de(r["id"]), []).append(r)
    return por_base


def _agregar_nist(por_base: dict, controles_base) -> dict:
    """Agrega las filas NIST de los controles base dados (D108, D109): el primero de ESTADOS presente
    (None si no hay filas), conteos por estado, hallazgos y playbooks sin repetir."""
    usadas = {}
    for c in sorted(controles_base, key=_orden):
        for r in por_base.get(c, ()):
            usadas[r["id"]] = r
    rows = sorted(usadas.values(), key=lambda r: r["prioridad"])
    estados = {r["estado"] for r in rows}
    cuenta = collections.Counter(r["estado"] for r in rows)
    return {
        "estado": next((e for e in _lb.ESTADOS if e in estados), None),
        "controles": sorted({base_de(r["id"]) for r in rows}, key=_orden),
        "brecha": cuenta[_lb.E_BRECHA], "observado": cuenta[_lb.E_CONTROL], "sin_evidencia": cuenta[_lb.E_SIN],
        "no_evaluable": cuenta[_lb.E_NOEVAL],
        "hallazgos": list(dict.fromkeys(h for r in rows for h in r["hallazgos"])),
        "playbooks": list(dict.fromkeys(p for r in rows for p in r["playbooks"]))}


def tsa() -> dict:
    """Marco TSA SD 1580/82 (marcos/tsa_sd_1580_82.json), leido una vez."""
    if "tsa" not in _cache:
        _cache["tsa"] = json.loads(RUTA_TSA.read_text(encoding="utf-8"))
    return _cache["tsa"]


def _construir_tsa(filas_nist: list, perfil: dict | None) -> dict:
    """Filas TSA SD 1580/82 seccion III: estado agregado de las filas NIST por un mapeo propio (D109)."""
    por_base = _por_base(filas_nist)
    filas = []
    for pos, req in enumerate(tsa()["requisitos"]):
        doc = req["tipo"] == "documental"
        ag = _agregar_nist({} if doc else por_base, req["sp800_53"])
        if doc:
            estado = _lb.E_NOEVAL
        else:
            estado = ag["estado"] or _lb.E_SIN
        filas.append({"id": req["id"], "titulo": req["titulo"], "tipo": req["tipo"], "estado": estado,
                      **{k: v for k, v in ag.items() if k != "estado"}, "_pos": pos})
    # las filas quedan en el orden de la directiva; la prioridad usa la regla de CIS1
    for i, r in enumerate(sorted(filas, key=lambda r: (_lb.ESTADOS.index(r["estado"]), -r["brecha"], r["_pos"])), 1):
        r["prioridad"] = i
    for r in filas:
        del r["_pos"]
    return {"edicion": (perfil or {}).get("tsa_sd", EDICION_TSA), "filas": filas}


def _construir_cis(filas_nist: list, cis: list, perfil: dict | None, mapeos: list | None = None) -> dict:
    """Filas CIS del grupo elegido: estado agregado de las filas NIST por las referencias de CSF 2.0 (D108)."""
    ig, origen = grupo_cis(perfil)
    clave = ig.lower()
    por_base = _por_base(filas_nist)
    citan: dict = {}
    for sub, d in _csf().items():
        for sal in d["cis_v8_1"]:
            citan.setdefault(sal, []).append(sub)
    por_tipo = {m["tipo"]: m["por_salvaguarda"] for m in mapeos or ()}
    m53, mcsf = por_tipo.get("sp800_53"), por_tipo.get("csf2")
    filas = []
    for pos, sal in enumerate(x for x in cis if x[clave]):
        d53 = list(m53.get(sal["id"], ())) if m53 is not None else []
        dcsf = list(mcsf.get(sal["id"], ())) if mcsf is not None else []
        if mcsf is not None:
            subs = sorted({d for d, _r in dcsf})
        else:
            subs = [] if m53 is not None else sorted(citan.get(sal["id"], ()))
        if m53 is not None:
            ctl = {base_de(d) for d, _r in d53}
        else:
            ctl = {base_de(c) for sub in subs for c in _csf().get(sub, {}).get("sp800_53", ())}
        ag = _agregar_nist(por_base, ctl)
        if ag["estado"]:
            estado = ag["estado"]
        elif subs or d53 or not (sal["clase"] == "Documentation" or sal["funcion"] == "Govern"):
            estado = _lb.E_SIN
        else:
            estado = _lb.E_NOEVAL
        extra = {"mapeo_sp800_53": d53, "mapeo_csf2": dcsf} if mapeos else {}
        filas.append({
            "id": sal["id"], "control": sal["control"], "titulo": sal["titulo"], "estado": estado,
            "subcategorias": subs, **extra, **{k: v for k, v in ag.items() if k != "estado"}, "_pos": pos})
    filas.sort(key=lambda r: (_lb.ESTADOS.index(r["estado"]), -r["brecha"], r["_pos"]))
    for i, r in enumerate(filas, 1):
        r["prioridad"] = i
        del r["_pos"]
    out = {"grupo": ig, "origen": origen, "filas": filas}
    if mapeos:
        out["mapeo"] = {"sp800_53": next((m["archivo"] for m in mapeos if m["tipo"] == "sp800_53"), ""),
                        "csf2": next((m["archivo"] for m in mapeos if m["tipo"] == "csf2"), "")}
    return out


def construir(assets: dict, zcr: dict, firewall: dict, findings: list, perfil: dict | None = None,
              cis: list | None = None, cis_mapeo: list | None = None) -> dict:
    """Parte NIST de la matriz (las filas 62443 salen de la linea base al escribir). Siempre devuelve datos.
    Con `cis` (cis_controles.cargar) agrega la parte CIS (D108); `cis_mapeo` (cargar_mapeo) usa los mapeos
    oficiales de CIS en lugar de las referencias de NIST (D111)."""
    nivel, origen = linea_base_nist(perfil)
    cat = cargar()["controles"]
    por_zona = _bases_zonas(perfil, nivel, origen)
    por_ip = {ip: a for a in assets.values() for ip in a["ips"]} if por_zona else None
    declaradas = {z["zona"] for z in por_zona}
    if por_zona and any(_zona_de(a.get("zona_asignada") or "", declaradas) == ZONA_OTRAS for a in assets.values()):
        por_zona.append({"zona": ZONA_OTRAS, "linea_base": nivel,
                         "origen": ORIGEN_ZONA_HEREDADA if origen == ORIGEN_BASE_PERFIL else ORIGEN_ZONA_PROPUESTA})
    hall = _hallazgos(findings, por_ip, declaradas)
    observados = _controles_observados(assets, zcr, firewall, findings)
    fragmentos = [_citas(txt) for txt in ESTANDARES[CLAVE_NIST].refs.values()]

    def fila(ident, zona, niv, org_, hs):
        c = cat[ident]
        ctl = "" if es_mejora(ident) else observados.get(ident, "")
        if hs:
            estado = _lb.E_BRECHA
        elif ctl:
            estado = _lb.E_CONTROL
        elif any(_cita(ident, f) for f in fragmentos):
            estado = _lb.E_SIN
        else:
            estado = _lb.E_NOEVAL
        base = cat.get(base_de(ident), {})
        org = bool(c.get("toda_la_organizacion") or base.get("toda_la_organizacion"))
        r = {
            "id": ident, "familia": c["familia"], "mejora": es_mejora(ident),
            "titulo": c["titulo"] or base.get("titulo", ""),
            "alcance": ALC_ORG if org else ALC_SITIO, "agregado": c["niveles"][niv]["agregado"],
            "estado": estado, "control": ctl if estado == _lb.E_CONTROL else "",
            "hallazgos": [h["titulo"] for h in sorted(hs, key=lambda h: (SEV_ORDER.get(h["sev"], 9), h["titulo"]))],
            "playbooks": sorted({p for p in (playbooks.para_titulo(h["titulo"]) for h in hs) if p}),
            "sev": min((SEV_ORDER.get(h["sev"], 9) for h in hs), default=9)}
        if por_zona:
            r.update({"zona": zona, "linea_base": niv, "origen": org_})
        return r

    filas = []
    if not por_zona:
        for ident in controles_de(nivel):
            filas.append(fila(ident, "", nivel, origen, [h for h in hall if _cita(ident, h["citas"])]))
    else:
        incluidos = {z["zona"]: set(controles_de(z["linea_base"])) for z in por_zona}
        for ident in sorted(set().union(*incluidos.values()), key=_orden):
            base = cat.get(base_de(ident), {})
            org = bool(cat[ident].get("toda_la_organizacion") or base.get("toda_la_organizacion"))
            en = [z for z in por_zona if ident in incluidos[z["zona"]]]
            hs_sitio = [h for h in hall if _cita(ident, h["citas"])]
            if org:
                z = max(en, key=lambda z: LINEAS_BASE.index(z["linea_base"]))
                filas.append(fila(ident, "", z["linea_base"], z["origen"], hs_sitio))
                continue
            for z in en:
                hs = [h for h in hs_sitio if h["global"] or z["zona"] in h["zonas"]]
                filas.append(fila(ident, z["zona"], z["linea_base"], z["origen"], hs))
    filas.sort(key=lambda r: (_lb.ESTADOS.index(r["estado"]), r["sev"], _orden(r["id"]), r.get("zona", "")))
    for i, r in enumerate(filas, 1):
        r["prioridad"] = i
    n_c, n_m = conteo(nivel)
    out = {"nist": {"linea_base": nivel, "origen": origen, "controles": n_c, "mejoras": n_m, "filas": filas}}
    if por_zona:
        out["nist"]["por_zona"] = [{"zona": z["zona"], "linea_base": z["linea_base"], "origen": z["origen"],
                                    "controles": conteo(z["linea_base"])[0], "mejoras": conteo(z["linea_base"])[1],
                                    "activos": sum(1 for a in assets.values()
                                                   if _zona_de(a.get("zona_asignada") or "", declaradas) == z["zona"])}
                                   for z in por_zona]
        sitio: dict = {}
        for r in filas:
            sitio.setdefault(r["id"], r)
        filas = list(sitio.values())      # CIS y TSA leen una fila por control (la de mejor estado)
    if cis:
        out["cis"] = _construir_cis(filas, cis, perfil, cis_mapeo)
    if (perfil or {}).get("tsa_sd"):
        out["tsa"] = _construir_tsa(filas, perfil)
    return out


# --------------------------------------------------------------------------- #
# Tablas y texto
# --------------------------------------------------------------------------- #


def hay(mc: dict) -> bool:
    return bool(mc and mc.get("nist"))


def _vacias() -> list:
    return [""] * N_VALIDACION


def _filas_62443(lb: dict) -> list:
    """Filas de zonas y de conductos de la linea base de B7b, con las columnas de esta matriz."""
    out = []
    if not _lb.hay(lb):
        return out
    for z in lb["zonas"]:
        for r in sorted(z["filas"], key=lambda r: r["prioridad"]):
            out.append([M_62443, t("zona"), z["zona"], r["requisito"], _lb._titulo(r["requisito"]),
                        f"SL{z['sl_t']}", t(z["origen_sl_t"]), t(r["estado"]), _lb._evidencia(r),
                        _titulos(r), "; ".join(r["playbooks"]), r["prioridad"], *_vacias()])
    for c in lb["conductos"]:
        for r in sorted(c["filas"], key=lambda r: r["prioridad"]):
            out.append([M_62443, t("conducto"), c["conducto"], r["requisito"], _lb._titulo(r["requisito"]),
                        f"SL{c['sl_t']}", t(c["origen_sl_t"]), t(r["estado"]), _lb._evidencia(r),
                        _titulos(r), "; ".join(r["playbooks"]), r["prioridad"], *_vacias()])
    return out


def _titulos(r: dict) -> str:
    return "; ".join(t(h) for h, _n in r["hallazgos"])


def _filas_nist(mc: dict) -> list:
    n = mc["nist"]
    out = []
    for r in sorted(n["filas"], key=lambda r: r["prioridad"]):
        objetivo = t("linea base {nivel}", nivel=t(r.get("linea_base", n["linea_base"])))
        if r["agregado"]:
            objetivo += "; " + t("agregado por el overlay OT")
        titulo = r["titulo"] + (" - " + t("mejora") if r["mejora"] else "")
        evid = t(r["control"]) if r["control"] else "; ".join(t(h) for h in r["hallazgos"])
        out.append([M_NIST, t(r["alcance"]), _nz(r.get("zona", "")), r["id"], titulo, objetivo,
                    t(r.get("origen", n["origen"])), t(r["estado"]), evid,
                    "; ".join(t(h) for h in r["hallazgos"]), "; ".join(r["playbooks"]), r["prioridad"],
                    *_vacias()])
    return out


def _estados_2_1(lb: dict) -> list:
    """[(requisito de la 2-1, estado agregado, filas de zona usadas, ids SR)] en el orden del catalogo."""
    filas = [r for z in lb["zonas"] for r in z["filas"]]
    conj = _spe.conjuntos()
    out = []
    for e in _spe.cargar()["elementos"]:
        if e["tipo"] != _spe.T_REQ:
            continue
        ids = conj[e["id"]]
        rows = [r for r in filas if r["requisito"] in ids]
        estados = {r["estado"] for r in rows}
        if rows:
            est = next(x for x in _lb.ESTADOS if x in estados)
        elif ids:
            est = _lb.E_SIN
        else:
            est = _lb.E_NOEVAL if e["evidencia_propuesta"] == "documental" else _lb.E_SIN
        out.append((e, est, rows, sorted(ids, key=_lb._orden_id)))
    return out


def _filas_2_1(lb: dict) -> list:
    """Una fila por requisito de la 2-1 (D106), ordenadas por prioridad; sin linea base no hay filas."""
    if not _lb.hay(lb):
        return []
    datos = []
    for pos, (e, est, rows, ids) in enumerate(_estados_2_1(lb)):
        n_b = sum(1 for r in rows if r["estado"] == _lb.E_BRECHA)
        datos.append(((_lb.ESTADOS.index(est), -n_b, pos), e, est, rows, ids))
    datos.sort(key=lambda d: d[0])
    out = []
    for prio, (_k, e, est, rows, ids) in enumerate(datos, 1):
        sr = "; ".join(ids)
        if rows:
            c = collections.Counter(r["estado"] for r in rows)
            evid = t("SR citados: {sr}. Filas por zona: {b} con brecha, {c} con control observado, {s} sin "
                     "evidencia, {n} no evaluables", sr=sr, b=c[_lb.E_BRECHA], c=c[_lb.E_CONTROL],
                     s=c[_lb.E_SIN], n=c[_lb.E_NOEVAL])
        elif ids:
            evid = t("SR citados: {sr}; ninguno esta en la linea base de las zonas (SL-T)", sr=sr)
        else:
            evid = t(_lb.NOTA_DOC if e["evidencia_propuesta"] == "documental" else _lb.NOTA_SIN_SR)
        hall = list(dict.fromkeys(t(h) for r in rows for h, _n in r["hallazgos"]))
        pb = list(dict.fromkeys(p for r in rows for p in r["playbooks"]))
        out.append([M_62443_21, t("programa"), "", e["id"], e["titulo"][idioma()], "", "", t(est), evid,
                    "; ".join(hall), "; ".join(pb), prio, *_vacias()])
    return out


_REL_CIS = {"Equivalent": "equivalente", "Subset": "subconjunto", "Superset": "superconjunto"}


def _evidencia_mapeo(c: dict, r: dict) -> str:
    """Evidencia de una fila CIS cuyo estado sale del mapeo oficial de CIS (D111)."""
    d53 = r["mapeo_sp800_53"]
    if not (r["subcategorias"] or d53):
        return t("Sin correspondencia en el mapeo oficial de CIS: revisar a mano")
    partes = []
    if c["mapeo"]["csf2"] and r["subcategorias"]:
        partes.append(t("CSF 2.0 (mapeo CIS): {s}.", s="; ".join(r["subcategorias"])))
    if d53:
        m = "; ".join(f"{d} ({t(_REL_CIS[x]) if x in _REL_CIS else x})" for d, x in d53)
        if r["controles"]:
            partes.append(t("Mapeo CIS a SP 800-53 Rev 5: {m}.", m=m))
        else:
            partes.append(t("Mapeo CIS a SP 800-53 Rev 5: {m}; ningun control correspondiente esta en la linea "
                            "base NIST elegida", m=m))
    if r["controles"]:
        partes.append(t("SP 800-53 en la linea base: {c}. Filas NIST: {b} con brecha, {o} con control "
                        "observado, {e} sin evidencia, {n} no evaluables", c="; ".join(r["controles"]),
                        b=r["brecha"], o=r["observado"], e=r["sin_evidencia"], n=r["no_evaluable"]))
    elif not d53:
        partes.append(t("Ningun control SP 800-53 correspondiente esta en la linea base NIST elegida"))
    return " ".join(partes)


def _filas_cis(mc: dict) -> list:
    """Una fila por salvaguarda del grupo IG elegido (D108); titulo tal cual del archivo del analista."""
    c = mc.get("cis")
    if not c:
        return []
    out = []
    for r in c["filas"]:
        s = "; ".join(r["subcategorias"])
        if c.get("mapeo"):
            evid = _evidencia_mapeo(c, r)
        elif r["controles"]:
            evid = t("CSF 2.0: {s}; SP 800-53 en la linea base: {c}. Filas NIST: {b} con brecha, {o} con control "
                     "observado, {e} sin evidencia, {n} no evaluables", s=s, c="; ".join(r["controles"]),
                     b=r["brecha"], o=r["observado"], e=r["sin_evidencia"], n=r["no_evaluable"])
        elif r["subcategorias"]:
            evid = t("CSF 2.0: {s}; ningun control SP 800-53 correspondiente esta en la linea base NIST elegida",
                     s=s)
        else:
            evid = t("Sin correspondencia publicada con CSF 2.0 en las referencias informativas de NIST: revisar "
                     "a mano")
        out.append([M_CIS, t(ALC_ORG), "", r["id"], r["titulo"], c["grupo"], t(c["origen"]), t(r["estado"]), evid,
                    "; ".join(t(h) for h in r["hallazgos"]), "; ".join(r["playbooks"]), r["prioridad"],
                    *_vacias()])
    return out


def _filas_tsa(mc: dict) -> list:
    """Una fila por medida de la seccion III de la directiva (D109), en el orden de la directiva."""
    x = mc.get("tsa")
    if not x:
        return []
    out = []
    for r in x["filas"]:
        if r["tipo"] == "documental":
            evid = t("Documental: se evalua por entrevista o documentos")
        elif r["controles"]:
            evid = t("SP 800-53 en la linea base: {c}. Filas NIST: {b} con brecha, {o} con control observado, "
                     "{e} sin evidencia, {n} no evaluables", c="; ".join(r["controles"]), b=r["brecha"],
                     o=r["observado"], e=r["sin_evidencia"], n=r["no_evaluable"])
        else:
            evid = t("ningun control SP 800-53 correspondiente esta en la linea base NIST elegida")
        out.append([M_TSA, t(ALC_ORG), "", r["id"], t(r["titulo"]), "", "", t(r["estado"]), evid,
                    "; ".join(t(h) for h in r["hallazgos"]), "; ".join(r["playbooks"]), r["prioridad"],
                    *_vacias()])
    return out


def filas_matriz(mc: dict, lb: dict) -> list:
    return _filas_62443(lb) + _filas_2_1(lb) + _filas_nist(mc) + _filas_cis(mc) + _filas_tsa(mc)


def por_zona(mc: dict) -> list:
    """Lineas base NIST por zona (NBZ1); [] si el perfil no declara ninguna."""
    return mc["nist"].get("por_zona") or []


def _texto_zonas(mc: dict) -> str:
    """'Z1 alta, Z2 moderada (heredada)': la linea base de cada zona y, si no la declara, de donde sale."""
    partes = []
    for z in por_zona(mc):
        marca = {ORIGEN_ZONA_HEREDADA: " " + t("(heredada)"),
                 ORIGEN_ZONA_PROPUESTA: " " + t("(propuesta)")}.get(z["origen"], "")
        partes.append(f"{_nz(z['zona'])} {t(z['linea_base'])}{marca}")
    return t("Linea base NIST SP 800-82r3 por zona: {z}.", z=", ".join(partes))


def filas_zonas(mc: dict) -> list:
    """Filas de linea_base_nist_zonas.csv: una por zona y una 'organizacion' (conteos de las filas NIST)."""
    cuenta: dict = collections.defaultdict(collections.Counter)
    for r in mc["nist"]["filas"]:
        cuenta[r.get("zona", "")][r["estado"]] += 1

    def conteos(z):
        c = cuenta[z]
        return [c[_lb.E_BRECHA], c[_lb.E_CONTROL], c[_lb.E_SIN], c[_lb.E_NOEVAL]]
    out = [[_nz(z["zona"]), t(z["linea_base"]), t(z["origen"]), z["controles"], z["mejoras"], z["activos"],
            *conteos(z["zona"])] for z in por_zona(mc)]
    org = [r for r in mc["nist"]["filas"] if not r.get("zona")]
    mej = sum(1 for r in org if r["mejora"])
    out.append([t(ALC_ORG), "", "", len(org) - mej, mej, "", *conteos("")])
    return out


def _nombre_familia(fam: str) -> str:
    return f"{fam} - {t(cargar()['familias'][fam]['es'])}"


def _cuentas_nist(mc: dict) -> dict:
    """{familia: Counter(estado)} de las filas NIST."""
    out: dict = collections.defaultdict(collections.Counter)
    for r in mc["nist"]["filas"]:
        out[r["familia"]][r["estado"]] += 1
    return dict(sorted(out.items()))


def filas_general(mc: dict) -> list:
    """Una fila por familia de 800-53 para linea_base_general.csv (columnas de linea_base.COL_GEN)."""
    n = mc["nist"]
    out = []
    zonal = bool(por_zona(mc))
    for fam, c in _cuentas_nist(mc).items():
        objetivo = t("linea base por zona") if zonal else t("linea base {nivel}", nivel=t(n["linea_base"]))
        nota = t(NOTA_FAMILIA) + (" " + _texto_zonas(mc) if zonal else "")
        out.append(["NIST SP 800-53", fam, _nombre_familia(fam), "", "", "", c[_lb.E_BRECHA], c[_lb.E_CONTROL],
                    c[_lb.E_SIN], c[_lb.E_NOEVAL], "", objetivo,
                    "" if zonal else t(n["origen"]), "", "", nota])
    return out


NOTA_FAMILIA = "conteo de controles y mejoras de la familia en la linea base elegida; sin determinar cumplimiento"


def tablas(mc: dict, lb: dict) -> list:
    """[(archivo, hoja, cabecera, filas)]: las tablas de la linea base (con las familias NIST en la general)
    y la matriz de controles."""
    if not hay(mc):
        return _lb.tablas(lb)
    out = []
    general_ok = False
    for archivo, hoja, cab, filas in _lb.tablas(lb):
        if archivo == _lb.ARCHIVO_GEN:
            filas, general_ok = filas + filas_general(mc), True
        out.append((archivo, hoja, cab, filas))
    if not general_ok:
        out.append((_lb.ARCHIVO_GEN, _lb.HOJA_GEN, _lb.COL_GEN, filas_general(mc)))
    out.append((ARCHIVO, HOJA, COLUMNAS, filas_matriz(mc, lb)))
    if por_zona(mc):
        out.append((ARCHIVO_ZONAS, HOJA_ZONAS, COL_ZONAS, filas_zonas(mc)))
    return out


def seccion(mc: dict, lb: dict) -> dict:
    """Para HTML, Markdown y Word: tabla breve por marco y familia (conteos por estado) y la nota de alcance."""
    estados = list(_lb.ESTADOS)
    cab = [t("marco"), t("familia"), *[t(e) for e in estados], t("total")]
    filas = []
    if _lb.hay(lb):
        frs = _n.cargar()["fr"]
        cuenta: dict = {fr: collections.Counter() for fr in frs}
        for clave in ("zonas", "conductos"):
            for x in lb[clave]:
                for r in x["filas"]:
                    cuenta[r["fr"]][r["estado"]] += 1
        for fr, c in cuenta.items():
            filas.append([M_62443, f"{fr} - {frs[fr]['titulo'][idioma()]}", *[c[e] for e in estados],
                          sum(c.values())])
        hijos: dict = {}
        for e in _spe.cargar()["elementos"]:
            hijos.setdefault(e["pertenece_a"], []).append(e)
        estado_de = {e["id"]: est for e, est, _r, _i in _estados_2_1(lb)}
        for spe in hijos.get("", ()):
            c = collections.Counter(estado_de[r["id"]] for r in _lb._requisitos_de(spe, hijos))
            filas.append([M_62443_21, f"{spe['id']} - {spe['titulo'][idioma()]}", *[c[e] for e in estados],
                          sum(c.values())])
    n = mc["nist"]
    for fam, c in _cuentas_nist(mc).items():
        filas.append([M_NIST, _nombre_familia(fam), *[c[e] for e in estados], sum(c.values())])
    if mc.get("cis"):
        por_control: dict = {}
        for r in mc["cis"]["filas"]:
            por_control.setdefault(r["control"], collections.Counter())[r["estado"]] += 1
        for ctl, c in sorted(por_control.items(), key=lambda kv: int(kv[0])):
            filas.append([M_CIS, f"CIS {ctl}", *[c[e] for e in estados], sum(c.values())])
    if mc.get("tsa"):
        por_letra: dict = {}
        for r in mc["tsa"]["filas"]:
            por_letra.setdefault(".".join(r["id"].split(".")[:2]), collections.Counter())[r["estado"]] += 1
        for letra, c in sorted(por_letra.items()):
            filas.append([M_TSA, f"TSA {letra}", *[c[e] for e in estados], sum(c.values())])
    resumen = t("Linea base NIST {nivel} ({origen}): {c} controles y {m} mejoras. Detalle y columnas de validacion "
                "del analista en {a}.", nivel=t(n["linea_base"]), origen=t(n["origen"]), c=n["controles"],
                m=n["mejoras"], a=ARCHIVO)
    nota = t(NOTA)
    tabla_zonas = None
    if por_zona(mc):
        vacias = [_nz(z["zona"]) for z in por_zona(mc) if not z["activos"]]
        resumen = _texto_zonas(mc) + " " + t("Controles de alcance organizacion: una fila, en la linea base mas "
                                             "alta que los incluye. Detalle y columnas de validacion del analista "
                                             "en {a}; conteos por zona en {z}.", a=ARCHIVO, z=ARCHIVO_ZONAS)
        if vacias:
            resumen += " " + t("Zonas declaradas sin activos observados en esta corrida: {z}.", z=", ".join(vacias))
        tabla_zonas = ([t(c) for c in COL_ZONAS], filas_zonas(mc))
    if mc.get("cis"):
        mp = mc["cis"].get("mapeo")
        if mp:
            archivos = "; ".join(f"{k}: {v}" for k, v in (("SP 800-53 Rev 5", mp["sp800_53"]),
                                                          ("CSF 2.0", mp["csf2"])) if v)
            nota += " " + t(NOTA_CIS_MAPEO, a=archivos)
        else:
            nota += " " + t(NOTA_CIS)
    nota += " " + t(NOTA_TSA) if mc.get("tsa") else ""
    out = {"titulo": t(TITULO), "nota": nota, "resumen": resumen, "tabla": (cab, filas)}
    if tabla_zonas:
        out["tabla_zonas"] = tabla_zonas
    return out
