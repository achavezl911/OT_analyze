"""B7b (D76): linea base ISA/IEC 62443 as-is / to-be, especifica (zona y conducto) y general (FR y madurez).

to-be = lo que el catalogo de niveles (D75) exige al SL-T de cada zona y conducto. as-is = lo que dice la
evidencia de la corrida: hallazgos que citan el requisito, firewall y switches observados y la matriz de
cobertura. Nunca dice "cumple" ni "no cumple": un analisis pasivo da evidencia tecnica, no cumplimiento.
Funciones puras sobre el modelo ya calculado; los textos se traducen al escribir las tablas.
"""
from __future__ import annotations

import collections
import re

from . import cobertura as _cob
from . import conductos_zcr as _zc
from . import niveles62443 as _n
from . import playbooks
from . import spe62443 as _spe
from .catalog import SEV_ORDER
from .firewalls.higiene import M_ANY, M_CONFIA
from .i18n import idioma, t
from .standards import ESTANDARES, referencias

TITULO = "Linea base ISA/IEC 62443 (as-is / to-be)"
ARCHIVO_ESP, HOJA_ESP = "linea_base_especifica.csv", "Linea base especifica"
ARCHIVO_CON, HOJA_CON = "linea_base_conductos.csv", "Linea base conductos"
ARCHIVO_GEN, HOJA_GEN = "linea_base_general.csv", "Linea base general"
ARCHIVO_21, HOJA_21 = "linea_base_2_1.csv", "Linea base 2-1"
COL_21 = ["tipo", "id", "pertenece_a", "nombre", "evidencia_propuesta", "sr_referenciados", "con_brecha",
          "control_observado", "sin_evidencia", "no_evaluable", "sr_con_brecha", "cr_referenciados",
          "sp_referenciados", "nota"]
COL_ESP = ["zona", "sl_t", "origen_sl_t", "zona_inferida", "fr", "requisito", "to_be", "cobertura",
           "estado_as_is", "evidencia", "playbooks", "prioridad"]
COL_CON = ["conducto", "zonas", "sl_t", "origen_sl_t", "fr", "requisito", "to_be", "cobertura", "estado_as_is",
           "evidencia", "playbooks", "politica_propuesta", "prioridad"]
COL_GEN = ["tipo", "id", "nombre", "sl_t_maximo", "sl_t_minimo", "cota_minima", "con_brecha", "control_observado",
           "sin_evidencia", "no_evaluable", "sr_con_brecha", "nivel_objetivo", "origen_objetivo", "nivel_logrado",
           "preguntas_entrevista", "nota"]
MAX_TOP = 10

E_BRECHA = "brecha con evidencia"
E_CONTROL = "control observado"
E_SIN = "sin evidencia en los datos (verificar en sitio)"
E_NOEVAL = "no evaluable con datos de red (entrevista o documentos)"
ESTADOS = (E_BRECHA, E_SIN, E_NOEVAL, E_CONTROL)        # orden de prioridad: el control observado va al final

SL_DEFECTO = 2
ORIGEN_PERFIL = "declarado en el perfil"
ORIGEN_PROPUESTO = ("propuesto por la herramienta; lo fija el cliente con su evaluacion de riesgo "
                    "(ISA-62443-3-2, ZCR 5)")
ML_DEFECTO = "ML 2"
ORIGEN_ML_PERFIL = "declarado en el perfil"
ORIGEN_ML_PROPUESTO = "propuesto por la herramienta; lo fija el cliente"
ML_A = "por evaluar con entrevista (ISA-TR62443-2-2-2025, anexo B)"
SIN_ZONA = "hallazgo sin zona"
_IPV4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?!\d)")
FRS_CONDUCTO = ("FR3", "FR4", "FR5")

NOTA_COTA = "cota superior segun la evidencia; no demuestra que el nivel se alcance"
NOTA_SPE = ("La linea base por elementos del programa (SPE, sub-SPE y requisitos de ISA/IEC 62443-2-1:2024) esta "
            "en linea_base_2_1.csv, con identificadores de la norma, titulos propios y las correspondencias "
            "publicadas con 3-3, 4-2 y 2-4; una correspondencia no es equivalencia ni prueba de cumplimiento.")
NOTA_DOC = "Documental: se evalua por entrevista"
NOTA_SIN_SR = "Sin requisito de 3-3 asociado: esta corrida no lo evalua; revisar a mano"
NOTA = ("Linea base construida con ISA/IEC 62443-3-3:2013 y 4-2:2018 (vigentes anteriores a 2020), 3-2:2020 y "
        "el informe tecnico TR 2-2:2025. El objetivo (to-be) es lo que el catalogo de requisitos exige al nivel "
        "SL-T de cada zona y conducto; el estado (as-is) sale solo de la evidencia de esta corrida. La cota por "
        "FR es un maximo segun la evidencia, no un nivel logrado medido: se lee junto a los requisitos sin "
        "evidencia y no evaluables. Los SL-T no declarados en el perfil son propuestas de la herramienta que fija "
        "el cliente. Esto es evidencia tecnica, no una determinacion de cumplimiento. " + NOTA_SPE)

# Dos preguntas por FR para la entrevista que mide el nivel de madurez (palabras propias).
PREGUNTAS = {
    "FR1": (("Como se identifica y autentica a cada persona que entra a los sistemas de control, y quien "
            "administra esas cuentas?"),
            "Que cuentas compartidas, genericas o de fabricante siguen activas y como se controlan?"),
    "FR2": (("Quien autoriza que una persona o un programa cambie la configuracion o la logica del proceso, y "
            "como se revisa esa autorizacion?"),
            "Como se gestionan el acceso remoto y las sesiones de terceros: aprobacion, duracion y registro?"),
    "FR3": (("Como se comprueba que el firmware, el software y la configuracion de los equipos no cambian sin "
            "autorizacion?"),
            "Que se valida en los respaldos y programas antes de instalarlos o restaurarlos?"),
    "FR4": (("Que informacion sensible (parametros, credenciales, disenos) se guarda o viaja en el entorno de "
            "control y como se protege?"),
            "Como se sanean o destruyen los medios y equipos cuando salen de servicio?"),
    "FR5": (("Quien aprueba y documenta cada comunicacion permitida entre zonas, y cada cuanto se revisan las "
            "reglas?"),
            ("Que pasa cuando un equipo externo (portatil, memoria USB, tercero) necesita conectarse a una zona "
            "de control?")),
    "FR6": ("Quien revisa los registros y alertas del entorno de control, y con que frecuencia?",
            "Existe un plan de respuesta a incidentes OT probado, con roles y contactos definidos?"),
    "FR7": ("Cada cuanto se prueban los respaldos y la recuperacion de los equipos criticos, y cuanto tarda?",
            "Que equipos no tienen redundancia y que le pasa al proceso si fallan?"),
}

_CITA = re.compile(r"(?<![A-Za-z])SR (\d+\.\d+)(?: RE (\d+))?")
_NUM = re.compile(r"\d+")
# Los tres hallazgos de conductos_zcr se atribuyen por conducto (sus brechas), no por la IP de sus equipos.
_DE_CONDUCTO = {_zc.B_SIN_FW: _zc.TIT_SIN_FW, _zc.B_RIESGO: _zc.TIT_RIESGO, _zc.B_SALTA: _zc.TIT_SALTA}


def _orden_id(ident: str) -> tuple:
    return tuple(int(x) for x in _NUM.findall(ident))


def _sl_num(sl) -> int:
    m = _NUM.search(str(sl or ""))
    return int(m.group(0)) if m else 0


def _requisitos() -> list:
    """Todos los SR y RE del catalogo: id, sr, fr, minimo (SL desde el que se exige), es_re."""
    cat = _n.cargar()
    out = []
    for sr, d in cat["sr"].items():
        out.append({"id": sr, "sr": sr, "fr": d["fr"], "minimo": d["sl_minimo"], "re": False})
        for r in d["re"]:
            out.append({"id": r, "sr": sr, "fr": d["fr"], "minimo": cat["re_sr"][r]["sl_minimo"], "re": True})
    return out


def _exigidos(nivel: int) -> set:
    """Ids que la 3-3 exige en el nivel SL-C `nivel` (la union de las listas por SR)."""
    out: set = set()
    for sr in _n.cargar()["sr"]:
        out.update(_n.requisitos_sl(sr, nivel))
    return out


# --------------------------------------------------------------------------- #
# Hallazgos que citan requisitos
# --------------------------------------------------------------------------- #


def _citas(texto: str) -> set:
    return {f"SR {m.group(1)}" + (f" RE {m.group(2)}" if m.group(2) else "") for m in _CITA.finditer(texto or "")}


def _cita(rq: dict, citas: set) -> bool:
    """Un hallazgo cita el requisito; una RE hereda la cita de su SR si el hallazgo no distingue RE."""
    if rq["id"] in citas:
        return True
    return (rq["re"] and rq["sr"] in citas
            and not any(c.startswith(rq["sr"] + " RE ") for c in citas))


def _hallazgos(findings: list, asset_zona: dict) -> list:
    """Hallazgos agrupados como el reporte (titulo, severidad) que citan algun SR: citas, IP y activos por zona."""
    grupos: dict = {}
    for f in findings:
        g = grupos.setdefault((f["titulo"], f["severidad"]), {
            "titulo": f["titulo"], "sev": f["severidad"], "ips": set(),
            "citas": _citas((f.get("referencias") or {}).get("iec62443", ""))})
        # como el plan de remediacion: la lista de activos del hallazgo o, si no la trae, las IPv4 de su evidencia
        g["ips"].update(f.get("activos") or _IPV4.findall(f.get("evidencia") or ""))
    out = []
    for g in grupos.values():
        if not g["citas"]:
            continue
        por_zona: dict = collections.defaultdict(set)
        for ip in g["ips"]:
            z = asset_zona.get(ip)
            if z:
                por_zona[z[1]].add(z[0])
        g["por_zona"] = {z: len(v) for z, v in por_zona.items()}
        g["playbook"] = playbooks.para_titulo(g["titulo"])
        out.append(g)
    return sorted(out, key=lambda g: (g["titulo"], g["sev"]))


def _evidencia_h(pares: list) -> list:
    """[[titulo, n]] (n = 0: hallazgo sin zona) en el orden de severidad."""
    pares = sorted(pares, key=lambda p: (SEV_ORDER.get(p[0]["sev"], 9), p[0]["titulo"]))
    return [[h["titulo"], n] for h, n in pares]


# --------------------------------------------------------------------------- #
# Controles observados (reglas explicitas y deterministas; ver D76)
# --------------------------------------------------------------------------- #


def _marcas_reglas(firewall: dict) -> dict:
    """{(firewall, id de regla): marcas} para saber si la regla que permite un conducto es amplia."""
    fw = firewall or {}
    out: dict = {}
    fws = fw.get("firewalls")
    if fws and len(fws) > 1:
        for f in fws:
            for r in (f.get("datos") or {}).get("reglas", ()):
                out[(f["id"], str(r["id"]))] = r.get("marcas", "")
    else:
        for r in fw.get("reglas", ()):
            out[("", str(r["id"]))] = r.get("marcas", "")
    return out


def _ctl_firewall(fila: dict, marcas: dict) -> str:
    """SR 5.1 y SR 5.2: el conducto cruza un firewall observado y las reglas que lo permiten no son any-any
    ni confian sin inspeccion."""
    ids = fila.get("reglas_ids") or []
    if not fila["firewalls"] or not ids:
        return ""
    for k in ids:
        m = marcas.get(tuple(k), "")
        if M_ANY in m or M_CONFIA in m:
            return ""
    return "firewall observado con reglas especificas para el conducto"


def _ctl_hora(zona: str, zonas_con_switch: set) -> str:
    """SR 2.11: la zona tiene un switch analizado (el hallazgo de hora sin sincronizar ya se descarto antes)."""
    return "switch analizado sin hallazgo de hora sin sincronizar" if zona in zonas_con_switch else ""


# --------------------------------------------------------------------------- #
# Calculo
# --------------------------------------------------------------------------- #


def _sl_zonas(zonas: dict) -> dict:
    """{zona: {sl_t, origen, inferida}} de las zonas de la planta (sin Internet ni 'sin zona')."""
    out = {}
    for f in zonas.get("filas", ()):
        if f["origen"] in ("internet", "sin zona"):
            continue
        n = _sl_num(f["sl_t"])
        out[f["zona"]] = {"sl_t": n or SL_DEFECTO, "origen": ORIGEN_PERFIL if n else ORIGEN_PROPUESTO,
                          "inferida": f["inferida"] == "si", "origen_zona": f["origen"]}
    return out


def _fila(rq: dict, sl_t: int, cobertura: str, hs: list, control: str, **extra) -> dict:
    if hs:
        estado = E_BRECHA
    elif control:
        estado = E_CONTROL
    elif cobertura == _cob.NO_EVID:
        estado = E_NOEVAL
    else:
        estado = E_SIN
    sev = min((SEV_ORDER.get(h["sev"], 9) for h, _c in hs), default=9)
    return dict(extra, requisito=rq["id"], sr=rq["sr"], fr=rq["fr"], desde=rq["minimo"], estado=estado,
                cobertura=cobertura, hallazgos=_evidencia_h(hs), control=control if estado == E_CONTROL else "",
                playbooks=sorted({h["playbook"] for h, _c in hs if h["playbook"]}), sev=sev)


def _prioridad(filas: list, clave) -> None:
    """Ordena `filas` (en su sitio) por estado, SL minimo y severidad, y numera la prioridad desde 1."""
    filas.sort(key=lambda r: (ESTADOS.index(r["estado"]), r["desde"], r["sev"], clave(r), _orden_id(r["requisito"])))
    for i, r in enumerate(filas, 1):
        r["prioridad"] = i


def _cota(brechas: set, fr: str, universo: dict) -> int:
    """Mayor n en 0..4 tal que ningun requisito del FR exigido hasta SLn tiene brecha con evidencia."""
    cota = 0
    for n in (1, 2, 3, 4):
        if any(i in brechas for i in universo[n] if i in universo["fr"][fr]):
            break
        cota = n
    return cota


def construir(assets: dict, zonas: dict, zcr: dict, firewall: dict, switches: dict, findings: list,
              perfil: dict | None = None) -> dict:
    """Linea base completa, o {} si no hay zonas de la planta. `findings` = todos los hallazgos de la corrida."""
    sl_z = _sl_zonas(zonas or {})
    if not sl_z:
        return {}
    perfil = perfil or {}
    reqs = _requisitos()
    cob = {f["id"]: f["cobertura"] for f in _cob.clasificar(_cob.cargar("iec62443"), ESTANDARES["iec62443"])}
    por_nivel = {n: _exigidos(n) for n in (1, 2, 3, 4)}
    universo = dict(por_nivel, fr={fr: {r["id"] for r in reqs if r["fr"] == fr} for fr in _n.cargar()["fr"]})
    asset_zona = {}
    zonas_con_switch: set = set()
    for k, a in assets.items():
        for ip in a["ips"]:
            asset_zona[ip] = (a.get("mac") or k, a.get("zona_asignada") or "")
        if a.get("switch_puerto") and a.get("zona_asignada"):
            zonas_con_switch.add(a["zona_asignada"])
    asset_zona = {ip: v for ip, v in asset_zona.items() if v[1] in sl_z}
    hallazgos = _hallazgos(findings, asset_zona)
    marcas = _marcas_reglas(firewall)

    # ---- por zona
    zonas_out = []
    todas: list = []
    for nombre in sorted(sl_z):
        z = sl_z[nombre]
        aplican = [(h, h["por_zona"].get(nombre, 0)) for h in hallazgos
                   if h["por_zona"].get(nombre) or not h["por_zona"]]
        brechas, filas = set(), []
        for rq in reqs:
            hs = [(h, n) for h, n in aplican if _cita(rq, h["citas"])]
            if hs:
                brechas.add(rq["id"])
            if rq["id"] not in por_nivel[z["sl_t"]]:
                continue
            ctl = _ctl_hora(nombre, zonas_con_switch) if rq["id"] == "SR 2.11" and not hs else ""
            filas.append(_fila(rq, z["sl_t"], cob.get(rq["sr"], _cob.NO_EVID), hs, ctl, zona=nombre))
        fr_out = {}
        for fr in universo["fr"]:
            rows = [r for r in filas if r["fr"] == fr]
            cota = _cota(brechas, fr, universo)
            cuenta = collections.Counter(r["estado"] for r in rows)
            fr_out[fr] = {"sl_t": z["sl_t"], "cota": cota, "brecha": max(0, z["sl_t"] - cota),
                          "con_brecha": cuenta[E_BRECHA], "control_observado": cuenta[E_CONTROL],
                          "sin_evidencia": cuenta[E_SIN], "no_evaluable": cuenta[E_NOEVAL],
                          "sr_brecha": [r["requisito"] for r in sorted(rows, key=lambda r: _orden_id(r["requisito"]))
                                        if r["estado"] == E_BRECHA]}
        zonas_out.append({"zona": nombre, "sl_t": z["sl_t"], "origen_sl_t": z["origen"], "inferida": z["inferida"],
                          "fr": fr_out, "filas": filas})
        todas.extend(filas)
    _prioridad(todas, lambda r: r["zona"])

    # ---- por conducto
    con_out = []
    ref_zcr = {b: _citas(referencias(tit).get("iec62443", "")) for b, tit in _DE_CONDUCTO.items()}
    generales = [h for h in hallazgos if h["titulo"] not in _DE_CONDUCTO.values()]
    for f in (zcr or {}).get("filas", ()):
        zs = [sl_z[x] for x in (f["zona_a"], f["zona_b"]) if x in sl_z]
        if zs:
            fuente = max(zs, key=lambda z: (z["sl_t"], z["origen"] == ORIGEN_PERFIL))
            sl_t, origen = fuente["sl_t"], fuente["origen"]
        else:
            sl_t, origen = SL_DEFECTO, ORIGEN_PROPUESTO
        ips = set(f.get("ips", ()))
        aplican = [(h, len(ips & h["ips"])) for h in generales if ips & h["ips"]]
        sinteticos = [({"titulo": tit, "sev": "Alta" if f["critico"] and b == _zc.B_SIN_FW else "Media",
                        "citas": ref_zcr[b], "playbook": playbooks.para_titulo(tit)}, None)
                      for b, tit in _DE_CONDUCTO.items() if b in f["brechas"]]
        filas = []
        for rq in reqs:
            if rq["fr"] not in FRS_CONDUCTO or rq["id"] not in por_nivel[sl_t]:
                continue
            hs = [(h, n) for h, n in aplican + sinteticos if _cita(rq, h["citas"])]
            ctl = _ctl_firewall(f, marcas) if rq["id"] in ("SR 5.1", "SR 5.2") and not hs else ""
            filas.append(_fila(rq, sl_t, cob.get(rq["sr"], _cob.NO_EVID), hs, ctl, conducto=f["id"]))
        con_out.append({"conducto": f["id"], "zona_a": f["zona_a"], "zona_b": f["zona_b"], "sl_t": sl_t,
                        "origen_sl_t": origen, "propuesta": dict(f["propuesta"]), "filas": filas})
    todas_con = [r for c in con_out for r in c["filas"]]
    _prioridad(todas_con, lambda r: r["conducto"])

    # ---- general
    ml = _madurez(perfil)
    fr_gen = []
    for fr, d in _n.cargar()["fr"].items():
        pz = [z["fr"][fr] for z in zonas_out]
        fr_gen.append({
            "fr": fr, "abreviatura": d["abreviatura"], "sl_t_max": max(p["sl_t"] for p in pz),
            "sl_t_min": min(p["sl_t"] for p in pz), "cota_min": min(p["cota"] for p in pz),
            "brecha_max": max(p["brecha"] for p in pz),
            **{k: sum(p[k] for p in pz) for k in ("con_brecha", "control_observado", "sin_evidencia",
                                                  "no_evaluable")},
            "sr_brecha": sorted({i for p in pz for i in p["sr_brecha"]}, key=_orden_id),
            "preguntas": list(PREGUNTAS[fr])})
    prioritarias = sorted(
        [dict(r, ambito="zona", donde=r["zona"]) for r in todas if r["estado"] == E_BRECHA]
        + [dict(r, ambito="conducto", donde=r["conducto"]) for r in todas_con if r["estado"] == E_BRECHA],
        key=lambda r: (r["desde"], r["sev"], r["ambito"], r["donde"], _orden_id(r["requisito"])))[:MAX_TOP]
    return {"zonas": zonas_out, "conductos": con_out, "general": {"fr": fr_gen, "madurez": ml},
            "prioritarias": prioritarias}


def _madurez(perfil: dict) -> dict:
    declarado = str(perfil.get("ml_objetivo") or "")
    objetivo = f"ML {declarado[-1]}" if re.fullmatch(r"ML[1-4]", declarado) else ML_DEFECTO
    return {"objetivo": objetivo, "origen": ORIGEN_ML_PERFIL if declarado else ORIGEN_ML_PROPUESTO,
            "niveles": [{"id": ml, "objetivo": ml == objetivo, "logrado": ML_A} for ml in _n.cargar()["madurez"]]}


# --------------------------------------------------------------------------- #
# Tablas y texto
# --------------------------------------------------------------------------- #


def hay(lb: dict) -> bool:
    return bool(lb and lb.get("zonas"))


def _titulo(ident: str) -> str:
    return _n.titulo(ident, idioma())


def _sl(n: int) -> str:
    return f"SL{n}" if n else t("por debajo de SL1")


def _evidencia(r: dict) -> str:
    if r["estado"] == E_CONTROL:
        return t(r["control"])
    partes = [t(h) if n is None else t(h) + " (" + (t("{n} activos", n=n) if n else t(SIN_ZONA)) + ")"
              for h, n in r["hallazgos"]]
    return "; ".join(partes)


def _fila_comun(r: dict) -> list:
    return [r["fr"], r["requisito"],
            t("{titulo} (exigido desde SL {n})", titulo=_titulo(r["requisito"]), n=r["desde"]), t(r["cobertura"]),
            t(r["estado"]), _evidencia(r), "; ".join(r["playbooks"])]


def _ordenadas(lb: dict, clave: str) -> list:
    """Filas de todas las zonas (clave 'zonas') o conductos, por prioridad."""
    return sorted((r for x in lb[clave] for r in x["filas"]), key=lambda r: r["prioridad"])


def filas_especifica(lb: dict) -> list:
    por_zona = {z["zona"]: z for z in lb["zonas"]}
    out = []
    for r in _ordenadas(lb, "zonas"):
        z = por_zona[r["zona"]]
        out.append([r["zona"], f"SL{z['sl_t']}", t(z["origen_sl_t"]), t("si") if z["inferida"] else t("no"),
                    *_fila_comun(r), r["prioridad"]])
    return out


def texto_propuesta(prop: dict) -> str:
    return "; ".join(f"{t(k)} {prop[k]}" for k in ("permitir", "revisar", "bloquear") if prop.get(k))


def filas_conductos(lb: dict) -> list:
    por_con = {c["conducto"]: c for c in lb["conductos"]}
    out = []
    for r in _ordenadas(lb, "conductos"):
        c = por_con[r["conducto"]]
        out.append([c["conducto"], f"{c['zona_a']} <-> {c['zona_b']}", f"SL{c['sl_t']}", t(c["origen_sl_t"]),
                    *_fila_comun(r), texto_propuesta(c["propuesta"]), r["prioridad"]])
    return out


def filas_general(lb: dict) -> list:
    out = []
    for g in lb["general"]["fr"]:
        out.append(["FR", g["fr"], f"{_n.cargar()['fr'][g['fr']]['titulo'][idioma()]} ({g['abreviatura']})",
                    f"SL{g['sl_t_max']}", f"SL{g['sl_t_min']}", _sl(g["cota_min"]), g["con_brecha"],
                    g["control_observado"], g["sin_evidencia"], g["no_evaluable"], "; ".join(g["sr_brecha"]),
                    "", "", "", " | ".join(t(p) for p in g["preguntas"]), t(NOTA_COTA)])
    m = lb["general"]["madurez"]
    for n in m["niveles"]:
        out.append(["madurez", n["id"], _titulo(n["id"]), "", "", "", "", "", "", "", "",
                    n["id"] if n["objetivo"] else "", t(m["origen"]) if n["objetivo"] else "", t(n["logrado"]),
                    "", t(NOTA_SPE) if n["objetivo"] else ""])
    return out


def _requisitos_de(e: dict, hijos: dict) -> list:
    """Requisitos de la 2-1 que cuelgan de un SPE, sub-SPE o requisito (el propio requisito)."""
    if e["tipo"] == _spe.T_REQ:
        return [e]
    return [r for h in hijos.get(e["id"], ()) for r in _requisitos_de(h, hijos)]


def _unicos(piezas) -> list:
    return list(dict.fromkeys(piezas))


def filas_2_1(lb: dict) -> list:
    """Una fila por SPE, sub-SPE y requisito de la 2-1 con el as-is de los SR de 3-3 que evalua la herramienta."""
    filas = [r for z in lb["zonas"] for r in z["filas"]]
    conj = _spe.conjuntos()
    hijos: dict = {}
    for e in _spe.cargar()["elementos"]:
        hijos.setdefault(e["pertenece_a"], []).append(e)
    out = []
    for e in _spe.jerarquia():
        reqs = _requisitos_de(e, hijos)
        ids = conj[e["id"]]
        es_req = e["tipo"] == _spe.T_REQ
        cuenta = [""] * 5
        nota = ""
        if ids:
            rows = [r for r in filas if r["requisito"] in ids]
            c = collections.Counter(r["estado"] for r in rows)
            cuenta = [c[E_BRECHA], c[E_CONTROL], c[E_SIN], c[E_NOEVAL],
                      "; ".join(sorted({r["requisito"] for r in rows if r["estado"] == E_BRECHA}, key=_orden_id))]
        elif es_req:
            nota = t(NOTA_DOC if e["evidencia_propuesta"] == "documental" else NOTA_SIN_SR)
        out.append([e["tipo"], e["id"], e["pertenece_a"], e["titulo"][idioma()],
                    t(e["evidencia_propuesta"]) if es_req else "", "; ".join(sorted(ids, key=_orden_id)),
                    *cuenta, "; ".join(sorted({x for r in reqs for x in _spe.cr(r)}, key=_orden_id)),
                    "; ".join(_unicos(x for r in reqs for x in _spe.sp(r))), nota])
    return out


def tablas(lb: dict) -> list:
    """[(archivo, hoja, cabecera, filas)] para el CSV y el XLSX."""
    if not hay(lb):
        return []
    return [(ARCHIVO_ESP, HOJA_ESP, COL_ESP, filas_especifica(lb)),
            (ARCHIVO_CON, HOJA_CON, COL_CON, filas_conductos(lb)),
            (ARCHIVO_GEN, HOJA_GEN, COL_GEN, filas_general(lb)),
            (ARCHIVO_21, HOJA_21, COL_21, filas_2_1(lb))]


def seccion(lb: dict) -> dict:
    """Para HTML, Markdown y Word: resumen, tabla zona x FR, las brechas de mayor prioridad y la nota."""
    frs = list(_n.cargar()["fr"])
    cab_pivote = [t("zona"), t("sl_t"), *frs]
    pivote = [[z["zona"], f"SL{z['sl_t']}", *[
        t("SL-T {a} / cota {c} / brecha {b}", a=z["fr"][fr]["sl_t"], c=z["fr"][fr]["cota"], b=z["fr"][fr]["brecha"])
        for fr in frs]] for z in lb["zonas"]]
    cab_top = [t("prioridad"), t("zona"), t("requisito"), t("to_be"), t("evidencia")]
    top = [[i, (t("conducto") + " " if r["ambito"] == "conducto" else "") + r["donde"], r["requisito"],
            t("{titulo} (exigido desde SL {n})", titulo=_titulo(r["requisito"]), n=r["desde"]), _evidencia(r)]
           for i, r in enumerate(lb["prioritarias"], 1)]
    n_b = sum(1 for r in _ordenadas(lb, "zonas") if r["estado"] == E_BRECHA)
    n_c = sum(1 for r in _ordenadas(lb, "conductos") if r["estado"] == E_BRECHA)
    resumen = t("{z} zonas y {c} conductos; {b} requisitos con brecha con evidencia en zonas y {bc} en conductos. "
                "Detalle en {a1}, {a2}, {a3} y {a4}.", z=len(lb["zonas"]), c=len(lb["conductos"]), b=n_b, bc=n_c,
                a1=ARCHIVO_ESP, a2=ARCHIVO_CON, a3=ARCHIVO_GEN, a4=ARCHIVO_21)
    return {"titulo": t(TITULO), "nota": t(NOTA), "resumen": resumen, "pivote": (cab_pivote, pivote),
            "top": (cab_top, top), "nota_cota": t(NOTA_COTA)}
