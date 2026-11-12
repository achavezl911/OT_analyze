"""Registro de riesgos (R1, D83): probabilidad x impacto por hallazgo, mapa de calor 5x5 y quick wins.

Metodo propio, no de un estandar, con heuristicas sin calibrar: probabilidad = severidad del hallazgo +1 si
es alcanzable desde Internet o IT (A1) o involucra una CVE en KEV; impacto = lo declarado por zona en el
perfil (6 dimensiones) o, si no, inferido de la criticidad del activo. El esfuerzo de cada playbook es
una estimacion propia sin revisar. El analista ajusta con `ajustes_riesgo` en el perfil. Es un orden de
atencion, no una medida de cumplimiento. No sustituye ni cambia el plan de remediacion (D35). Solo lee el modelo.
"""
from __future__ import annotations

import hashlib
import re

from .catalog import CRIT_ORDER, SEV_ORDER
from .i18n import t
from .perfil import DIMENSIONES_IMPACTO, dimension_inferida, dimensiones_impacto

TITULO = "Registro de riesgos y mapa de calor"
HOJA_REGISTRO = "Registro de riesgos"
HOJA_MAPA = "Mapa de calor de riesgo"
ARCHIVO_REGISTRO = "riesgos.csv"
ARCHIVO_MAPA = "mapa_calor_riesgo.csv"
NOTA = ("Metodo propio (probabilidad x impacto), no de un estandar, con heuristicas sin calibrar. La probabilidad "
        "parte de la severidad del hallazgo y sube un punto si el activo es alcanzable desde Internet o IT "
        "(rutas de ataque) o tiene una CVE explotada (KEV). El impacto inferido de la criticidad del activo "
        "requiere validacion con el cliente; con el impacto por zona del perfil se calcula por dimension. El "
        "esfuerzo de cada playbook es una estimacion propia sin revisar. Es un orden de atencion, no un "
        "veredicto de cumplimiento.")
SIN_RIESGOS = "Sin hallazgos que registrar como riesgo."
SIN_QUICK = "Ningun riesgo cumple el criterio de quick win."
NOTA_QUICK = "Quick win: riesgo de nivel Alto o Muy alto cuyo playbook tiene esfuerzo estimado bajo."
MAX_TOP = 10
MAX_ACTIVOS = 10

COLUMNAS = ["id_riesgo", "id_hallazgo", "titulo", "categoria", "severidad", "zonas", "activos", "probabilidad",
            "motivo_probabilidad", "impacto", "dimension_impacto", "motivo_impacto", "puntuacion", "nivel",
            "tecnicas_mitre_ics", "esfuerzo_estimado", "quick_win", "origen", "recomendacion", "playbook"]
COL_MAPA = ["impacto", "probabilidad", "puntuacion", "nivel", "riesgos", "ids"]
CAB_TOP = ["ID", "Riesgo", "Severidad", "Probabilidad", "Impacto", "Puntuacion", "Nivel", "Esfuerzo estimado"]
CAB_QUICK = ["ID", "Riesgo", "Nivel", "Esfuerzo estimado", "Playbook"]

NIVELES = ("Bajo", "Medio", "Alto", "Muy alto")
COLORES = {"Bajo": "92D050", "Medio": "FFE699", "Alto": "F4B183", "Muy alto": "FF5050"}   # verde a rojo
CLASES = {"Bajo": "mc-bajo", "Medio": "mc-medio", "Alto": "mc-alto", "Muy alto": "mc-muy-alto"}
BASE_PROB ={"Alta": 4, "Media": 3, "Baja": 2}
IMPACTO_CRIT = {"Critica": 5, "Alta": 4, "Media": 3, "Baja": 2, "No determinada": 3}
DIM_INFERIDA = "produccion (inferida)"
SUFIJO_INFERIDA = " (inferida)"
CAB_TOP_CAND = ["ID", "Riesgo", "Severidad", "Factores", "Zonas", "Esfuerzo estimado"]
FRASE_CANDIDATOS = ("Modo candidatos: la herramienta no puntua; el equipo evalua con el metodo del proyecto.")
SIN_ESFUERZO = "no determinado"
_IPV4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?!\d)")


def id_hallazgo(titulo: str) -> str:
    """ID estable: H- y los 6 primeros hexadecimales del SHA-256 del titulo en espanol (la clave sin traducir)."""
    return "H-" + hashlib.sha256(titulo.encode("utf-8")).hexdigest()[:6]


def nivel(puntuacion: int) -> str:
    if puntuacion >= 20:
        return "Muy alto"
    if puntuacion >= 10:
        return "Alto"
    return "Medio" if puntuacion >= 5 else "Bajo"


def _ips_ruta(rutas: dict) -> dict:
    """{ip: {origenes}} de los activos que son objetivo o paso de un camino de A1 (Internet o zona IT)."""
    out: dict = {}
    for f in (rutas or {}).get("filas", ()):
        ips = set(_IPV4.findall(f.get("camino", ""))) | {f["objetivo"]}
        for ip in ips:
            out.setdefault(ip, set()).add(f["origen"])
    return out


def _kev(f: dict) -> bool:
    from .avisos_cisa import TITULO_KEV
    return TITULO_KEV in f["titulo"]


def _ips_hallazgo(f: dict, por_ip: dict) -> list:
    return sorted({ip for ip in (f.get("activos") or _IPV4.findall(f.get("evidencia") or "")) if ip in por_ip})


def _lista_activos(ips: list) -> str:
    if len(ips) <= MAX_ACTIVOS:
        return ";".join(ips)
    return ";".join(ips[:MAX_ACTIVOS]) + t(" y {n} mas", n=len(ips) - MAX_ACTIVOS)


def _t_dim(dim: str) -> str:
    """Traduce una dimension de impacto: las seis de la herramienta si; las del perfil son texto del proyecto."""
    base = dim.removesuffix(SUFIJO_INFERIDA)
    if base in DIMENSIONES_IMPACTO:
        return t(dim)
    return base + t(SUFIJO_INFERIDA) if base != dim else base


def _factores(f: dict, ips: list, expuestas: dict) -> list:
    """Factores de exposicion observados (sin puntos): origen alcanzable y KEV."""
    causas = []
    origenes = sorted({o for ip in ips for o in expuestas.get(ip, ())})
    if origenes:
        if "Internet" in origenes:
            causas.append(t("alcanzable desde Internet"))
        else:
            causas.append(t("alcanzable desde la zona IT {z}", z=", ".join(origenes)))
    if _kev(f):
        causas.append(t("CVE explotada (KEV)"))
    return causas


def _probabilidad(f: dict, ips: list, expuestas: dict, hay_rutas: bool) -> tuple:
    base = BASE_PROB[f["severidad"]]
    motivo = t("severidad {s} ({n})", s=t(f["severidad"]), n=base)
    causas = _factores(f, ips, expuestas)
    if causas:
        return min(5, base + 1), motivo + " + " + " y ".join(causas) + " (+1)"
    if not hay_rutas:
        return base, motivo + "; " + t("sin rutas de ataque calculadas: no suma exposicion")
    return base, motivo + "; " + t("sin exposicion observada desde Internet o IT")


def _impacto(ips: list, por_ip: dict, declaradas: dict, crit_decl: dict, dims=DIMENSIONES_IMPACTO,
             inferida=DIM_INFERIDA, candidato=False) -> tuple:
    """(impacto, dimension, motivo, declarado). Declarado por zona si algun activo cae en una zona con `impacto`;
    si no, inferido de la criticidad del activo mas critico; sin activo, 3. En modo candidato el motivo inferido
    no lleva el numero de la herramienta."""
    from .remediacion import criticidad_activo

    mejor = None            # (valor, indice de dimension, dimension, zona)
    for ip in ips:
        zona = por_ip[ip].get("zona_asignada") or ""
        for dim, v in (declaradas.get(zona) or {}).items():
            cand = (v, -dims.index(dim), dim, zona)
            if mejor is None or cand[:2] > mejor[:2]:
                mejor = cand
    if mejor:
        return mejor[0], mejor[2], t("zona {z} declara {d} = {n}", z=mejor[3], d=_t_dim(mejor[2]), n=mejor[0]), True
    if not ips:
        if candidato:
            return 3, inferida, t("hallazgo sin activo en la evidencia"), False
        return 3, inferida, t("hallazgo sin activo en la evidencia: impacto 3 por defecto, validar con el cliente"), False
    crit = min((criticidad_activo(por_ip[ip], crit_decl)[0] for ip in ips), key=lambda c: CRIT_ORDER.get(c, 9))
    n = IMPACTO_CRIT.get(crit, 3)
    if candidato:
        return n, inferida, t("criticidad {c} del activo mas critico", c=t(crit)), False
    return n, inferida, t("criticidad {c} del activo mas critico ({n}); inferido, validar con el cliente",
                          c=t(crit), n=n), False


def _agrupar(res) -> list:
    """Un hallazgo por titulo (la mayor severidad), sin Informativa; une activos."""
    from .report.common import agrupar_hallazgos

    out: dict = {}
    for f in agrupar_hallazgos([*res.caps, *res.extras]):
        if f["severidad"] not in BASE_PROB:
            continue
        g = out.get(f["titulo"])
        if g is None:
            out[f["titulo"]] = dict(f)
        else:       # misma pareja titulo-severidad distinta: queda la mas alta (vienen ordenadas)
            g["evidencia"] += "\n" + f["evidencia"]
            g["activos"] = sorted({*g.get("activos", []), *f.get("activos", [])})
    return list(out.values())


def construir(res) -> dict:
    """{"filas", "mapa", "quick_wins", "avisos"}; las filas llevan los valores en espanol."""
    from . import playbooks
    from .rutas_ataque import hay as hay_ra

    perfil = res.perfil or {}
    crit_decl = perfil.get("criticidad_activos", {})
    decl_zona = {z["nombre"]: z["impacto"] for z in perfil.get("zonas", ()) if z.get("impacto")}
    ajustes = perfil.get("ajustes_riesgo", {})
    candidatos = (perfil.get("riesgo") or {}).get("modo") == "candidatos"
    dims = dimensiones_impacto(perfil)
    inferida = dimension_inferida(perfil) + SUFIJO_INFERIDA
    por_ip = {ip: a for a in res.assets.values() for ip in a["ips"]}
    expuestas = _ips_ruta(res.rutas_ataque)
    hay_rutas = hay_ra(res.rutas_ataque)
    pbs = playbooks.cargar()
    filas, usados, nfact = [], set(), {}
    for f in _agrupar(res):
        hid = f.get("id") or id_hallazgo(f["titulo"])
        ips = _ips_hallazgo(f, por_ip)
        factores = _factores(f, ips, expuestas)
        if candidatos:
            p, mot_p = "", "; ".join([t("severidad {s}", s=t(f["severidad"])), *factores])
        else:
            p, mot_p = _probabilidad(f, ips, expuestas, hay_rutas)
        i, dim, mot_i, _decl = _impacto(ips, por_ip, decl_zona, crit_decl, dims, inferida, candidatos)
        if candidatos:
            i = ""
        origen = "candidato" if candidatos else "inferido"
        aj = ajustes.get(hid)
        if aj:
            usados.add(hid)
            nota = t("ajustado por el analista: {j}", j=aj["justificacion"])
            if "probabilidad" in aj:
                p, mot_p = aj["probabilidad"], nota
            if "impacto" in aj:
                i, mot_i = aj["impacto"], nota
            if not candidatos or ("probabilidad" in aj and "impacto" in aj):
                origen = "analista"
        pid = playbooks.para_titulo(f["titulo"])
        esfuerzo = pbs[pid]["esfuerzo_estimado"] if pid else SIN_ESFUERZO
        puntuada = p != "" and i != ""
        pts = p * i if puntuada else ""
        niv = nivel(pts) if puntuada else ""
        nfact[hid] = len(factores)
        zonas = sorted({por_ip[ip].get("zona_asignada") or "" for ip in ips} - {""})
        filas.append({
            "id_riesgo": "R-" + hid[2:], "id_hallazgo": hid, "titulo": f["titulo"], "categoria": f["categoria"],
            "severidad": f["severidad"], "zonas": ";".join(zonas), "activos": _lista_activos(ips),
            "probabilidad": p, "motivo_probabilidad": mot_p, "impacto": i, "dimension_impacto": dim,
            "motivo_impacto": mot_i, "puntuacion": pts, "nivel": niv,
            "tecnicas_mitre_ics": (f.get("referencias") or {}).get("mitre-ics", ""),
            "esfuerzo_estimado": esfuerzo, "quick_win": ("si" if niv in ("Alto", "Muy alto") and esfuerzo == "bajo" else "no") if puntuada else "",
            "origen": origen, "recomendacion": f["recomendacion"], "playbook": pid})
    if candidatos:      # primero lo puntuado por el analista; despues los candidatos por severidad y exposicion
        filas.sort(key=lambda r: (0, -r["puntuacion"], SEV_ORDER[r["severidad"]], 0, r["titulo"])
                   if r["puntuacion"] != "" else
                   (1, 0, SEV_ORDER[r["severidad"]], -nfact[r["id_hallazgo"]], r["titulo"]))
    else:
        filas.sort(key=lambda r: (-r["puntuacion"], SEV_ORDER[r["severidad"]], r["titulo"]))
    avisos = [t("ajustes_riesgo: el hallazgo {h} no aparece en esta corrida; el ajuste no se aplica.", h=h)
              for h in sorted(set(ajustes) - usados)]
    return {"filas": filas, "mapa": _mapa(filas), "quick_wins": [r for r in filas if r["quick_win"] == "si"],
            "avisos": avisos, "nota": t(NOTA), "modo": "candidatos" if candidatos else "puntuado"}


def _mapa(filas: list) -> list:
    """25 celdas (impacto 5 a 1, probabilidad 1 a 5): {impacto, probabilidad, puntuacion, nivel, riesgos, ids}."""
    out = []
    for i in range(5, 0, -1):
        for p in range(1, 6):
            ids = [r["id_riesgo"] for r in filas if r["puntuacion"] != "" and r["impacto"] == i
                   and r["probabilidad"] == p]
            out.append({"impacto": i, "probabilidad": p, "puntuacion": i * p, "nivel": nivel(i * p),
                        "riesgos": len(ids), "ids": ";".join(ids)})
    return out


def de(res) -> dict:
    """Registro de la corrida, calculado una vez."""
    if not res.riesgos:
        res.riesgos = construir(res)
        for adv in res.riesgos["avisos"]:
            print(f"[!] {adv}")
    return res.riesgos


def hay(r: dict) -> bool:
    return bool(r) and bool(r.get("filas"))


def _mostrar(r: dict) -> dict:
    return dict(r, **{c: t(r[c]) for c in ("titulo", "categoria", "severidad", "nivel", "origen", "recomendacion",
                                           "esfuerzo_estimado", "quick_win")},
                dimension_impacto=_t_dim(r["dimension_impacto"]))


def tabla(r: dict) -> list:
    return [[x.get(c, "") for c in COLUMNAS] for x in map(_mostrar, r["filas"])]


def tabla_mapa(r: dict) -> list:
    return [[c["impacto"], c["probabilidad"], c["puntuacion"], t(c["nivel"]), c["riesgos"], c["ids"]]
            for c in r["mapa"]]


def tablas(r: dict) -> list:
    """[(archivo, hoja, cabecera, filas)]; el mapa va al XLSX como cuadricula (xlsxout), no como tabla plana."""
    if not hay(r):
        return []
    return [(ARCHIVO_REGISTRO, HOJA_REGISTRO, COLUMNAS, tabla(r)), (ARCHIVO_MAPA, None, COL_MAPA, tabla_mapa(r))]


def cuadricula(r: dict) -> tuple:
    """(cabecera, filas, niveles) del mapa de calor: filas = impacto 5 a 1; cada celda es el conteo; `niveles`
    es la matriz de niveles (espanol) para colorear. La primera columna de cada fila es la etiqueta de impacto."""
    cab = [t("Impacto \\ Probabilidad")] + [str(p) for p in range(1, 6)]
    filas, niveles = [], []
    for k in range(5):
        celdas = r["mapa"][k * 5:(k + 1) * 5]
        filas.append([str(celdas[0]["impacto"])] + [c["riesgos"] for c in celdas])
        niveles.append([None] + [c["nivel"] for c in celdas])
    return cab, filas, niveles


def cuadricula_texto(r: dict) -> tuple:
    """Como `cuadricula`, pero cada celda dice conteo y nivel (Markdown, sin color)."""
    cab, filas, niveles = cuadricula(r)
    return cab, [[f[0]] + [f"{n} ({t(v)})" for n, v in zip(f[1:], niv[1:])] for f, niv in zip(filas, niveles)]


def seccion(r: dict) -> dict:
    """Datos de la seccion de los reportes (todo traducido)."""
    if not hay(r):
        return {"titulo": t(TITULO), "nota": t(NOTA), "vacia": t(SIN_RIESGOS)}
    cand = r.get("modo") == "candidatos"
    if cand:
        top = [[x["id_riesgo"], x["titulo"], x["severidad"], x["motivo_probabilidad"], x["zonas"],
                x["esfuerzo_estimado"]] for x in map(_mostrar, r["filas"][:MAX_TOP])]
    else:
        top = [[x["id_riesgo"], x["titulo"], x["severidad"], x["probabilidad"], x["impacto"], x["puntuacion"],
                x["nivel"], x["esfuerzo_estimado"]] for x in map(_mostrar, r["filas"][:MAX_TOP])]
    quick = [[x["id_riesgo"], x["titulo"], x["nivel"], x["esfuerzo_estimado"], x["playbook"] or "-"]
             for x in map(_mostrar, r["quick_wins"])]
    resumen = "; ".join(f"{t(n)}: {sum(1 for x in r['filas'] if x['nivel'] == n)}" for n in NIVELES) + "."
    if cand:
        n_p = sum(1 for x in r["filas"] if x["puntuacion"] != "")
        resumen = (t(FRASE_CANDIDATOS) + " "
                   + t("Candidatos: {c}; puntuados por el analista: {p}.", c=len(r["filas"]) - n_p, p=n_p))
        if n_p:
            resumen += " " + "; ".join(f"{t(n)}: {sum(1 for x in r['filas'] if x['nivel'] == n)}"
                                       for n in NIVELES) + "."
    return {"titulo": t(TITULO), "nota": t(NOTA), "resumen": resumen, "mapa": cuadricula(r),
            "mapa_texto": cuadricula_texto(r), "cab_top": [t(c) for c in (CAB_TOP_CAND if cand else CAB_TOP)],
            "top": top,
            "cab_quick": [t(c) for c in CAB_QUICK], "quick": quick, "nota_quick": t(NOTA_QUICK),
            "sin_quick": t(SIN_QUICK), "vacia": ""}


def para_json(r: dict) -> dict:
    if not hay(r):
        return {}
    out = {"registro": r["filas"], "mapa": r["mapa"], "quick_wins": r["quick_wins"],
           "nota": r["nota"]}
    if r.get("modo") == "candidatos":
        out["modo"] = "candidatos"
    return out
