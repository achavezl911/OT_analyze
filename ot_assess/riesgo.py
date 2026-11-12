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
from .perfil import DIMENSIONES_IMPACTO, dimension_inferida, dimensiones_impacto, escalas

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
NOTA_QUICK_PROYECTO = "Quick win: riesgo de nivel {n} cuyo playbook tiene esfuerzo estimado {e}."
NOTA_METODO = ("Escala, niveles, elevacion y quick win segun el metodo de riesgo del proyecto declarado en el "
               "perfil; los nombres y etiquetas del proyecto no se traducen.")
MAX_TOP = 10
MAX_ACTIVOS = 10

COLUMNAS = ["id_riesgo", "id_hallazgo", "titulo", "categoria", "severidad", "zonas", "activos", "probabilidad",
            "motivo_probabilidad", "impacto", "dimension_impacto", "motivo_impacto", "puntuacion", "nivel",
            "tecnicas_mitre_ics", "esfuerzo_estimado", "quick_win", "origen", "recomendacion", "playbook"]
COL_ETQ = {"probabilidad_etiqueta": ("probabilidad", "etq_p"), "impacto_etiqueta": ("impacto", "etq_i")}
COL_MAPA = ["impacto", "probabilidad", "puntuacion", "nivel", "riesgos", "ids"]
CAB_TOP = ["ID", "Riesgo", "Severidad", "Probabilidad", "Impacto", "Puntuacion", "Nivel", "Esfuerzo estimado"]
CAB_QUICK = ["ID", "Riesgo", "Nivel", "Esfuerzo estimado", "Playbook"]

NIVELES = ("Bajo", "Medio", "Alto", "Muy alto")
COLORES = {"Bajo": "92D050", "Medio": "FFE699", "Alto": "F4B183", "Muy alto": "FF5050"}   # verde a rojo
CLASES = {"Bajo": "mc-bajo", "Medio": "mc-medio", "Alto": "mc-alto", "Muy alto": "mc-muy-alto"}
NIVELES_DEF = (("Bajo", 1, "92D050"), ("Medio", 5, "FFE699"), ("Alto", 10, "F4B183"), ("Muy alto", 20, "FF5050"))
PALETA = ("92D050", "C9E265", "FFE699", "F4B183", "FF8080", "FF5050")       # verde a rojo (RM2, D129)
ESFUERZOS = ("bajo", "medio", "alto")
CLAVES_METODO = ("escala", "niveles", "elevacion", "quick_win")
MAX_ELEVACION = 10
_COND_DIM = re.compile(r"dimension:([a-z0-9_]{1,30})>=(\d+)")
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


def _color_posicion(k: int, n: int) -> str:
    return PALETA[(k * 10 + n - 1) // (2 * (n - 1))]


def _texto_corto(v, donde: str, maximo: int, fallo) -> str:
    if not isinstance(v, str) or not 1 <= len(v) <= maximo or "\n" in v or "\r" in v:
        fallo(f"'{donde}' debe ser un texto de 1 a {maximo} caracteres sin saltos de linea.")
    return v


def validar_metodo(d: dict, dims: tuple, fallo, objeto) -> dict:
    """Valida las subclaves de metodo de 'riesgo' (RM2, D129): escala, niveles, elevacion y quick_win."""
    out = {}
    if "escala" in d:
        e = objeto(d["escala"], "riesgo.escala", ("probabilidad", "impacto"))
        if not e:
            fallo("'riesgo.escala': indique 'probabilidad', 'impacto' o ambos.")
        out["escala"] = {}
        for eje in ("probabilidad", "impacto"):
            if eje not in e:
                continue
            etq = e[eje]
            if not isinstance(etq, list) or not 3 <= len(etq) <= 10:
                fallo(f"'riesgo.escala.{eje}' debe ser una lista de 3 a 10 etiquetas.")
            etq = [_texto_corto(x, f"riesgo.escala.{eje}", 40, fallo) for x in etq]
            if len(set(etq)) != len(etq):
                fallo(f"riesgo.escala.{eje} tiene etiquetas repetidas.")
            out["escala"][eje] = etq
    np_, ni = escalas(out)
    if "niveles" in d:
        lista = d["niveles"]
        if not isinstance(lista, list) or not 2 <= len(lista) <= 6:
            fallo("'riesgo.niveles' debe ser una lista de 2 a 6 niveles {nombre, desde, color}.")
        niv, vistos = [], set()
        for x in lista:
            x = objeto(x, "riesgo.niveles", ("nombre", "desde", "color"))
            if "nombre" not in x or "desde" not in x:
                fallo("cada nivel de 'riesgo.niveles' necesita 'nombre' y 'desde'.")
            nombre = _texto_corto(x["nombre"], "riesgo.niveles.nombre", 30, fallo)
            if nombre in vistos:
                fallo(f"riesgo.niveles: el nombre {nombre!r} esta repetido.")
            vistos.add(nombre)
            desde = x["desde"]
            if not isinstance(desde, int) or isinstance(desde, bool):
                fallo(f"riesgo.niveles.{nombre}: 'desde' debe ser un entero.")
            n = {"nombre": nombre, "desde": desde}
            if "color" in x:
                if not isinstance(x["color"], str) or not re.fullmatch(r"[0-9A-Fa-f]{6}", x["color"]):
                    fallo(f"riesgo.niveles.{nombre}: 'color' debe ser RRGGBB (seis hexadecimales).")
                n["color"] = x["color"].upper()
            niv.append(n)
        if niv[0]["desde"] != 1:
            fallo("riesgo.niveles: el primer nivel debe empezar en 'desde' = 1.")
        if any(a["desde"] >= b["desde"] for a, b in zip(niv, niv[1:])):
            fallo("riesgo.niveles: 'desde' debe ser estrictamente creciente.")
        if niv[-1]["desde"] > np_ * ni:
            fallo(f"riesgo.niveles: el ultimo 'desde' ({niv[-1]['desde']}) supera la puntuacion maxima {np_ * ni}.")
        out["niveles"] = niv
    nombres = [n["nombre"] for n in out["niveles"]] if "niveles" in out else [n[0] for n in NIVELES_DEF]
    if "elevacion" in d:
        lista = d["elevacion"]
        if not isinstance(lista, list) or len(lista) > MAX_ELEVACION:
            fallo(f"'riesgo.elevacion' debe ser una lista de 0 a {MAX_ELEVACION} reglas.")
        out["elevacion"] = []
        for x in lista:
            x = objeto(x, "riesgo.elevacion", ("condicion", "nivel_minimo"))
            if "condicion" not in x or "nivel_minimo" not in x:
                fallo("cada regla de 'riesgo.elevacion' necesita 'condicion' y 'nivel_minimo'.")
            c = x["condicion"]
            m = _COND_DIM.fullmatch(c) if isinstance(c, str) else None
            if c not in ("kev", "exposicion") and not m:
                fallo(f"riesgo.elevacion: condicion {c!r} desconocida; valores: kev, exposicion, "
                      "dimension:<id>>=<n>.")
            if m and m.group(1) not in dims:
                fallo(f"riesgo.elevacion: la dimension {m.group(1)!r} no esta en las dimensiones de impacto "
                      f"({', '.join(dims)}).")
            if m and not 1 <= int(m.group(2)) <= ni:
                fallo(f"riesgo.elevacion: {c!r} fuera de la escala de impacto (1 a {ni}).")
            if x["nivel_minimo"] not in nombres:
                fallo(f"riesgo.elevacion: el nivel {x['nivel_minimo']!r} no existe ({', '.join(nombres)}).")
            out["elevacion"].append({"condicion": c, "nivel_minimo": x["nivel_minimo"]})
    if "quick_win" in d:
        q = objeto(d["quick_win"], "riesgo.quick_win", ("niveles", "esfuerzo"))
        out["quick_win"] = {}
        for k, validos in (("niveles", nombres), ("esfuerzo", ESFUERZOS)):
            if k not in q:
                continue
            v = q[k]
            if not isinstance(v, list) or not v or any(x not in validos for x in v):
                fallo(f"'riesgo.quick_win.{k}' debe ser una lista no vacia con valores de: {', '.join(validos)}.")
            out["quick_win"][k] = list(dict.fromkeys(v))
    return out


def metodo(perfil) -> dict:
    """Metodo de riesgo efectivo: escala, niveles con color, elevacion y criterio de quick win (RM2, D129)."""
    d = (perfil or {}).get("riesgo") or {}
    esc = d.get("escala") or {}
    np_, ni = escalas(d)
    if d.get("niveles"):
        n = len(d["niveles"])
        niveles = [(x["nombre"], x["desde"], x.get("color") or _color_posicion(k, n))
                   for k, x in enumerate(d["niveles"])]
    else:
        niveles = list(NIVELES_DEF)
    q = d.get("quick_win") or {}
    return {"np": np_, "ni": ni, "etq_p": list(esc.get("probabilidad") or ()), "etq_i": list(esc.get("impacto") or ()),
            "niveles": niveles, "nombres": [x[0] for x in niveles], "propio_niveles": bool(d.get("niveles")),
            "elevacion": list(d.get("elevacion") or ()), "con_elevacion": "elevacion" in d,
            "qw_niveles": list(q.get("niveles") or [x[0] for x in niveles[-2:]]),
            "qw_esfuerzo": list(q.get("esfuerzo") or ["bajo"]),
            "declarado": any(k in d for k in CLAVES_METODO)}


def nivel(puntuacion: int, m: dict = None) -> str:
    """Nivel de una puntuacion: el de mayor 'desde' <= puntuacion (el primero si ninguno)."""
    elegido = (m or _M0)["niveles"][0][0]
    for nombre, desde, _ in (m or _M0)["niveles"]:
        if puntuacion >= desde:
            elegido = nombre
    return elegido


def _reescalar(v: int, n: int) -> int:
    """1-5 -> 1-n: 1 + redondeo hacia arriba en .5 de (v-1)*(n-1)/4."""
    return 1 + ((v - 1) * (n - 1) + 2) // 4


def _etq(k: int, etiquetas: list) -> str:
    return f"{k} - {etiquetas[k - 1]}" if etiquetas else str(k)


_M0 = metodo({})


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
    m = metodo(perfil)
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
            if m["np"] != 5:
                p, mot_p = _reescalado(p, mot_p, m["np"])
        i, dim, mot_i, decl = _impacto(ips, por_ip, decl_zona, crit_decl, dims, inferida, candidatos)
        if candidatos:
            i = ""
        elif not decl and m["ni"] != 5:
            i, mot_i = _reescalado(i, mot_i, m["ni"])
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
        niv = nivel(pts, m) if puntuada else ""
        elev = []
        if niv and m["elevacion"]:
            niv, elev = _elevar(m, niv, f, ips, expuestas, por_ip, decl_zona)
        nfact[hid] = len(factores)
        zonas = sorted({por_ip[ip].get("zona_asignada") or "" for ip in ips} - {""})
        filas.append({
            "id_riesgo": "R-" + hid[2:], "id_hallazgo": hid, "titulo": f["titulo"], "categoria": f["categoria"],
            "severidad": f["severidad"], "zonas": ";".join(zonas), "activos": _lista_activos(ips),
            "probabilidad": p, "motivo_probabilidad": mot_p, "impacto": i, "dimension_impacto": dim,
            "motivo_impacto": mot_i, "puntuacion": pts, "nivel": niv,
            "tecnicas_mitre_ics": (f.get("referencias") or {}).get("mitre-ics", ""),
            "esfuerzo_estimado": esfuerzo,
            "quick_win": ("si" if niv in m["qw_niveles"] and esfuerzo in m["qw_esfuerzo"] else "no") if puntuada else "",
            "origen": origen, "recomendacion": f["recomendacion"], "playbook": pid})
        for col, (eje, etq) in COL_ETQ.items():
            if m[etq]:
                filas[-1][col] = m[etq][filas[-1][eje] - 1] if filas[-1][eje] != "" else ""
        if m["con_elevacion"]:
            filas[-1]["elevacion"] = "; ".join(elev)
    if candidatos:      # primero lo puntuado por el analista; despues los candidatos por severidad y exposicion
        filas.sort(key=lambda r: (0, -r["puntuacion"], SEV_ORDER[r["severidad"]], 0, r["titulo"])
                   if r["puntuacion"] != "" else
                   (1, 0, SEV_ORDER[r["severidad"]], -nfact[r["id_hallazgo"]], r["titulo"]))
    else:
        filas.sort(key=lambda r: (-r["puntuacion"], SEV_ORDER[r["severidad"]], r["titulo"]))
    avisos = [t("ajustes_riesgo: el hallazgo {h} no aparece en esta corrida; el ajuste no se aplica.", h=h)
              for h in sorted(set(ajustes) - usados)]
    nota = t(NOTA) + (" " + t(NOTA_METODO) if m["declarado"] else "")
    return {"filas": filas, "mapa": _mapa(filas, m), "quick_wins": [r for r in filas if r["quick_win"] == "si"],
            "avisos": avisos, "nota": nota, "modo": "candidatos" if candidatos else "puntuado", "metodo": m}


def _reescalado(v: int, motivo: str, n: int) -> tuple:
    return _reescalar(v, n), motivo + "; " + t("reescalado de 1-5 a 1-{n}", n=n)


def _elevar(m: dict, niv: str, f: dict, ips: list, expuestas: dict, por_ip: dict, decl_zona: dict) -> tuple:
    """(nivel, reglas aplicadas): sube el nivel al menos al minimo de cada regla cuya condicion se cumple."""
    idx, aplicadas = m["nombres"].index(niv), []
    for r in m["elevacion"]:
        c = r["condicion"]
        if c == "kev":
            ok = _kev(f)
        elif c == "exposicion":
            ok = any(expuestas.get(ip) for ip in ips)
        else:
            dim, minimo = _COND_DIM.fullmatch(c).groups()
            ok = any((decl_zona.get(por_ip[ip].get("zona_asignada") or "") or {}).get(dim, 0) >= int(minimo)
                     for ip in ips)
        if ok:
            aplicadas.append(f"{c} -> {r['nivel_minimo']}")
            idx = max(idx, m["nombres"].index(r["nivel_minimo"]))
    return m["nombres"][idx], aplicadas


def _mapa(filas: list, m: dict = None) -> list:
    """Celdas (impacto N a 1, probabilidad 1 a M): {impacto, probabilidad, puntuacion, nivel, riesgos, ids}."""
    m = m or _M0
    out = []
    for i in range(m["ni"], 0, -1):
        for p in range(1, m["np"] + 1):
            ids = [r["id_riesgo"] for r in filas if r["puntuacion"] != "" and r["impacto"] == i
                   and r["probabilidad"] == p]
            out.append({"impacto": i, "probabilidad": p, "puntuacion": i * p, "nivel": nivel(i * p, m),
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


def _mostrar(r: dict, m: dict = None) -> dict:
    """Fila traducida; los nombres de nivel del proyecto (RM2) no se traducen."""
    out = dict(r, **{c: t(r[c]) for c in ("titulo", "categoria", "severidad", "origen", "recomendacion",
                                          "esfuerzo_estimado", "quick_win")},
               dimension_impacto=_t_dim(r["dimension_impacto"]))
    out["nivel"] = r["nivel"] if (m or _M0)["propio_niveles"] else t(r["nivel"])
    return out


def _m(r: dict) -> dict:
    return r.get("metodo") or _M0


def columnas(r: dict) -> list:
    """Columnas de riesgos.csv: las fijas y, segun el metodo del proyecto, etiquetas de escala y elevacion."""
    m = _m(r)
    return COLUMNAS + [c for c, (_, etq) in COL_ETQ.items() if m[etq]] + (["elevacion"] if m["con_elevacion"] else [])


def tabla(r: dict) -> list:
    cols, m = columnas(r), _m(r)
    return [[x.get(c, "") for c in cols] for x in (_mostrar(f, m) for f in r["filas"])]


def tabla_mapa(r: dict) -> list:
    m = _m(r)
    return [[c["impacto"], c["probabilidad"], c["puntuacion"], c["nivel"] if m["propio_niveles"] else t(c["nivel"]),
             c["riesgos"], c["ids"]] for c in r["mapa"]]


def tablas(r: dict) -> list:
    """[(archivo, hoja, cabecera, filas)]; el mapa va al XLSX como cuadricula (xlsxout), no como tabla plana."""
    if not hay(r):
        return []
    return [(ARCHIVO_REGISTRO, HOJA_REGISTRO, columnas(r), tabla(r)), (ARCHIVO_MAPA, None, COL_MAPA, tabla_mapa(r))]


def cuadricula(r: dict) -> tuple:
    """(cabecera, filas, niveles) del mapa de calor: filas = impacto 5 a 1; cada celda es el conteo; `niveles`
    es la matriz de niveles (espanol) para colorear. La primera columna de cada fila es la etiqueta de impacto."""
    m = _m(r)
    cab = [t("Impacto \\ Probabilidad")] + [_etq(p, m["etq_p"]) for p in range(1, m["np"] + 1)]
    filas, niveles = [], []
    for k in range(m["ni"]):
        celdas = r["mapa"][k * m["np"]:(k + 1) * m["np"]]
        filas.append([_etq(celdas[0]["impacto"], m["etq_i"])] + [c["riesgos"] for c in celdas])
        niveles.append([None] + [c["nivel"] for c in celdas])
    return cab, filas, niveles


def cuadricula_texto(r: dict) -> tuple:
    """Como `cuadricula`, pero cada celda dice conteo y nivel (Markdown, sin color)."""
    cab, filas, niveles = cuadricula(r)
    tn = (lambda v: v) if _m(r)["propio_niveles"] else t
    return cab, [[f[0]] + [f"{n} ({tn(v)})" for n, v in zip(f[1:], niv[1:])] for f, niv in zip(filas, niveles)]


def _nota_quick(m: dict) -> str:
    if not m["declarado"]:
        return t(NOTA_QUICK)
    return t(NOTA_QUICK_PROYECTO, n=", ".join(m["qw_niveles"] if m["propio_niveles"] else map(t, m["qw_niveles"])),
             e=", ".join(map(t, m["qw_esfuerzo"])))


def seccion(r: dict) -> dict:
    """Datos de la seccion de los reportes (todo traducido)."""
    if not hay(r):
        return {"titulo": t(TITULO), "nota": t(NOTA), "vacia": t(SIN_RIESGOS)}
    m = _m(r)
    nota = t(NOTA) + (" " + t(NOTA_METODO) if m["declarado"] else "")
    tn = (lambda v: v) if m["propio_niveles"] else t
    cand = r.get("modo") == "candidatos"
    filas = [_mostrar(x, m) for x in r["filas"][:MAX_TOP]]
    if cand:
        top = [[x["id_riesgo"], x["titulo"], x["severidad"], x["motivo_probabilidad"], x["zonas"],
                x["esfuerzo_estimado"]] for x in filas]
    else:
        top = [[x["id_riesgo"], x["titulo"], x["severidad"], x["probabilidad"], x["impacto"], x["puntuacion"],
                x["nivel"], x["esfuerzo_estimado"]] for x in filas]
    quick = [[x["id_riesgo"], x["titulo"], x["nivel"], x["esfuerzo_estimado"], x["playbook"] or "-"]
             for x in (_mostrar(y, m) for y in r["quick_wins"])]
    por_nivel = "; ".join(f"{tn(n)}: {sum(1 for x in r['filas'] if x['nivel'] == n)}" for n in m["nombres"]) + "."
    resumen = por_nivel
    if cand:
        n_p = sum(1 for x in r["filas"] if x["puntuacion"] != "")
        resumen = (t(FRASE_CANDIDATOS) + " "
                   + t("Candidatos: {c}; puntuados por el analista: {p}.", c=len(r["filas"]) - n_p, p=n_p))
        if n_p:
            resumen += " " + por_nivel
    return {"titulo": t(TITULO), "nota": nota, "resumen": resumen, "mapa": cuadricula(r),
            "mapa_texto": cuadricula_texto(r), "cab_top": [t(c) for c in (CAB_TOP_CAND if cand else CAB_TOP)],
            "top": top, "colores": {n: c for n, _, c in m["niveles"]}, "propio": m["propio_niveles"],
            "cab_quick": [t(c) for c in CAB_QUICK], "quick": quick, "nota_quick": _nota_quick(m),
            "sin_quick": t(SIN_QUICK), "vacia": ""}


def para_json(r: dict) -> dict:
    if not hay(r):
        return {}
    out = {"registro": r["filas"], "mapa": r["mapa"], "quick_wins": r["quick_wins"],
           "nota": r["nota"]}
    if r.get("modo") == "candidatos":
        out["modo"] = "candidatos"
    m = _m(r)
    if m["declarado"]:
        out["metodo"] = {"escala": {"probabilidad": m["np"], "impacto": m["ni"]},
                         "niveles": [{"nombre": n, "desde": d} for n, d, _ in m["niveles"]],
                         "elevacion": len(m["elevacion"]),
                         "quick_win": {"niveles": m["qw_niveles"], "esfuerzo": m["qw_esfuerzo"]}}
    return out
