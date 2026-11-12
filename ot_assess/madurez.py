"""Madurez de ciberseguridad OT por dominio (M7, D84).

El nivel de cada dominio es lo que el sitio declara en una entrevista estructurada (cuestionario de 32 preguntas,
escala 0-4 alineada a ML1-ML4 de IEC 62443). La herramienta da el cuestionario, lo lee, calcula nivel actual,
objetivo y brecha, y agrega evidencia tecnica de la corrida: los hallazgos asignados a cada dominio y algunos datos
ya calculados (inventario, obsolescencia, KEV, cobertura de captura). Si el nivel declarado (>= 3) tiene al menos un
hallazgo Alta asignado, lo marca para revision; no cambia el nivel. Nunca dice "cumple" ni "no cumple". Las
preguntas, la asignacion de titulos a dominio y los mapeos a NIST CSF 2.0 e IEC 62443 son datos propios
(`data/madurez.json`) sin revisar. Solo lee el modelo ya calculado.
"""
from __future__ import annotations

import csv
import json
import re
from pathlib import Path

from .i18n import Traducido, idioma, t

RUTA = Path(__file__).parent / "data" / "madurez.json"

TITULO = "Madurez por dominio"
HOJA = "Madurez por dominio"
HOJA_CUESTIONARIO = "Cuestionario de madurez"
ARCHIVO = "madurez.csv"
ARCHIVO_CUESTIONARIO = "cuestionario_madurez.csv"
NOTA = ("El nivel de cada dominio es lo que el sitio declara en la entrevista estructurada (escala 0 a 4, alineada a "
        "los niveles de madurez ML1 a ML4 de IEC 62443); la herramienta no lo mide. Las senales tecnicas son los "
        "hallazgos de esta corrida asignados al dominio y datos ya calculados; son evidencia relacionada, no un "
        "veredicto de cumplimiento. La asignacion de hallazgos a dominio, las preguntas y sus mapeos a NIST CSF 2.0 e "
        "IEC 62443 estan sin revisar. Un dominio con menos de la mitad de las preguntas contestadas queda "
        "insuficiente, sin nivel.")
SIN_CUESTIONARIO = ("No se cargo el cuestionario contestado: la seccion muestra el objetivo y las senales "
                    "tecnicas. El nivel actual se mide con la entrevista; la plantilla esta en {archivo} y se "
                    "entrega con --madurez ARCHIVO.")
NOTA_PROYECTO = ("El nivel de cada dominio es lo que el sitio declara en la entrevista estructurada, en la escala de "
                 "madurez del proyecto (definida en el perfil, con su equivalencia con la escala de la herramienta); la "
                 "herramienta no lo mide. Las senales tecnicas son los hallazgos de esta corrida asignados al dominio y "
                 "datos ya calculados; son evidencia relacionada, no un veredicto de cumplimiento. La asignacion de "
                 "hallazgos a dominio, las preguntas y sus mapeos a NIST CSF 2.0 e IEC 62443 estan sin revisar. Un "
                 "dominio con menos de la mitad de las preguntas contestadas queda insuficiente, sin nivel.")
TITULO_EQUIVALENCIA = "Equivalencia de escalas"
CAB_EQUIVALENCIA = ["Valor", "Nombre", "Descripcion", "Niveles de la herramienta (0 a 4)"]
COL_NOMBRES = ["nombre_nivel_actual", "nombre_nivel_objetivo"]
ORIGEN_DOMINIO = "declarado en el perfil (madurez_objetivo)"
ORIGEN_ML = "tomado de ml_objetivo del perfil"
ORIGEN_PROPUESTO = "propuesto por la herramienta; lo fija el cliente"
OBJETIVO_DEFECTO = 2
INSUFICIENTE = "insuficiente"
REVISAR = "revisar: la evidencia de red no respalda el nivel declarado ({titulos})"
SOLO_ENTREVISTA = "no evaluable con datos de red; solo con la entrevista"
NIVEL_REVISION = 3
MAX_TITULOS = 5

COLUMNAS = ["dominio", "nivel_actual", "nivel_objetivo", "origen_objetivo", "brecha", "contestadas", "total",
            "hallazgos_alta", "hallazgos_media", "hallazgos_baja", "senales", "contradiccion",
            "referencias_csf", "referencias_62443"]
COL_CUESTIONARIO = ["id", "dominio", "pregunta", "escala", "respuesta", "evidencia_presentada", "entrevistado",
                    "fecha", "comentario"]
CAB_SECCION = ["Dominio", "Nivel actual", "Objetivo", "Brecha", "Contestadas", "Hallazgos Alta/Media/Baja",
               "Senales tecnicas", "Revision"]
COL_RESPUESTAS = ("respuesta", "evidencia_presentada", "entrevistado", "fecha", "comentario")
_NA = ("n/a", "na")
_ENTERO = re.compile(r"-?\d+")


class ErrorMadurez(ValueError):
    """Cuestionario o perfil invalido; el mensaje trae el numero de linea."""


_cache: dict = {}


def datos() -> dict:
    if not _cache:
        _cache.update(json.loads(RUTA.read_text(encoding="utf-8")))
    return _cache


def claves() -> tuple:
    return tuple(d["clave"] for d in datos()["dominios"])


def preguntas() -> list:
    """[{id, dominio, texto, csf, iec62443}] en el orden del cuestionario."""
    return [dict(p, dominio=d["clave"]) for d in datos()["dominios"] for p in d["preguntas"]]


def nombre_dominio(clave: str) -> str:
    return next(d["nombre"] for d in datos()["dominios"] if d["clave"] == clave)


def texto_escala(esc: dict | None = None) -> str:
    if esc and esc["proyecto"]:
        return "; ".join(f"{n['valor']} = {n['nombre']}" + (f": {n['descripcion']}" if n.get("descripcion") else "")
                         for n in esc["niveles"])
    return "; ".join(f"{n} = {t(x)}" for n, x in datos()["escala"].items())


# --- escala de madurez del proyecto (MAD2, D131) ----------------------------------------------------------- #

def equivalencia_defecto(minimo: int, maximo: int) -> dict:
    """Nivel 0-4 de la herramienta -> valor de la escala del proyecto: lineal, el .5 sube."""
    n = maximo - minimo
    return {k: minimo + int(k * n / 4 + 0.5) for k in range(5)}


def escala_de(perfil) -> dict:
    """Escala efectiva: {proyecto, niveles, min, max, eq {0..4: valor}}. Sin 'escala_madurez': la 0-4 de la herramienta."""
    e = (perfil or {}).get("escala_madurez")
    if not e:
        return {"proyecto": False, "niveles": [], "min": 0, "max": 4, "eq": {k: k for k in range(5)}}
    vals = [n["valor"] for n in e["niveles"]]
    eq = {int(k): v for k, v in (e.get("equivalencia") or {}).items()} or equivalencia_defecto(vals[0], vals[-1])
    return {"proyecto": True, "niveles": [dict(n) for n in e["niveles"]], "min": vals[0], "max": vals[-1], "eq": eq}


def nombre_nivel(esc: dict, valor) -> str:
    """Nombre del nivel de mayor valor <= `valor`; vacio sin valor o sin escala del proyecto."""
    if valor is None or not esc["proyecto"]:
        return ""
    nombre = ""
    for n in esc["niveles"]:
        if n["valor"] <= valor:
            nombre = n["nombre"]
    return nombre


def validar_escala(d, fallo, objeto) -> dict:
    """Valida `escala_madurez` del perfil. Devuelve {niveles, equivalencia} con la equivalencia completa."""
    from .riesgo import _texto_corto

    d = objeto(d, "escala_madurez", ("niveles", "equivalencia"))
    lista = d.get("niveles")
    if not isinstance(lista, list) or not 3 <= len(lista) <= 7:
        fallo("'escala_madurez.niveles' debe ser una lista de 3 a 7 niveles {valor, nombre, descripcion}.")
    niveles, nombres = [], set()
    for x in lista:
        x = objeto(x, "escala_madurez.niveles", ("valor", "nombre", "descripcion"))
        if "valor" not in x or "nombre" not in x:
            fallo("cada nivel de 'escala_madurez.niveles' necesita 'valor' y 'nombre'.")
        if not isinstance(x["valor"], int) or isinstance(x["valor"], bool):
            fallo(f"escala_madurez.niveles: 'valor' {x['valor']!r} debe ser un entero.")
        n = {"valor": x["valor"], "nombre": _texto_corto(x["nombre"], "escala_madurez.niveles.nombre", 40, fallo)}
        if n["nombre"] in nombres:
            fallo(f"escala_madurez.niveles: el nombre {n['nombre']!r} esta repetido.")
        nombres.add(n["nombre"])
        if "descripcion" in x:
            n["descripcion"] = _texto_corto(x["descripcion"], "escala_madurez.niveles.descripcion", 300, fallo)
        niveles.append(n)
    vals = [n["valor"] for n in niveles]
    if any(b != a + 1 for a, b in zip(vals, vals[1:])):
        fallo("escala_madurez.niveles: los valores deben ser enteros consecutivos y ascendentes (p. ej. 1 a 5).")
    if "equivalencia" in d:
        e = objeto(d["equivalencia"], "escala_madurez.equivalencia", tuple("01234"))
        if sorted(e) != list("01234"):
            fallo("'escala_madurez.equivalencia' necesita las cinco claves 0 a 4 (niveles de la herramienta).")
        eq = {}
        for k in "01234":
            v = e[k]
            if not isinstance(v, int) or isinstance(v, bool) or v not in vals:
                fallo(f"escala_madurez.equivalencia.{k}: {v!r} no es un valor de la escala ({vals[0]} a {vals[-1]}).")
            eq[k] = v
        if any(eq[a] > eq[b] for a, b in zip("0123", "1234")):
            fallo("'escala_madurez.equivalencia' no puede decrecer de un nivel de la herramienta al siguiente.")
    else:
        eq = {str(k): v for k, v in equivalencia_defecto(vals[0], vals[-1]).items()}
    return {"niveles": niveles, "equivalencia": eq}


def dominios_de(titulo: str) -> set:
    """Claves de dominio cuyos fragmentos aparecen en el titulo (en espanol); una prueba exige exactamente una."""
    bajo = titulo.lower()
    return {dom for dom, frags in datos()["asignacion_titulos"].items() if any(f in bajo for f in frags)}


def dominio_de(titulo: str) -> str:
    d = dominios_de(titulo)
    return next(iter(d)) if len(d) == 1 else ""


def objetivos_validos(d, fallo, escala: dict | None = None) -> dict:
    """Valida `madurez_objetivo` del perfil: {dominio: entero dentro de la escala (0 a 4 o la del proyecto)}."""
    lo, hi = (escala["min"], escala["max"]) if escala else (0, 4)
    if not isinstance(d, dict):
        fallo(f"'madurez_objetivo' debe ser un objeto dominio -> nivel ({lo} a {hi}).")
    for k, v in d.items():
        if k not in claves():
            fallo(f"madurez_objetivo: '{k}' no es un dominio (use: {', '.join(claves())}).")
        if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
            fallo(f"madurez_objetivo.{k}: '{v}' debe ser un entero de {lo} a {hi}.")
    return dict(d)


# --- cuestionario ------------------------------------------------------------------------------------------ #

def cab_cuestionario() -> list:
    """Cabecera traducida. 'respuesta' ya significa otra cosa en el catalogo (DNS), asi que va con su propia clave."""
    return [t("respuesta (entrevista)") if c == "respuesta" and idioma() != "es" else
            (Traducido(c) if c == "respuesta" else t(c)) for c in COL_CUESTIONARIO]


def filas_cuestionario(respuestas: dict | None = None, escala: dict | None = None) -> list:
    """Filas del cuestionario (traducidas); con `respuestas` ({id: {columna: valor}}) las repite."""
    respuestas = respuestas or {}
    esc = texto_escala(escala)
    out = []
    for p in preguntas():
        r = respuestas.get(p["id"], {})
        out.append([p["id"], t(nombre_dominio(p["dominio"])), t(p["texto"]), esc]
                   + [r.get(c, "") for c in COL_RESPUESTAS])
    return out


def escribir_cuestionario(ruta, respuestas: dict | None = None, escala: dict | None = None) -> Path:
    from .report.common import escritor_csv

    ruta = Path(ruta)
    with open(ruta, "w", newline="", encoding="utf-8-sig") as fh:
        w = escritor_csv(fh)
        w.writerow(cab_cuestionario())
        w.writerows(filas_cuestionario(respuestas, escala))
    return ruta


def _separador(texto: str) -> str:
    primera = texto.splitlines()[0] if texto.strip() else ""
    return ";" if primera.count(";") > primera.count(",") else ","


def leer(ruta, escala: dict | None = None) -> dict:
    """Lee el cuestionario contestado: {id: {respuesta, evidencia_presentada, entrevistado, fecha, comentario}}.
    `respuesta` es un entero 0-4 (o de la escala del proyecto), "N/A" o "" (sin contestar). Falla con ErrorMadurez y todas las lineas con
    error; no devuelve nada a medias."""
    ruta = Path(ruta)
    try:
        texto = ruta.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as e:
        raise ErrorMadurez(f"No pude leer el cuestionario '{ruta.name}': {e}")
    lector = csv.reader(texto.splitlines(), delimiter=_separador(texto))
    try:
        cab = [c.strip().lower() for c in next(lector)]
    except StopIteration:
        raise ErrorMadurez(f"{ruta.name}: el archivo esta vacio.")
    except csv.Error as e:
        raise ErrorMadurez(f"{ruta.name} linea 1: no es un CSV valido ({e}).")
    for c in ("id", "respuesta"):
        if c not in cab:
            raise ErrorMadurez(f"{ruta.name} linea 1: falta la columna '{c}'.")
    conocidos = {p["id"] for p in preguntas()}
    lo, hi = (escala["min"], escala["max"]) if escala else (0, 4)
    out, errores = {}, []
    for fila in lector:
        n = lector.line_num
        if not any(x.strip() for x in fila):
            continue
        d = {c: (fila[i].strip() if i < len(fila) else "") for i, c in enumerate(cab)}
        ident = d["id"].upper()
        if ident not in conocidos:
            errores.append(f"{ruta.name} linea {n}: el ID '{d['id']}' no existe en el cuestionario.")
            continue
        if ident in out:
            errores.append(f"{ruta.name} linea {n}: el ID '{ident}' esta repetido.")
            continue
        r = d["respuesta"]
        if r.lower() in _NA:
            r = "N/A"
        elif r and not (_ENTERO.fullmatch(r) and lo <= int(r) <= hi and r == str(int(r))):
            errores.append(f"{ruta.name} linea {n}: respuesta '{r}' no valida en {ident} (use {lo} a {hi}, N/A o "
                           "deje vacio).")
            continue
        out[ident] = {"respuesta": r, **{c: d.get(c, "") for c in COL_RESPUESTAS[1:]}}
    if errores:
        raise ErrorMadurez("\n".join(errores[:20]) + (f"\n... y {len(errores) - 20} errores mas"
                                                      if len(errores) > 20 else ""))
    return out


def leer_opcion(ap, ruta, perfil=None):
    """Para `--madurez ARCHIVO` de los CLI de analisis: None sin la opcion; con ella, lo que devuelve `leer`
    o un error de argumentos (antes de analizar nada)."""
    if not ruta:
        return None
    if not Path(ruta).is_file():
        ap.error(f"--madurez espera un archivo existente: '{ruta}'")
    try:
        return leer(ruta, escala_de(perfil))
    except ErrorMadurez as e:
        ap.error(str(e))


def imprimir(m: dict) -> None:
    g = m["general"]
    if not m["con_cuestionario"]:
        print("    madurez: sin cuestionario (plantilla en cuestionario_madurez.csv)")
    elif g["nivel"] is None:
        print("    madurez: ningun dominio con respuestas suficientes")
    else:
        print(f"    madurez: promedio {_num(g['nivel'])} de {_esc(m)['max']} (objetivo {_num(g['objetivo'])}, "
              f"brecha {_num(g['brecha'])}) en {g['dominios_con_nivel']} dominios")
    for x in m["dominios"]:
        if x["contradiccion"]:
            print(f"[!] madurez {x['clave']}: {x['contradiccion']}")


# --- calculo ----------------------------------------------------------------------------------------------- #

def _redondear(x: float) -> float:
    return int(x * 10 + 0.5) / 10


def _esc(m: dict) -> dict:
    return m.get("escala") or escala_de(None)


def _nivel(contestadas: dict, preguntas_dom: list) -> tuple:
    """(nivel o None, numericas, na, total). Insuficiente: menos de la mitad contestadas o sin ninguna numerica."""
    rs = [contestadas.get(p["id"], {}).get("respuesta", "") for p in preguntas_dom]
    numericas = [int(r) for r in rs if _ENTERO.fullmatch(r)]
    na = sum(1 for r in rs if r == "N/A")
    total = len(preguntas_dom)
    if not numericas or (len(numericas) + na) * 2 < total:
        return None, len(numericas), na, total
    return _redondear(sum(numericas) / len(numericas)), len(numericas), na, total


def _objetivo(dom: str, perfil: dict, esc: dict) -> tuple:
    por_dom = perfil.get("madurez_objetivo") or {}
    if dom in por_dom:
        return por_dom[dom], ORIGEN_DOMINIO
    ml = str(perfil.get("ml_objetivo") or "")
    if re.fullmatch(r"ML[1-4]", ml):
        return esc["eq"][int(ml[-1])], ORIGEN_ML
    return esc["eq"][OBJETIVO_DEFECTO], ORIGEN_PROPUESTO


def _hallazgos(res) -> tuple:
    """({dominio: {"Alta": n, "Media": n, "Baja": n, "titulos_alta": [...]}}, titulos sin dominio)."""
    from .report.common import agrupar_hallazgos

    out = {c: {"Alta": 0, "Media": 0, "Baja": 0, "titulos_alta": []} for c in claves()}
    sin = set()
    for f in agrupar_hallazgos([*getattr(res, "caps", ()), *getattr(res, "extras", ())]):
        if f["severidad"] not in ("Alta", "Media", "Baja"):
            continue
        dom = dominio_de(f["titulo"])
        if not dom:
            sin.add(f["titulo"])
            continue
        out[dom][f["severidad"]] += 1
        if f["severidad"] == "Alta" and f["titulo"] not in out[dom]["titulos_alta"]:
            out[dom]["titulos_alta"].append(f["titulo"])
    return out, sorted(sin)


def _pct(a: int, b: int) -> int:
    return int(100 * a / b + 0.5) if b else 0


def _senales(res) -> dict:
    """Senales tecnicas por dominio donde el dato ya existe en la corrida."""
    from . import cobertura_captura as _cc
    from . import obsolescencia as _ob

    s = {c: [] for c in claves()}
    inv = getattr(res, "inventario_normalizado", None) or {}
    filas = inv.get("filas") or []
    if filas:
        completos = sum(1 for f in filas if all((f["campos"].get(c) or {}).get("valor")
                                                for c in ("fabricante", "modelo", "firmware")))
        s["activos"].append(t("{p}% de {n} activos del inventario normalizado con fabricante, modelo y firmware",
                              p=_pct(completos, len(filas)), n=len(filas)))
    else:
        s["activos"].append(t("sin inventario normalizado en esta corrida"))
    obs = getattr(res, "obsolescencia", None) or {}
    if obs.get("filas"):
        vencidos = len({f["id"] for f in obs["filas"] if f["estado"] == _ob.F_VENCIDO})
        s["parches"].append(t("{n} activos fuera de soporte (reporte de obsolescencia)", n=vencidos))
    cruces = getattr(res, "vulns_cruces", None) or []
    if any("kev" in c for c in cruces):
        kev = len({c["activo"] for c in cruces if c.get("kev") == "si" and c["activo"] is not None
                   and c["vuln"]["estado"] == "abierta"})
        s["parches"].append(t("{n} activos con CVE en el catalogo KEV (abiertas)", n=kev))
    cob = getattr(res, "cobertura_captura", None) or {}
    if cob.get("puntos"):
        r = cob["resumen"]
        s["monitoreo"].append(t("cobertura de captura: {a} puntos aptos, {l} aptos con limitaciones, {x} no aptos",
                                a=r[_cc.APTA], l=r[_cc.LIMITADA], x=r[_cc.NO_APTA]))
    for dom in ("incidentes", "riesgo"):
        s[dom].append(t(SOLO_ENTREVISTA))
    return s


def construir(res, respuestas: dict | None = None) -> dict:
    """{"dominios", "general", "con_cuestionario", "respuestas", "sin_asignar"}; textos ya traducidos al idioma
    de la corrida. `respuestas` es lo que devuelve `leer` (o None)."""
    perfil = getattr(res, "perfil", None) or {}
    esc = escala_de(perfil)
    por_dom, sin_asignar = _hallazgos(res)
    senales = _senales(res)
    con = respuestas is not None
    dominios = []
    for d in datos()["dominios"]:
        clave = d["clave"]
        objetivo, origen = _objetivo(clave, perfil, esc)
        nivel, num, na, total = _nivel(respuestas or {}, d["preguntas"]) if con else (None, 0, 0, len(d["preguntas"]))
        h = por_dom[clave]
        brecha = _redondear(max(0, objetivo - nivel)) if nivel is not None else None
        contradiccion = ""
        if nivel is not None and nivel >= esc["eq"][NIVEL_REVISION] and h["titulos_alta"]:
            contradiccion = t(REVISAR, titulos="; ".join(t(x) for x in h["titulos_alta"][:MAX_TITULOS]))
        dominios.append({
            "clave": clave, "nombre": t(d["nombre"]), "nivel": nivel,
            "estado": "medido" if nivel is not None else (INSUFICIENTE if con else "sin cuestionario"),
            "objetivo": objetivo, "origen_objetivo": t(origen), "brecha": brecha,
            "contestadas": num + na, "total": total, "na": na,
            "hallazgos": {k: h[k] for k in ("Alta", "Media", "Baja")}, "titulos_alta": list(h["titulos_alta"]),
            "senales": senales[clave], "contradiccion": contradiccion,
            "csf": "; ".join(sorted({p["csf"] for p in d["preguntas"]})),
            "iec62443": "; ".join(sorted({p["iec62443"] for p in d["preguntas"]}, key=_orden_ref))})
    con_nivel = [x for x in dominios if x["nivel"] is not None]
    general = {"dominios_con_nivel": len(con_nivel), "nivel": None, "objetivo": None, "brecha": None}
    if con_nivel:
        n = len(con_nivel)
        general.update(nivel=_redondear(sum(x["nivel"] for x in con_nivel) / n),
                       objetivo=_redondear(sum(x["objetivo"] for x in con_nivel) / n),
                       brecha=_redondear(sum(x["brecha"] for x in con_nivel) / n))
    return {"dominios": dominios, "general": general, "con_cuestionario": con, "respuestas": respuestas or {},
            "sin_asignar": sin_asignar, "escala": esc}


def _orden_ref(r: str) -> tuple:
    nums = [int(x) for x in re.findall(r"\d+", r)]
    return (0 if r.startswith("FR") else 1, nums)


# --- salidas ----------------------------------------------------------------------------------------------- #

def hay(m: dict) -> bool:
    return bool(m and m.get("dominios"))


def _num(x) -> str:
    return "" if x is None else f"{x:.1f}"


def _nivel_texto(x: dict, vacio_sin_cuestionario: str = "") -> str:
    if x["nivel"] is not None:
        return _num(x["nivel"])
    return t(INSUFICIENTE) if x["estado"] == INSUFICIENTE else vacio_sin_cuestionario


def filas_tabla(m: dict) -> list:
    out = []
    esc = _esc(m)
    for x in m["dominios"]:
        h = x["hallazgos"]
        fila = [x["nombre"], _nivel_texto(x), x["objetivo"], x["origen_objetivo"],
                _num(x["brecha"]) if x["nivel"] is not None else _nivel_texto(x), x["contestadas"], x["total"],
                h["Alta"], h["Media"], h["Baja"], " | ".join(x["senales"]), x["contradiccion"], x["csf"],
                x["iec62443"]]
        if esc["proyecto"]:
            fila += [nombre_nivel(esc, x["nivel"]), nombre_nivel(esc, x["objetivo"])]
        out.append(fila)
    return out


def filas_equivalencia(esc: dict) -> list:
    """Por nivel del proyecto: valor, nombre, descripcion y los niveles 0-4 de la herramienta que le corresponden."""
    herr = datos()["escala"]
    out = []
    for n in esc["niveles"]:
        ks = [k for k in range(5) if esc["eq"][k] == n["valor"]]
        out.append([n["valor"], n["nombre"], n.get("descripcion", ""),
                    "; ".join(f"{k} = {t(herr[str(k)])}" for k in ks) or "-"])
    return out


def tablas(m: dict) -> list:
    if not hay(m):
        return []
    esc = _esc(m)
    out = [(ARCHIVO, HOJA, COLUMNAS + (COL_NOMBRES if esc["proyecto"] else []), filas_tabla(m)),
           (ARCHIVO_CUESTIONARIO, HOJA_CUESTIONARIO, cab_cuestionario(), filas_cuestionario(m["respuestas"], esc))]
    if esc["proyecto"]:     # solo al XLSX (sin archivo CSV propio)
        out.append((None, TITULO_EQUIVALENCIA, CAB_EQUIVALENCIA, filas_equivalencia(esc)))
    return out


def _resumen(m: dict) -> str:
    g = m["general"]
    if not m["con_cuestionario"]:
        return t(SIN_CUESTIONARIO, archivo=ARCHIVO_CUESTIONARIO)
    if g["nivel"] is None:
        return t("Ningun dominio tiene suficientes respuestas para calcular su nivel. Detalle en {a}.", a=ARCHIVO)
    if _esc(m)["proyecto"]:
        return t("Promedio declarado {n} en la escala del proyecto ({lo} a {hi}) en {c} de {d} dominios "
                 "(objetivo {o}, brecha {b}). Detalle en {a}.", n=_num(g["nivel"]), lo=_esc(m)["min"],
                 hi=_esc(m)["max"], c=g["dominios_con_nivel"], d=len(m["dominios"]), o=_num(g["objetivo"]),
                 b=_num(g["brecha"]), a=ARCHIVO)
    return t("Promedio declarado {n} de 4 en {c} de {d} dominios (objetivo {o}, brecha {b}). Detalle en {a}.",
             n=_num(g["nivel"]), c=g["dominios_con_nivel"], d=len(m["dominios"]), o=_num(g["objetivo"]),
             b=_num(g["brecha"]), a=ARCHIVO)


def seccion(m: dict) -> dict:
    """Datos de la seccion de los reportes: tabla breve, avisos de revision y, con niveles, el radar."""
    cab = [t(c) for c in CAB_SECCION]
    filas, revisiones = [], []
    for x in m["dominios"]:
        h = x["hallazgos"]
        filas.append([x["nombre"], _nivel_texto(x, "-"), x["objetivo"],
                      _num(x["brecha"]) if x["nivel"] is not None else "-", f"{x['contestadas']}/{x['total']}",
                      f"{h['Alta']}/{h['Media']}/{h['Baja']}", "; ".join(x["senales"]) or "-",
                      x["contradiccion"] or "-"])
        if x["contradiccion"]:
            revisiones.append(f"{x['nombre']}: {x['contradiccion']}")
    esc = _esc(m)
    return {"titulo": t(TITULO), "nota": t(NOTA_PROYECTO if esc["proyecto"] else NOTA), "resumen": _resumen(m),
            "cab": cab, "filas": filas,
            "revisiones": revisiones, "radar": m["general"]["dominios_con_nivel"] > 0,
            "origen_objetivo": "; ".join(sorted({x["origen_objetivo"] for x in m["dominios"]})),
            "equivalencia": ({"titulo": t(TITULO_EQUIVALENCIA), "cab": [t(c) for c in CAB_EQUIVALENCIA],
                              "filas": filas_equivalencia(esc)} if esc["proyecto"] else None)}


def radar_svg(m: dict) -> str:
    """Radar de nivel actual contra objetivo, en SVG en linea sin JavaScript. Vacio sin ningun nivel."""
    import math
    from xml.sax.saxutils import escape

    doms = m["dominios"]
    if not any(x["nivel"] is not None for x in doms):
        return ""
    n, c, r = len(doms), 190, 130
    esc = _esc(m)

    def punto(i, v):
        v = (v - esc["min"]) * 4 / (esc["max"] - esc["min"])        # a la escala 0-4 del dibujo
        ang = -math.pi / 2 + 2 * math.pi * i / n
        return c + r * v / 4 * math.cos(ang), c + r * v / 4 * math.sin(ang)

    def poligono(vals):
        pts = [punto(i, v) for i, v in vals]
        return " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)

    partes = [(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {2 * c} {2 * c}" width="{2 * c}" '
               f'height="{2 * c}" role="img" aria-label="{escape(t("Madurez por dominio: nivel actual contra objetivo"))}">')]
    for k in range(1, 5):
        partes.append(f'<polygon points="{poligono([(i, esc["min"] + k * (esc["max"] - esc["min"]) / 4) for i in range(n)])}" fill="none" stroke="#c8c8c8"/>')
    for i, x in enumerate(doms):
        x2, y2 = punto(i, esc["max"])
        partes.append(f'<line x1="{c}" y1="{c}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="#c8c8c8"/>')
        lx, ly = punto(i, esc["min"] + 4.55 * (esc["max"] - esc["min"]) / 4)
        ancla = "middle" if abs(lx - c) < 8 else ("start" if lx > c else "end")
        partes.append(f'<text x="{lx:.1f}" y="{ly:.1f}" font-size="11" text-anchor="{ancla}" '
                      f'dominant-baseline="middle">{escape(x["nombre"])}</text>')
    partes.append(f'<polygon points="{poligono([(i, x["objetivo"]) for i, x in enumerate(doms)])}" '
                  'fill="none" stroke="#d9822b" stroke-width="2" stroke-dasharray="6 4"/>')
    con = [(i, x["nivel"]) for i, x in enumerate(doms) if x["nivel"] is not None]
    partes.append(f'<polygon points="{poligono(con)}" fill="#2b6cb0" fill-opacity="0.25" stroke="#2b6cb0" '
                  'stroke-width="2"/>')
    partes.append(f'<text x="8" y="14" font-size="11" fill="#2b6cb0">{escape(t("Nivel actual"))}</text>')
    partes.append(f'<text x="8" y="28" font-size="11" fill="#d9822b">{escape(t("Objetivo"))}</text>')
    partes.append("</svg>")
    return "".join(partes)


def para_json(m: dict) -> dict:
    if not hay(m):
        return {}
    esc = _esc(m)
    extra = ({"escala": {"niveles": [{"valor": n["valor"], "nombre": n["nombre"]} for n in esc["niveles"]],
                         "equivalencia": {str(k): v for k, v in sorted(esc["eq"].items())}}}
             if esc["proyecto"] else {})
    return {"con_cuestionario": m["con_cuestionario"], "general": m["general"], "sin_asignar": m["sin_asignar"],
            "nota": t(NOTA_PROYECTO if esc["proyecto"] else NOTA), **extra,
            "dominios": [{"clave": x["clave"], "nombre": x["nombre"], "estado": x["estado"], "nivel_actual": x["nivel"],
                          "nivel_objetivo": x["objetivo"], "origen_objetivo": x["origen_objetivo"],
                          "brecha": x["brecha"], "contestadas": x["contestadas"], "total": x["total"],
                          "hallazgos": x["hallazgos"], "senales": x["senales"],
                          "contradiccion": x["contradiccion"], "referencias_csf": x["csf"],
                          "referencias_62443": x["iec62443"]} for x in m["dominios"]]}
