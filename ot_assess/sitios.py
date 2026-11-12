"""Consolidado multi-sitio (M1, D94): junta las carpetas de salida de varios sitios en un libro de hojas fijas.

Lee solo los CSV publicos de cada carpeta y, de resultado.json, perfil.cliente, perfil.sitio, perfil.idioma y
entorno.ot_assess. Las hojas y columnas son siempre las mismas; un archivo ausente deja la hoja con cabecera y
sin filas de ese sitio. Es evidencia tecnica agregada: no dice si un sitio cumple o no un marco.
"""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

from . import i18n, json_entrada
from .catalog import SEV_ORDER
from .i18n import t
from .madurez import RUTA as RUTA_MADUREZ
from .report.common import celda_csv
from .report.xlsx import escribir_xlsx
from .riesgo import COLUMNAS as COL_RIESGO
from .riesgo import NIVELES

LIBRO = "consolidado_sitios.xlsx"
JSON = "consolidado_sitios.json"
USO = "interno (consolida varios sitios; no se entrega a un sitio)"
SEVS = tuple(SEV_ORDER)
ARCHIVOS = {
    "hallazgos": ("hallazgos.csv", ("id", "severidad", "categoria", "titulo")),
    "riesgos": ("riesgos.csv", ("id_riesgo", "puntuacion")),
    "madurez": ("madurez.csv", ("dominio", "nivel_actual", "nivel_objetivo")),
    "inventario": ("inventario_normalizado.csv", ()),
    "vulnerabilidades": ("vulnerabilidades_firmware.csv", ("cve",)),
    "ingenieria": ("eventos_ingenieria.csv", ()),
    "salud": ("salud_red.csv", ("mbps_p95_minuto",)),
}
COLS_RIESGO = [c for c in COL_RIESGO if c in (
    "id_riesgo", "id_hallazgo", "titulo", "categoria", "severidad", "zonas", "activos", "probabilidad", "impacto",
    "puntuacion", "nivel", "quick_win", "recomendacion")]
SI = {"si", "yes", "true", "1", "x"}



def cab_sitios(niveles=NIVELES) -> list:
    """Cabecera de la hoja Sitios; una columna riesgos_<nivel> por nivel de riesgo (RM2, D129)."""
    return (["sitio", "cliente", "carpeta", "version", "activos", "hallazgos"]
            + ["hallazgos_" + s.lower() for s in SEVS] + ["riesgos"]
            + ["riesgos_" + n.lower().replace(" ", "_") for n in niveles]
            + ["madurez_actual_promedio", "madurez_objetivo_promedio", "vulnerabilidades", "kev",
               "sesiones_ingenieria", "mbps_p95_max"])


CAB_SITIOS = cab_sitios()
CAB_COMUNES = ["id", "titulo", "categoria", "severidad_max", "sitios", "porcentaje_sitios", "lista_sitios"]
CAB_HALLAZGOS = ["sitio", "captura", "id", "severidad", "categoria", "titulo"]
CAB_RIESGOS = ["sitio"] + COLS_RIESGO
CAB_MADUREZ = ["sitio", "dominio", "nivel_actual", "nivel_objetivo", "brecha"]
CAB_INVENTARIO = ["fabricante", "modelo", "firmware", "activos", "sitios", "lista_sitios"]
CAB_VULN = ["cve", "severidad", "cvss", "kev", "fabricante", "modelo", "activos", "sitios", "lista_sitios"]
CAB_FUENTES = ["sitio", "carpeta", "version", "archivo", "sha256"]

# (archivo CSV, hoja, cabecera): el orden es el de las hojas del libro.
SALIDAS = [
    ("sitios.csv", "Sitios", CAB_SITIOS),
    ("hallazgos_comunes.csv", "Hallazgos comunes", CAB_COMUNES),
    ("hallazgos_sitios.csv", "Hallazgos por sitio", CAB_HALLAZGOS),
    ("riesgos_sitios.csv", "Riesgos", CAB_RIESGOS),
    ("madurez_sitios.csv", "Madurez", CAB_MADUREZ),
    ("inventario_sitios.csv", "Inventario", CAB_INVENTARIO),
    ("vulnerabilidades_sitios.csv", "Vulnerabilidades", CAB_VULN),
    (None, "Fuentes", CAB_FUENTES),
]


class ErrorSitios(Exception):
    pass


def _g(fila: dict, campo: str) -> str:
    return (fila.get(campo) or "").strip()


def _num(v, defecto=None):
    try:
        return float(str(v).replace(",", "").strip())
    except ValueError:
        return defecto


def _fmt(x: float) -> str:
    return f"{x:.1f}"


def _cols_usadas() -> list:
    """Columnas (en espanol) que lee `sitios`, de cualquier archivo."""
    req = {c for _a, r in ARCHIVOS.values() for c in r}
    return sorted(req | set(COLS_RIESGO) | {
        "captura", "nivel", "dominio", "nivel_actual", "nivel_objetivo", "brecha", "fabricante", "modelo",
        "firmware", "cve", "cvss", "kev", "mbps_p95_minuto"})


def _inversos() -> tuple:
    """(severidad, nivel, texto): del ingles a la clave en espanol. Texto = menor clave con esa traduccion."""
    if not _CACHE:
        cat = i18n.catalogo("en")
        texto: dict = {}
        for k in sorted(cat):
            texto.setdefault(cat[k], k)
        _CACHE.extend([{cat[s]: s for s in SEV_ORDER if s in cat}, {cat[n]: n for n in NIVELES if n in cat},
                       texto])
    return tuple(_CACHE)


_CACHE: list = []


def _a_espanol(datos: dict) -> None:
    """Devuelve a su clave en espanol los valores de una carpeta generada en ingles (por campo)."""
    sev, niv, texto = _inversos()
    por_campo = (("severidad", sev), ("nivel", niv), ("categoria", texto), ("titulo", texto),
                 ("dominio", texto))
    for clave in ("hallazgos", "riesgos", "vulnerabilidades", "madurez"):
        for f in datos[clave]:
            for campo, mapa in por_campo:
                if campo in f and f[campo] is not None:
                    v = f[campo].strip()
                    f[campo] = mapa.get(v, f[campo])


def _leer(carpeta: Path, nombre: str, requeridas: tuple):
    """-> (filas, sha256, en) o (None, motivo, False) si falta el archivo o una columna que se usa.

    Una columna que no esta pero cuya traduccion al ingles si (carpeta generada con --idioma en) se renombra a
    la clave en espanol; `en` dice si hubo que renombrar la severidad (la senal de carpeta en ingles).
    """
    p = carpeta / nombre
    if not p.is_file():
        return None, f"falta {nombre}", False
    datos = p.read_bytes()
    try:
        lector = csv.DictReader(datos.decode("utf-8-sig").splitlines(), restval="")
        filas = list(lector)
        campos = lector.fieldnames or []
    except (UnicodeDecodeError, csv.Error):
        return None, f"no se pudo leer {nombre}", False
    cat = i18n.catalogo("en")
    ren = {cat[c]: c for c in _cols_usadas() if c not in campos and cat.get(c) in campos}
    if ren:
        filas = [{ren.get(k, k): v for k, v in f.items()} for f in filas]
        campos = [ren.get(k, k) for k in campos]
    if filas or campos:
        faltan = [c for c in requeridas if c not in campos]
        if faltan:
            return None, f"a {nombre} le falta la columna {', '.join(faltan)}", False
    return filas, hashlib.sha256(datos).hexdigest(), "severidad" in ren.values()


def _meta(carpeta: Path) -> dict:
    try:
        j = json_entrada.cargar((carpeta / "resultado.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        j = {}
    p = j.get("perfil") if isinstance(j.get("perfil"), dict) else {}
    e = j.get("entorno") if isinstance(j.get("entorno"), dict) else {}
    return {"cliente": str(p.get("cliente") or ""), "sitio": str(p.get("sitio") or ""),
            "idioma": str(p.get("idioma") or ""), "version": str(e.get("ot_assess") or ""),
            "niveles": _niveles_json(j)}


def _niveles_json(j: dict) -> tuple:
    """Nombres de los niveles de riesgo del metodo del proyecto (RM2, D129) en resultado.json; () si no hay."""
    r = j.get("riesgos") if isinstance(j.get("riesgos"), dict) else {}
    m = r.get("metodo") if isinstance(r.get("metodo"), dict) else {}
    n = m.get("niveles") if isinstance(m.get("niveles"), list) else []
    return tuple(str(x["nombre"]) for x in n if isinstance(x, dict) and x.get("nombre"))


def _dominios() -> list:
    try:
        d = json.loads(RUTA_MADUREZ.read_text(encoding="utf-8"))
        return [x["nombre"] for x in d["dominios"]]
    except (OSError, ValueError, KeyError, TypeError):
        return []


def _lista(nombres) -> str:
    return "; ".join(nombres)


def leer_sitios(carpetas: list, nombres: dict) -> tuple:
    """-> (sitios, avisos). `nombres` = {carpeta resuelta: nombre} que manda sobre el perfil."""
    sitios, avisos, vistos = [], [], {}
    for c in carpetas:
        c = Path(c).expanduser()
        if not c.is_dir():
            raise ErrorSitios(f"'{c}' no es una carpeta")
        m = _meta(c)
        nombre = nombres.get(c.resolve()) or m["sitio"] or c.name
        if nombre in vistos:
            raise ErrorSitios(f"El nombre de sitio '{nombre}' se repite ({vistos[nombre]} y {c.name}). "
                              f"Distinguelos con --nombre CARPETA=NOMBRE.")
        vistos[nombre] = c.name
        datos, fuentes, en = {}, [], False
        for clave, (arch, req) in ARCHIVOS.items():
            filas, extra, ingles = _leer(c, arch, req)
            if filas is None:
                avisos.append(f"sitio {nombre}: {extra}")
                datos[clave] = []
            else:
                datos[clave] = filas
                fuentes.append({"archivo": arch, "sha256": extra})
                en = en or (clave == "hallazgos" and ingles)
        # Idioma de la carpeta: cabeceras de hallazgos.csv, si no el perfil, si no es.
        idioma = "en" if en else (m["idioma"] if m["idioma"] in i18n.IDIOMAS else "es")
        if idioma == "en":
            _a_espanol(datos)
        sitios.append({"sitio": nombre, "carpeta": c.name, "datos": datos, "fuentes": fuentes,
                       "cliente": m["cliente"], "version": m["version"], "idioma": idioma,
                       "niveles": m["niveles"] or NIVELES})
    clientes = sorted({s["cliente"] for s in sitios if s["cliente"]})
    if len(clientes) > 1:
        avisos.append("las carpetas traen clientes distintos: " + "; ".join(clientes))
    versiones = sorted({s["version"] for s in sitios if s["version"]})
    if len(versiones) > 1:
        avisos.append("las carpetas se generaron con versiones distintas de la herramienta: " + "; ".join(versiones))
    if len({s["niveles"] for s in sitios}) > 1:
        avisos.append("las carpetas usan niveles de riesgo distintos (metodo del proyecto en el perfil): el "
                      "consolidado cuenta cada nivel en su propia columna")
    idiomas = sorted({s["idioma"] for s in sitios})
    if len(idiomas) > 1:
        avisos.append("las carpetas estan en idiomas distintos (" + ", ".join(idiomas) + "): se normalizaron "
                      "al idioma del consolidado (los titulos sin traduccion exacta quedan como vienen)")
    return sitios, avisos


def _sev_max(sevs) -> str:
    return min(sevs, key=lambda s: (SEV_ORDER.get(s, 9), s))


def niveles_riesgo(sitios: list) -> list:
    """Niveles de riesgo del consolidado: los de cada sitio en orden y sin repetir (los cuatro por defecto o los
    del metodo del proyecto, RM2) y al final cualquier otro valor de 'nivel' que traiga riesgos.csv."""
    out: list = []
    for s in sitios:
        out += [n for n in s.get("niveles") or NIVELES if n not in out]
    for s in sitios:
        for x in s["datos"]["riesgos"]:
            n = _g(x, "nivel")
            if n and n not in out:
                out.append(n)
    return out


def _tablas(sitios: list) -> dict:
    nombres = [s["sitio"] for s in sitios]
    niveles = niveles_riesgo(sitios)
    n = len(sitios)
    # Sitios
    filas_sitios = []
    for s in sitios:
        d = s["datos"]
        # Un hallazgo por id con su severidad mas alta: un sitio con varios puntos de captura no cuenta
        # el mismo hallazgo una vez por captura.
        por_h: dict = {}
        for x in d["hallazgos"]:
            por_h.setdefault(_g(x, "id"), []).append(_g(x, "severidad"))
        h = [_sev_max(v) for _i, v in sorted(por_h.items())]
        r = [_g(x, "nivel") for x in d["riesgos"]]
        act = [_num(_g(x, "nivel_actual")) for x in d["madurez"]]
        obj = [_num(_g(x, "nivel_objetivo")) for x in d["madurez"]]
        act, obj = [x for x in act if x is not None], [x for x in obj if x is not None]
        p95 = [x for x in (_num(_g(f, "mbps_p95_minuto")) for f in d["salud"]) if x is not None]
        filas_sitios.append(
            [s["sitio"], s["cliente"], s["carpeta"], s["version"], len(d["inventario"]), len(h)]
            + [h.count(v) for v in SEVS] + [len(d["riesgos"])] + [r.count(v) for v in niveles]
            + [_fmt(sum(act) / len(act)) if act else "", _fmt(sum(obj) / len(obj)) if obj else "",
               len(d["vulnerabilidades"]), sum(1 for x in d["vulnerabilidades"] if _g(x, "kev").lower() in SI),
               len(d["ingenieria"]), _fmt(max(p95)) if p95 else ""])
    # Hallazgos
    largo, por_id = [], {}
    for s in sitios:
        for x in s["datos"]["hallazgos"]:
            largo.append([s["sitio"], _g(x, "captura"), _g(x, "id"), _g(x, "severidad"), _g(x, "categoria"),
                          _g(x, "titulo")])
            por_id.setdefault(_g(x, "id"), []).append((s["sitio"], x))
    comunes = []
    for i, lst in por_id.items():
        ss = [a for a, _ in lst]
        sitios_i = [nm for nm in nombres if nm in ss]
        primero = lst[0][1]
        comunes.append([i, _g(primero, "titulo"), _g(primero, "categoria"),
                        _sev_max([_g(x, "severidad") for _, x in lst]), len(sitios_i),
                        f"{round(100 * len(sitios_i) / n)}%", _lista(sitios_i)])
    comunes.sort(key=lambda f: (-f[4], SEV_ORDER.get(f[3], 9), f[0]))
    # Riesgos
    riesgos = []
    for s in sitios:
        for x in s["datos"]["riesgos"]:
            riesgos.append([s["sitio"]] + [_g(x, c) for c in COLS_RIESGO])
    ip = CAB_RIESGOS.index("puntuacion")
    ii = CAB_RIESGOS.index("id_riesgo")
    riesgos.sort(key=lambda f: (-(_num(f[ip], 0.0)), f[0], f[ii]))
    # Madurez
    orden = _dominios()
    vistos = {}
    for s in sitios:
        for x in s["datos"]["madurez"]:
            vistos.setdefault(_g(x, "dominio"), None)
    doms = orden + [d for d in vistos if d not in orden]
    mad = []
    for s in sitios:
        por = {_g(x, "dominio"): x for x in s["datos"]["madurez"]}
        for d in doms:
            if d in por:
                x = por[d]
                mad.append([s["sitio"], d, _g(x, "nivel_actual"), _g(x, "nivel_objetivo"), _g(x, "brecha")])
    mad.sort(key=lambda f: (nombres.index(f[0]), doms.index(f[1])))
    for d in doms:
        def prom(col, d=d):
            v = [_num(f[col]) for f in mad if f[1] == d]
            v = [x for x in v if x is not None]
            return _fmt(sum(v) / len(v)) if v else ""
        if any(f[1] == d for f in mad):
            mad.append(["Promedio", d, prom(2), prom(3), prom(4)])
    # Inventario
    inv: dict = {}
    for s in sitios:
        for x in s["datos"]["inventario"]:
            k = (_g(x, "fabricante"), _g(x, "modelo"), _g(x, "firmware"))
            e = inv.setdefault(k, [0, []])
            e[0] += 1
            if s["sitio"] not in e[1]:
                e[1].append(s["sitio"])
    inventario = [[*k, e[0], len(e[1]), _lista(e[1])] for k, e in inv.items()]
    inventario.sort(key=lambda f: (-f[3], f[0], f[1], f[2]))
    # Vulnerabilidades
    vul: dict = {}
    for s in sitios:
        for x in s["datos"]["vulnerabilidades"]:
            k = (_g(x, "cve"), _g(x, "severidad"), _g(x, "cvss"), "si" if _g(x, "kev").lower() in SI else "no",
                 _g(x, "fabricante"), _g(x, "modelo"))
            e = vul.setdefault(k, [0, []])
            e[0] += 1
            if s["sitio"] not in e[1]:
                e[1].append(s["sitio"])
    vulns = [[*k, e[0], len(e[1]), _lista(e[1])] for k, e in vul.items()]
    vulns.sort(key=lambda f: (f[3] != "si", -(_num(f[2], 0.0)), f[0], f[4], f[5]))
    fuentes = [[s["sitio"], s["carpeta"], s["version"], f["archivo"], f["sha256"]]
               for s in sitios for f in s["fuentes"]]
    return {"Sitios": filas_sitios, "Hallazgos comunes": comunes, "Hallazgos por sitio": largo,
            "Riesgos": riesgos, "Madurez": mad, "Inventario": inventario, "Vulnerabilidades": vulns,
            "Fuentes": fuentes}


def consolidar(carpetas: list, nombres: dict | None = None) -> dict:
    sitios, avisos = leer_sitios(carpetas, nombres or {})
    return {"sitios": sitios, "avisos": avisos, "tablas": _tablas(sitios), "niveles": niveles_riesgo(sitios)}


def idioma_defecto(r: dict) -> str:
    primero = r["sitios"][0]["idioma"] if r["sitios"] else ""
    return primero if primero in i18n.IDIOMAS else "es"


# Columnas cuyos valores son textos de la herramienta (claves en espanol): salen en el idioma del consolidado.
TRADUCIR = {"severidad", "severidad_max", "nivel", "categoria", "titulo", "dominio", "kev", "quick_win"}


def _valores(filas: list, cab: list) -> list:
    """En ingles, los valores de TRADUCIR por el catalogo (exacto; si no esta, como vienen) y la fila Promedio.
    En espanol, sin cambio."""
    if i18n.idioma() == "es":
        return filas
    cat = i18n.catalogo(i18n.idioma())
    cols = {i for i, c in enumerate(cab) if c in TRADUCIR}
    isit = cab.index("sitio") if "sitio" in cab else -1
    return [[cat.get(v, v) if i in cols and isinstance(v, str)
             else str(t("Promedio")) if i == isit and v == "Promedio" else v for i, v in enumerate(f)]
            for f in filas]


def escribir(out: Path, r: dict, idioma: str | None = None) -> list:
    """Escribe los CSV, el libro y el json en `out`; devuelve los nombres de archivo."""
    anterior = i18n.idioma()
    i18n.usar(idioma or idioma_defecto(r))
    try:
        out.mkdir(parents=True, exist_ok=True)
        archivos, hojas = [], []
        for arch, hoja, cab in SALIDAS:
            if hoja == "Sitios":
                cab = cab_sitios(r.get("niveles") or NIVELES)
            cabecera = [str(t(c)) for c in cab]
            filas = [[celda_csv(c) for c in f] for f in _valores(r["tablas"][hoja], cab)]
            if arch:
                with open(out / arch, "w", newline="", encoding="utf-8-sig") as fh:
                    w = csv.writer(fh)
                    w.writerow(cabecera)
                    w.writerows(filas)
                archivos.append(arch)
            hojas.append((str(t(hoja)), cabecera, filas))
        escribir_xlsx(out / LIBRO, hojas)
        js = {"uso": str(t(USO)), "avisos": r["avisos"],
              "sitios": [{k: s[k] for k in ("sitio", "cliente", "carpeta", "version")} for s in r["sitios"]],
              "fuentes": [dict(zip(CAB_FUENTES, f)) for f in r["tablas"]["Fuentes"]]}
        (out / JSON).write_text(json.dumps(js, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        return archivos + [LIBRO, JSON]
    finally:
        i18n.usar(anterior)
