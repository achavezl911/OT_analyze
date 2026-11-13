"""I1b (D79): reporte de obsolescencia por activo (fin de soporte por fabricante, modelo, firmware y SO).

Sin red. Dos fuentes de fechas: la tabla del analista (`--fin-de-soporte`, CSV o XLSX) y una tabla minima
integrada de sistemas operativos (`data/fin_soporte_so.json`). La del analista manda. Trabaja sobre el inventario
normalizado de I1a (D78): un renglon por activo y producto que case. Nunca dice cumple / no cumple.
"""
from __future__ import annotations

import datetime
import json
import re
from pathlib import Path

from .i18n import t, unir
from .importers import perfiles as pf
from .importers.lector import leer_tabla
from .inventario_normalizado import _CRITICIDAD
from .model import Capture
from .rules.base import finding

F_VENCIDO, F_PRONTO, F_VIGENTE = "fuera de soporte", "fin de soporte en 12 meses o menos", "con soporte"
F_SIN_DATO, F_SIN_VERSION = "sin dato de soporte", "sin datos de version"
F_VENTA = "fin de venta (con soporte)"          # OBS2 (D135): solo con la clave de perfil fin_de_venta
ESTADOS = (F_VENCIDO, F_PRONTO, F_VIGENTE, F_SIN_DATO, F_SIN_VERSION)
MESES = 12
_RE_PRONTO = re.compile(r"^fin de soporte en (\d+) meses o menos$")
TIT_FUERA = "Software o sistema operativo fuera de soporte"
TIT_FUERA_REP = "Activos fuera de soporte segun el reporte de obsolescencia"
TIT_VENTA = "Equipos en fin de venta con soporte vigente"
TIT_PROXIMO = "Equipos con fin de soporte en los proximos 12 meses"
ARCHIVO, HOJA = "obsolescencia.csv", "Obsolescencia"
TITULO = "Obsolescencia de activos"
NOTA = ("Fin de soporte por activo segun la tabla del analista (--fin-de-soporte) y una tabla minima integrada de "
        "sistemas operativos Microsoft cuyas fechas aporto el propietario del proyecto (no verificadas contra el "
        "fabricante por la herramienta). La tabla del analista manda sobre la integrada. Un producto sin fila no "
        "esta 'con soporte': esta 'sin dato de soporte'. Es evidencia tecnica, no un dictamen de cumplimiento. "
        "Las columnas de validacion estan vacias a proposito.")
COLUMNAS = ["id", "nombre", "ips", "zona", "criticidad", "fabricante", "fabricante_fuente", "modelo",
            "modelo_fuente", "firmware", "firmware_fuente", "sistema_operativo", "sistema_operativo_fuente",
            "producto_casado", "fecha_referencia", "fecha_fin_soporte", "dias", "estado", "reemplazo_sugerido",
            "fuente_del_dato", "validado_por", "fecha_validacion", "comentario"]
ALIAS = {
    "fabricante": ["fabricante", "vendor", "manufacturer", "marca"],
    "producto": ["producto", "product", "modelo", "model"],
    "version": ["version", "firmware", "firmware_version", "version_firmware"],
    "fecha_fin_soporte": ["fecha_fin_soporte", "fin_de_soporte", "fin_soporte", "end_of_support", "eos", "eol",
                          "end_of_life", "fecha_eos", "fecha_eol"],
    "fecha_fin_venta": ["fecha_fin_venta", "fin_de_venta", "fin_venta", "end_of_sale", "eosale"],
    "reemplazo_sugerido": ["reemplazo_sugerido", "reemplazo", "replacement", "suggested_replacement"],
    "fuente": ["fuente", "source", "referencia", "url"],
}
SUFIJOS = {"INC", "CORP", "CORPORATION", "AG", "GMBH", "LTD", "LLC", "SA", "CO", "SE", "LIMITED", "COMPANY"}
_RE_VER = re.compile(r"\d+(?:\.\d+)*")
_RE_COND = re.compile(r"^(<=|>=|<|>|=)\s*v?(\d+(?:\.\d+)*)$", re.IGNORECASE)
_DIR_DATOS = Path(__file__).parent / "data"
_ORDEN = {"critica": 0, "alta": 1, "media": 2, "baja": 3}


# ---------------------------------------------------------------------------
# Tablas de fin de soporte

def _fecha(texto):
    try:
        return datetime.date.fromisoformat(str(texto).strip())
    except ValueError:
        return None


def _tupla(texto):
    m = _RE_VER.search(str(texto or ""))
    return tuple(int(x) for x in m.group(0).split(".")) if m else None


def _cmp(a: tuple, b: tuple) -> int:
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def _regla_version(texto: str):
    """Funcion version -> True/False/None (None: no se puede evaluar), o None si el texto es invalido."""
    s = str(texto or "").strip()
    if not s:
        return lambda v: True
    if s[0] in "<>=":
        conds = []
        for parte in s.split(","):
            m = _RE_COND.match(parte.strip())
            if not m:
                return None
            conds.append((m.group(1), tuple(int(x) for x in m.group(2).split("."))))

        def rango(v):
            tv = _tupla(v)
            if tv is None:
                return None
            ok = {"<": lambda c: c < 0, "<=": lambda c: c <= 0, ">": lambda c: c > 0, ">=": lambda c: c >= 0,
                  "=": lambda c: c == 0}
            return all(ok[op](_cmp(tv, ref)) for op, ref in conds)
        return rango
    base = s.lower().lstrip("v")
    if base.endswith("."):
        return lambda v: None if not str(v or "").strip() else (
            str(v).strip().lower().lstrip("v") + ".").startswith(base)
    return lambda v: None if not str(v or "").strip() else str(v).strip().lower().lstrip("v") == base


def _fila_tabla(fab, producto, version, fin, venta, reemplazo, fuente, excluir="", nota=""):
    return {"fabricante": fab, "producto": producto, "version": version, "fin": fin, "venta": venta,
            "reemplazo": reemplazo, "fuente": fuente, "excluir": excluir, "nota": nota,
            "regla": _regla_version(version)}


def cargar_analista(path) -> tuple:
    """(filas, avisos) del archivo del analista. Una fila invalida se avisa con su numero y se omite."""
    filas = leer_tabla(path)
    m = pf.mapear(list(dict.fromkeys(k for f in filas for k in f)), ALIAS) if filas else {}
    faltan = [c for c in ("producto", "fecha_fin_soporte") if c not in m]
    if filas and faltan:
        raise SystemExit(f"[!] --fin-de-soporte: no se reconocio la columna {', '.join(faltan)}. "
                         f"Encabezados validos: {', '.join(ALIAS['producto'] + ALIAS['fecha_fin_soporte'])}.")

    def v(f, c):
        return str(f.get(m[c]) or "").strip() if c in m else ""
    out, avisos = [], []
    for n, f in enumerate(filas, 2):                 # la fila 1 es el encabezado
        fin, venta, ver = _fecha(v(f, "fecha_fin_soporte")), v(f, "fecha_fin_venta"), v(f, "version")
        if not v(f, "producto"):
            avisos.append(t("--fin-de-soporte fila {n}: sin producto, se omite.", n=n))
        elif fin is None:
            avisos.append(t("--fin-de-soporte fila {n}: fecha_fin_soporte invalida ('{x}', use AAAA-MM-DD), se "
                            "omite.", n=n, x=v(f, "fecha_fin_soporte")))
        elif venta and _fecha(venta) is None:
            avisos.append(t("--fin-de-soporte fila {n}: fecha_fin_venta invalida ('{x}'), se omite.", n=n, x=venta))
        elif _regla_version(ver) is None:
            avisos.append(t("--fin-de-soporte fila {n}: version invalida ('{x}'; use texto exacto, prefijo '2.' o "
                            "rango '<3.1' / '>=2.0,<2.4'), se omite.", n=n, x=ver))
        else:
            out.append(_fila_tabla(v(f, "fabricante"), v(f, "producto"), ver, fin, venta, v(f, "reemplazo_sugerido"),
                                   v(f, "fuente") or "tabla del analista"))
    return out, avisos


def integrada() -> list:
    d = json.loads((_DIR_DATOS / "fin_soporte_so.json").read_text(encoding="utf-8"))
    return [_fila_tabla(d["fabricante"], x["producto"], "", _fecha(x["fecha_fin_soporte"]) if x["fecha_fin_soporte"]
                        else None, "", "", d["fuente"], x.get("excluir", ""), x.get("nota", ""))
            for x in d["filas"]]


# ---------------------------------------------------------------------------
# Casamiento

def _fab(texto: str) -> list:
    return [w for w in re.sub(r"[^A-Z0-9 ]+", " ", str(texto or "").upper()).split() if w not in SUFIJOS]


def _fab_casa(fila: str, activo: str) -> bool:
    a, b = _fab(fila), _fab(activo)
    if not a:
        return True
    return bool(b) and (b[:len(a)] == a or a[:len(b)] == b)


def _busca(patron: str, texto: str):
    try:
        return re.search(patron, texto, re.IGNORECASE)
    except re.error:
        return re.search(re.escape(patron), texto, re.IGNORECASE)


def _candidatas(filas: list, texto: str, version: str, fabricante: str, por_so: bool) -> list:
    """[(fila, evaluacion)] de las filas cuyo producto casa; evaluacion True/False/None (version desconocida)."""
    out = []
    for f in filas:
        m = _busca(f["producto"], texto)
        if not m or (f["excluir"] and _busca(f["excluir"], texto)):
            continue
        if not por_so and not _fab_casa(f["fabricante"], fabricante):
            continue
        ver = (texto[:m.start()] + " " + texto[m.end():]) if por_so else version
        out.append((f, f["regla"](ver)))
    return out


def _mejor(cands: list):
    """La fila mas especifica (producto mas largo); a igualdad, la primera del archivo."""
    return max(cands, key=lambda c: len(c[0]["producto"]), default=None)


def _en_un_ano(d: datetime.date) -> datetime.date:
    try:
        return d.replace(year=d.year + 1)
    except ValueError:                      # 29 de febrero
        return d.replace(year=d.year + 1, day=28)


def _mas_meses(d: datetime.date, n: int) -> datetime.date:
    """`d` mas `n` meses; si el dia no existe en el mes destino, el ultimo dia de ese mes (29 de febrero)."""
    m = d.month - 1 + n
    y, mes = d.year + m // 12, m % 12 + 1
    sig = datetime.date(y + mes // 12, mes % 12 + 1, 1)
    return d.replace(year=y, month=mes, day=min(d.day, (sig - datetime.timedelta(days=1)).day))


def _estado(fin, ref, meses=MESES, venta="", con_venta=False):
    if fin is None:
        return F_SIN_DATO, ""
    dias = (fin - ref).days
    if fin < ref:
        return F_VENCIDO, dias
    if fin <= (_en_un_ano(ref) if meses == MESES else _mas_meses(ref, meses)):
        return F_PRONTO, dias
    if con_venta:
        v = _fecha(venta)
        if v is not None and v < ref:
            return F_VENTA, dias
    return F_VIGENTE, dias


def _txt_pronto(meses: int) -> str:
    return F_PRONTO if meses == MESES else f"fin de soporte en {meses} meses o menos"


def _tit_proximo(meses: int) -> str:
    return TIT_PROXIMO if meses == MESES else f"Equipos con fin de soporte en los proximos {meses} meses"


def _t_estado(e: str) -> str:
    m = _RE_PRONTO.match(e)
    if m and int(m.group(1)) != MESES:
        return t("fin de soporte en {n} meses o menos", n=m.group(1))
    return t(e)


def validar(d, fallo, objeto) -> dict:
    """Clave de perfil `obsolescencia` (OBS2, D135): meses_proximo, fin_de_venta y clases."""
    d = objeto(d, "obsolescencia", ("meses_proximo", "fin_de_venta", "clases"))
    out: dict = {}
    if "meses_proximo" in d:
        m = d["meses_proximo"]
        if not isinstance(m, int) or isinstance(m, bool) or not 1 <= m <= 60:
            fallo("'obsolescencia.meses_proximo' debe ser un entero de 1 a 60.")
        out["meses_proximo"] = m
    if "fin_de_venta" in d:
        if not isinstance(d["fin_de_venta"], bool):
            fallo("'obsolescencia.fin_de_venta' debe ser true o false.")
        out["fin_de_venta"] = d["fin_de_venta"]
    if "clases" in d:
        c = d["clases"]
        if not isinstance(c, dict):
            fallo("'obsolescencia.clases' debe ser un objeto estado -> etiqueta.")
        validos = (*ESTADOS, F_VENTA) if out.get("fin_de_venta") else ESTADOS
        out["clases"] = {}
        for k, v in c.items():
            if k not in validos:
                fallo(f"obsolescencia.clases: estado desconocido '{k}' (validos: {', '.join(validos)}).")
            if not isinstance(v, str) or not 1 <= len(v.strip()) <= 40:
                fallo(f"obsolescencia.clases.{k}: la etiqueta debe ser un texto de 1 a 40 caracteres.")
            out["clases"][k] = v.strip()
    return out


def construir(inv: dict, analista=(), referencia=None, origen_ref: str = "", config=None) -> dict:
    """Reporte de obsolescencia sobre el inventario normalizado `inv` (I1a). `referencia`: fecha de corte."""
    ref = referencia or datetime.date.today()
    cfg = config
    meses = (cfg or {}).get("meses_proximo", MESES)
    con_venta = bool((cfg or {}).get("fin_de_venta"))
    clases = (cfg or {}).get("clases", {})
    pronto = _txt_pronto(meses)
    origen_ref = origen_ref or "fecha de la corrida"
    base, filas = integrada(), []
    for fila in (inv or {}).get("filas", ()):
        c = fila["campos"]

        def val(k, c=c):
            return c[k]["valor"] if k in c else ""

        def fte(k, c=c):
            return c[k]["fuente"] if k in c else ""
        modelo, fw, so, fab = val("modelo"), val("firmware"), val("sistema_operativo"), val("fabricante")
        casos = []                     # (etiqueta del producto, fila de tabla, evaluacion)
        for texto, version, por_so in ((modelo, fw, False), (so, "", True)):
            if not texto:
                continue
            mej = _mejor(_candidatas(analista, texto, version, fab, por_so))
            if mej is None and por_so:
                mej = _mejor(_candidatas(base, texto, version, fab, True))
            if mej is not None:
                casos.append((texto, *mej))
        ver_conocida = bool(fw or so)
        comunes = [fila["id"], val("nombre"), val("ips"), val("zona"), val("criticidad"), fab, fte("fabricante"),
                   modelo, fte("modelo"), fw, fte("firmware"), so, fte("sistema_operativo")]
        salidas = []
        for texto, f, ev in casos:
            if ev is False:
                continue                                  # la version del activo queda fuera de la fila
            if ev is None:
                salidas.append((texto, "", "", F_SIN_VERSION, "", "", f["fuente"], ""))
                continue
            est, dias = _estado(f["fin"], ref, meses, f["venta"], con_venta)
            if est == F_PRONTO:
                est = pronto
            fuente = f["fuente"] + (f" ({f['nota']})" if f["nota"] else "")
            salidas.append((texto, f["fin"].isoformat() if f["fin"] else "", dias, est, f["reemplazo"], "", fuente,
                            f["venta"]))
        if not salidas:
            salidas.append(("", "", "", F_SIN_DATO if ver_conocida else F_SIN_VERSION, "", "", "", ""))
        for prod, fin, dias, est, reemplazo, _x, fuente, venta in salidas:
            extra = [] if cfg is None else [clases.get(_canon(est), est)] + ([venta] if con_venta else [])
            filas.append({"id": fila["id"], "celdas": comunes + [prod, ref.isoformat(), fin, dias, est, reemplazo,
                                                                  fuente, "", "", ""] + extra,
                          "estado": est, "dias": dias if isinstance(dias, int) else None,
                          "zona": val("zona"), "criticidad": val("criticidad"), "purdue": val("nivel_purdue"),
                          "nombre": val("nombre") or val("ips"), "ips": [i for i in val("ips").split(";") if i],
                          "producto": prod, "fin": fin, "fuente": fuente, "venta": venta})
    estados = [pronto if e == F_PRONTO else e for e in ESTADOS]
    if con_venta:
        estados.insert(3, F_VENTA)
    cuenta = {e: sum(1 for f in filas if f["estado"] == e) for e in estados}
    resumen = {"filas": len(filas), "activos": len({f["id"] for f in filas}), "por_estado": cuenta,
               "referencia": ref.isoformat(), "referencia_origen": origen_ref, "filas_analista": len(analista)}
    rep = {"filas": filas, "referencia": ref.isoformat(), "referencia_origen": origen_ref, "resumen": resumen}
    if cfg is not None:
        por_clase: dict = {}
        for e, n in cuenta.items():
            por_clase[clases.get(_canon(e), e)] = por_clase.get(clases.get(_canon(e), e), 0) + n
        resumen["meses_proximo"], resumen["clases"] = meses, por_clase
        rep["config"] = {"meses_proximo": meses, "fin_de_venta": con_venta, "propias": sorted(set(clases.values()))}
    return rep


def _canon(estado: str) -> str:
    """Nombre del estado en la herramienta (con 12 meses) para buscarlo en las clases del proyecto."""
    return F_PRONTO if _RE_PRONTO.match(estado) else estado


def referencia_de(caps=(), periodo_hasta: str = "") -> tuple:
    """(fecha, origen): fin del periodo observado si se conoce; si no, la fecha de la corrida."""
    fin = max((c.ventana[1] for c in caps if getattr(c, "ventana", None) and len(c.ventana) > 1), default=0)
    if fin:
        return datetime.datetime.fromtimestamp(fin, datetime.timezone.utc).date(), "fin de la captura"
    d = _fecha(str(periodo_hasta)[:10]) if periodo_hasta else None
    if d:
        return d, "fin del periodo de la exportacion"
    return datetime.date.today(), "fecha de la corrida"


# ---------------------------------------------------------------------------
# Salidas

def hay(rep: dict) -> bool:
    return bool(rep and rep.get("filas"))


def tablas(rep: dict) -> list:
    if not hay(rep):
        return []
    filas = [[_t_estado(x) if i == COLUMNAS.index("estado") else x for i, x in enumerate(f["celdas"])]
             for f in rep["filas"]]
    cols = COLUMNAS
    if "config" in rep:
        cols = COLUMNAS + ["clase_proyecto"] + (["fecha_fin_venta"] if rep["config"]["fin_de_venta"] else [])
    return [(ARCHIVO, HOJA, cols, filas)]


def _crit(valor: str) -> str:
    return _CRITICIDAD.get(str(valor or "").strip().lower(), "")


def _orden_crit(f: dict) -> int:
    return _ORDEN.get(_crit(f["criticidad"]), 9)


def seccion(rep: dict) -> dict:
    por = rep["resumen"]["por_estado"]
    filas = [[t("estado"), _t_estado(e), n] for e, n in por.items()]
    if "config" in rep:
        propias = rep["config"]["propias"]
        filas += [[t("clase del proyecto"), e if e in propias else _t_estado(e), n]
                  for e, n in rep["resumen"]["clases"].items()]
    zonas: dict = {}
    for f in rep["filas"]:
        if f["estado"] == F_VENCIDO:
            z = f["zona"] or t("sin zona")
            zonas[z] = zonas.get(z, 0) + 1
    filas += [[t("zona (fuera de soporte)"), z, n] for z, n in sorted(zonas.items())]
    vencidos = sorted((f for f in rep["filas"] if f["estado"] == F_VENCIDO),
                      key=lambda f: (_orden_crit(f), f["fin"], f["id"]))[:10]
    filas += [[t("mayor criticidad fuera de soporte"), f"{f['nombre']} - {f['producto']}",
               f"{f['criticidad'] or t('sin criticidad')}; {f['fin']}"] for f in vencidos]
    resumen = t("{n} activos evaluados con fecha de referencia {ref} ({origen}). Detalle en {a}.",
                n=rep["resumen"]["activos"], ref=rep["referencia"], origen=t(rep["referencia_origen"]), a=ARCHIVO)
    return {"titulo": t(TITULO), "nota": t(NOTA), "resumen": resumen,
            "tabla": ([t("categoria"), t("elemento"), t("detalle")], filas)}


# ---------------------------------------------------------------------------
# Hallazgos

def _alta(f: dict) -> bool:
    niveles = [int(x) for x in re.findall(r"\d", f["purdue"] or "")]
    return _crit(f["criticidad"]) in ("alta", "critica") or (bool(niveles) and min(niveles) <= 2)


def _lineas(filas: list) -> list:
    return [t("- {activo} ({ips}): {prod} - fin de soporte {fin} ({dias} dias) | fuente: {fuente}",
              activo=f["nombre"], ips=";".join(f["ips"]), prod=f["producto"], fin=f["fin"], dias=f["dias"],
              fuente=f["fuente"] or t("tabla del analista")) for f in filas]


def _lineas_venta(filas: list) -> list:
    return [t("- {activo} ({ips}): {prod} - fin de venta {venta}; fin de soporte {fin} | fuente: {fuente}",
              activo=f["nombre"], ips=";".join(f["ips"]), prod=f["producto"], venta=f["venta"], fin=f["fin"],
              fuente=f["fuente"] or t("tabla del analista")) for f in filas]


def agregar_hallazgos(hallazgos: list, rep: dict):
    """`hallazgos`: dicts de hallazgo ya generados (se modifican). Devuelve un Capture extra con los nuevos o None."""
    if not hay(rep):
        return None
    vencidos = [f for f in rep["filas"] if f["estado"] == F_VENCIDO]
    meses = (rep.get("config") or {}).get("meses_proximo", MESES)
    pronto = [f for f in rep["filas"] if f["estado"] == _txt_pronto(meses)]
    venta = [f for f in rep["filas"] if f["estado"] == F_VENTA]
    ref = t("Segun el reporte de obsolescencia (fecha de referencia {ref}):", ref=rep["referencia"])
    extra = Capture(Path("reporte de obsolescencia"))
    if vencidos:
        ips = [i for f in vencidos for i in f["ips"]]
        previo = next((h for h in hallazgos if h["titulo"].startswith(TIT_FUERA)), None)
        if previo is not None:
            previo["evidencia"] = unir("\n", [previo["evidencia"], ref, *_lineas(vencidos)])
            previo["activos"] = sorted(set(previo.get("activos") or ()) | set(ips))
            if any(_alta(f) for f in vencidos):
                previo["severidad"] = "Alta"
        else:
            finding(extra, "Alta" if any(_alta(f) for f in vencidos) else "Media", TIT_FUERA_REP,
                    unir("\n", [ref, *_lineas(vencidos)]),
                    "Un sistema sin soporte no recibe parches del fabricante. La fecha y la fuente salen de la "
                    "tabla de fin de soporte; el reporte de obsolescencia lista cada activo.",
                    "Levantar plan de reemplazo o compensar con aislamiento de red y control de acceso estricto "
                    "mientras se reemplaza.", categoria="Obsolescencia", activos=ips)
    if pronto:
        finding(extra, "Baja", _tit_proximo(meses), unir("\n", [ref, *_lineas(pronto)]),
                "Planear el reemplazo con anticipacion evita llegar a la fecha sin presupuesto ni ventana de "
                "parada acordada con operacion.",
                "Incluir estos equipos en el plan de reemplazo y pedir al fabricante la ruta de migracion y los "
                "tiempos de entrega.", categoria="Obsolescencia", activos=[i for f in pronto for i in f["ips"]])
    if venta:
        finding(extra, "Baja", TIT_VENTA, unir("\n", [ref, *_lineas_venta(venta)]),
                "Un equipo descontinuado por el fabricante sigue con soporte, pero ya no se puede comprar como "
                "repuesto ni ampliar; conviene tener repuestos y un plan de reemplazo antes del fin de soporte.",
                "Incluir estos equipos en el plan de reemplazo y asegurar repuestos hasta la fecha de fin de "
                "soporte.", categoria="Obsolescencia", activos=[i for f in venta for i in f["ips"]])
    return extra if extra.findings else None
