"""MANIF1 (D139): manifiesto por conjunto de datos (dataset) y plan de captura contra lo capturado.

Con la clave de perfil `manifiesto` junta en una tabla lo que la herramienta ya mide (C1 por punto: ventana, huecos,
perdida TCP; entorno: SHA-256 de cada archivo crudo) con lo que el analista declara (sitio de una lista cerrada, sensor,
punto de captura, fuentes espejadas, segmentos que el punto no ve, perdidas del SPAN o del agregador). Un dataset es un
punto de captura (modo captura) o un lote de exportes de una plataforma (modo diagrama). Las horas se guardan en UTC; la
zona de presentacion solo agrega columnas locales con desfase fijo. Es estado y procedencia: no genera hallazgos ni
dictamina cumplimiento. Sin la clave no hace nada. El perfil se comparte entre corridas: un dataset cuyos archivos no
estan en esta corrida queda como "sin datos en esta corrida" (no es error).
"""
from __future__ import annotations

import hashlib
import os
import re
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import __version__
from .i18n import t

CLAVE = "manifiesto"
ARCHIVO = "manifiesto.csv"
HOJA = "Manifiesto"
ARCHIVO_PLAN = "plan_captura.csv"
HOJA_PLAN = "Plan de captura"
TITULO = "Manifiesto de datos"
TITULO_PLAN = "Plan de captura contra lo capturado"

COLUMNAS = ["dataset_id", "sitio", "sensor", "punto_o_archivos", "punto_captura", "fuentes_espejadas", "no_ve",
            "inicio_utc", "fin_utc", "origen_ventana", "inicio_local", "fin_local", "dias", "huecos",
            "perdida_tcp_pct", "perdidas_pcapng", "perdidas_declaradas", "archivos_n", "sha256", "procesado_por",
            "version", "estado"]
COL_SECCION = ["dataset_id", "sitio", "sensor", "punto_o_archivos", "inicio_utc", "fin_utc", "dias",
               "perdidas_pcapng", "archivos_n", "estado"]
COL_PLAN = ["sitio", "punto", "planeado", "capturado", "dataset_id", "dias_planeados", "dias_capturados", "estado"]

CON_DATOS, SIN_DATOS = "con datos", "sin datos en esta corrida"
MEDIDA, DECLARADA, DISTINTA = "medida", "declarada", "medida (declarada distinta)"
SIN_DATO = "sin dato"
SI, NO = "si", "no"
COMPLETO, PARCIAL, PENDIENTE, NO_PLANEADO = "completo", "parcial", "pendiente", "no planeado"

MAX_SITIOS, MAX_DATASETS, MAX_ARCHIVOS, MAX_PUNTOS, MAX_MUESTRAS = 200, 500, 200, 500, 50
MAX_TEXTO, MAX_LISTA, MAX_ID, MAX_CODIGO, MAX_ETIQUETA, MAX_PROCESADO = 200, 100, 64, 40, 40, 100
MAX_SECCION = 30
MAX_CELDA_XLSX = 32000
DIFERENCIA_VENTANA_S = 3600

_CODIGO = re.compile(rf"^[A-Za-z0-9_-]{{1,{MAX_CODIGO}}}$")
_ID = re.compile(rf"^[A-Za-z0-9._-]{{1,{MAX_ID}}}$")
_DESFASE = re.compile(r"^([+-])(\d{2}):(\d{2})$")
_CAMPOS_DS = ("sitio", "punto", "archivos", "id", "sensor", "punto_captura", "fuentes_espejadas", "no_ve",
              "perdidas_declaradas", "inicio_utc", "fin_utc")

NOTA = ("Procedencia de los datos: lo medido por la herramienta (ventana, huecos y perdida TCP de la validacion de la "
        "captura, SHA-256 de cada archivo crudo, contadores ISB de un pcapng) junto con lo que declara el analista "
        "(sensor, punto de captura, fuentes espejadas, segmentos que el punto no ve, perdidas del SPAN o del "
        "agregador). Es estado, no un dictamen de cumplimiento: que no haya perdidas declaradas no prueba que no las "
        "haya. Las horas locales usan un desfase fijo, sin reglas de horario de verano.")
AVISO_SIN_DATOS = "[!] manifiesto: dataset {id} ({sitio}) sin datos en esta corrida: {que}"
AVISO_DISTINTA = ("[!] manifiesto: dataset {id}: la ventana declarada difiere mas de 1 hora de la medida por la "
                  "captura; se usa la medida")
AVISO_SIN_DECLARAR = "[!] manifiesto: puntos de captura sin dataset declarado: {puntos}"
AVISO_REPETIDO = "[!] manifiesto: dataset_id repetido en la corrida: {ids}"


# --------------------------------------------------------------------------- #
# Perfil
# --------------------------------------------------------------------------- #


def _texto(x, donde, fallo, maximo=MAX_TEXTO):
    if not isinstance(x, str) or not 1 <= len(x.strip()) <= maximo:
        fallo(f"'{donde}' debe ser un texto de 1 a {maximo} caracteres.")
    return x.strip()


def _lista_textos(x, donde, fallo):
    if not isinstance(x, list) or len(x) > MAX_LISTA:
        fallo(f"'{donde}' debe ser una lista de 0 a {MAX_LISTA} textos.")
    return [_texto(i, donde, fallo) for i in x]


def _fecha(x, donde, fallo) -> str:
    """ISO 8601 con Z u offset -> texto UTC 'YYYY-MM-DDTHH:MM:SSZ'."""
    if not isinstance(x, str):
        fallo(f"'{donde}' debe ser una fecha ISO 8601 con Z u offset.")
    s = x.strip()
    if s[-1:] in ("Z", "z"):
        s = s[:-1] + "+00:00"
    try:
        d = datetime.fromisoformat(s)
    except ValueError:
        fallo(f"'{donde}': '{x}' no es una fecha ISO 8601 valida.")
    if d.tzinfo is None:
        fallo(f"'{donde}': '{x}' debe llevar Z u offset (las horas se guardan en UTC).")
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _minutos(desfase: str):
    """'+HH:MM' -> minutos con signo; None si no es valido o sale de -12:00 a +14:00."""
    m = _DESFASE.match(desfase) if isinstance(desfase, str) else None
    if not m or int(m.group(3)) > 59:
        return None
    n = (int(m.group(2)) * 60 + int(m.group(3))) * (-1 if m.group(1) == "-" else 1)
    return n if -720 <= n <= 840 else None


def _codigo(x, sitios, donde, fallo):
    if not isinstance(x, str) or x not in sitios:
        fallo(f"'{donde}': '{x}' no esta en {CLAVE}.sitios.")
    return x


def _dataset(d, i, sitios, fallo, objeto):
    donde = f"{CLAVE}.datasets[{i}]"
    d = objeto(d, donde, _CAMPOS_DS)
    out: dict = {"sitio": _codigo(d.get("sitio"), sitios, f"{donde}.sitio", fallo)}
    if "punto" not in d and "archivos" not in d:
        fallo(f"'{donde}' necesita 'punto' (modo captura) o 'archivos' (modo diagrama).")
    if "punto" in d:
        out["punto"] = _texto(d["punto"], f"{donde}.punto", fallo)
    if "archivos" in d:
        a = d["archivos"]
        if not isinstance(a, list) or not 1 <= len(a) <= MAX_ARCHIVOS:
            fallo(f"'{donde}.archivos' debe ser una lista de 1 a {MAX_ARCHIVOS} nombres de archivo.")
        nombres = [_texto(x, f"{donde}.archivos", fallo) for x in a]
        for n in nombres:
            if "/" in n or "\\" in n:
                fallo(f"'{donde}.archivos': '{n}' debe ser un nombre de archivo sin ruta.")
        out["archivos"] = list(dict.fromkeys(nombres))
    if "id" in d:
        if not isinstance(d["id"], str) or not _ID.match(d["id"]):
            fallo(f"'{donde}.id' debe tener de 1 a {MAX_ID} caracteres de [A-Za-z0-9._-].")
        out["id"] = d["id"]
    for k in ("sensor", "punto_captura", "perdidas_declaradas"):
        if k in d:
            out[k] = _texto(d[k], f"{donde}.{k}", fallo)
    for k in ("fuentes_espejadas", "no_ve"):
        out[k] = _lista_textos(d.get(k, []), f"{donde}.{k}", fallo)
    for k in ("inicio_utc", "fin_utc"):
        if k in d:
            out[k] = _fecha(d[k], f"{donde}.{k}", fallo)
    if "inicio_utc" in out and "fin_utc" in out and out["fin_utc"] < out["inicio_utc"]:
        fallo(f"'{donde}': fin_utc es anterior a inicio_utc.")
    return out


def _plan(p, sitios, fallo, objeto):
    p = objeto(p, f"{CLAVE}.plan", ("dias_por_punto", "puntos", "muestras"))
    out: dict = {"puntos": [], "muestras": []}
    puntos = p.get("puntos", [])
    if not isinstance(puntos, list) or len(puntos) > MAX_PUNTOS:
        fallo(f"'{CLAVE}.plan.puntos' debe ser una lista de 0 a {MAX_PUNTOS} objetos {{sitio, punto}}.")
    if "dias_por_punto" in p:
        d = p["dias_por_punto"]
        if isinstance(d, bool) or not isinstance(d, (int, float)) or not 0.5 <= d <= 60:
            fallo(f"'{CLAVE}.plan.dias_por_punto' debe ser un numero de 0.5 a 60.")
        out["dias_por_punto"] = float(d)
    elif puntos:
        fallo(f"'{CLAVE}.plan.dias_por_punto' es obligatorio cuando el plan trae puntos.")
    for i, x in enumerate(puntos):
        x = objeto(x, f"{CLAVE}.plan.puntos[{i}]", ("sitio", "punto"))
        out["puntos"].append({"sitio": _codigo(x.get("sitio"), sitios, f"{CLAVE}.plan.puntos[{i}].sitio", fallo),
                              "punto": _texto(x.get("punto"), f"{CLAVE}.plan.puntos[{i}].punto", fallo)})
    muestras = p.get("muestras", [])
    if not isinstance(muestras, list) or len(muestras) > MAX_MUESTRAS:
        fallo(f"'{CLAVE}.plan.muestras' debe ser una lista de 0 a {MAX_MUESTRAS} objetos.")
    for i, m in enumerate(muestras):
        donde = f"{CLAVE}.plan.muestras[{i}]"
        m = objeto(m, donde, ("nombre", "sitios", "total"))
        s = m.get("sitios")
        if not isinstance(s, list):
            fallo(f"'{donde}.sitios' debe ser una lista de codigos de {CLAVE}.sitios.")
        grupo = list(dict.fromkeys(_codigo(x, sitios, f"{donde}.sitios", fallo) for x in s))
        total = m.get("total")
        if isinstance(total, bool) or not isinstance(total, int) or total < len(grupo):
            fallo(f"'{donde}.total' debe ser un entero mayor o igual que la cantidad de sitios del grupo.")
        out["muestras"].append({"nombre": _texto(m.get("nombre"), f"{donde}.nombre", fallo), "sitios": grupo,
                                "total": total})
    return out


def validar(v, fallo, objeto) -> dict:
    """Normaliza la clave de perfil `manifiesto`."""
    v = objeto(v, CLAVE, ("sitios", "zona_presentacion", "procesado_por", "datasets", "plan"))
    s = v.get("sitios")
    if not isinstance(s, list) or not 1 <= len(s) <= MAX_SITIOS:
        fallo(f"'{CLAVE}.sitios' es obligatorio: una lista de 1 a {MAX_SITIOS} codigos de sitio.")
    for x in s:
        if not isinstance(x, str) or not _CODIGO.match(x):
            fallo(f"'{CLAVE}.sitios': '{x}' debe tener de 1 a {MAX_CODIGO} caracteres de [A-Za-z0-9_-].")
    out: dict = {"sitios": list(dict.fromkeys(s))}
    if "zona_presentacion" in v:
        z = objeto(v["zona_presentacion"], f"{CLAVE}.zona_presentacion", ("etiqueta", "desfase"))
        et = _texto(z.get("etiqueta"), f"{CLAVE}.zona_presentacion.etiqueta", fallo, MAX_ETIQUETA)
        if _minutos(z.get("desfase")) is None:
            fallo(f"'{CLAVE}.zona_presentacion.desfase' debe ser +HH:MM o -HH:MM entre -12:00 y +14:00.")
        out["zona_presentacion"] = {"etiqueta": et, "desfase": z["desfase"]}
    if "procesado_por" in v:
        out["procesado_por"] = _texto(v["procesado_por"], f"{CLAVE}.procesado_por", fallo, MAX_PROCESADO)
    ds = v.get("datasets")
    if not isinstance(ds, list) or not 1 <= len(ds) <= MAX_DATASETS:
        fallo(f"'{CLAVE}.datasets' es obligatorio: una lista de 1 a {MAX_DATASETS} objetos.")
    out["datasets"] = [_dataset(d, i, out["sitios"], fallo, objeto) for i, d in enumerate(ds)]
    ids = [d["id"] for d in out["datasets"] if "id" in d]
    if len(ids) != len(set(ids)):
        fallo(f"'{CLAVE}.datasets': hay ids repetidos ({', '.join(sorted({i for i in ids if ids.count(i) > 1}))}).")
    if "plan" in v:
        out["plan"] = _plan(v["plan"], out["sitios"], fallo, objeto)
    return out


# --------------------------------------------------------------------------- #
# Perdidas de un pcapng (bloques ISB), sin leer paquetes
# --------------------------------------------------------------------------- #

_SHB = b"\x0a\x0d\x0d\x0a"
_BLOQUE_ISB = 5
_OPC_IFDROP, _OPC_OSDROP = 5, 6


def _opciones_isb(cuerpo: bytes, fin: str) -> dict:
    """{codigo: valor} de las opciones isb_ifdrop e isb_osdrop del cuerpo de un ISB (tras id de interfaz y hora)."""
    out, pos = {}, 12
    while pos + 4 <= len(cuerpo):
        codigo, largo = struct.unpack(fin + "HH", cuerpo[pos:pos + 4])
        pos += 4
        if codigo == 0:
            break
        if codigo in (_OPC_IFDROP, _OPC_OSDROP) and largo == 8 and pos + 8 <= len(cuerpo):
            out[codigo] = struct.unpack(fin + "Q", cuerpo[pos:pos + 8])[0]
        pos += (largo + 3) // 4 * 4
    return out


def perdidas_pcapng(path):
    """Suma de isb_ifdrop e isb_osdrop de los ISB de un pcapng (el ultimo valor de cada interfaz: los contadores son
    acumulados). None ("sin dato") si no es pcapng, esta truncado o no trae esas opciones. Nunca lanza."""
    try:
        tam = os.path.getsize(path)
        with open(path, "rb") as fh:
            fin, pos, por_if = None, 0, {}
            while pos < tam:
                h = fh.read(8)
                if len(h) < 8:
                    return None
                if h[:4] == _SHB:
                    m = fh.read(4)
                    fin = "<" if m == b"\x4d\x3c\x2b\x1a" else ">" if m == b"\x1a\x2b\x3c\x4d" else None
                    if fin is None:
                        return None
                    largo = struct.unpack(fin + "I", h[4:8])[0]
                    falta = largo - 12
                else:
                    if fin is None:
                        return None
                    tipo, largo = struct.unpack(fin + "II", h)
                    falta = largo - 8
                    if largo < 12 or largo % 4 or pos + largo > tam:
                        return None
                    if tipo == _BLOQUE_ISB:
                        cuerpo = fh.read(falta)
                        iface = struct.unpack(fin + "I", cuerpo[:4])[0]
                        ops = _opciones_isb(cuerpo[:-4], fin)
                        previo = por_if.setdefault(iface, {})
                        for k, val in ops.items():
                            previo[k] = max(previo.get(k, 0), val)
                        falta = 0
                if largo < 12 or largo % 4 or pos + largo > tam:
                    return None
                if falta > 0:
                    fh.seek(falta, 1)
                pos += largo
        valores = [v for d in por_if.values() for v in d.values()]
        return sum(valores) if valores else None
    except (OSError, struct.error):
        return None


# --------------------------------------------------------------------------- #
# Construccion
# --------------------------------------------------------------------------- #


def _utc(texto: str) -> datetime:
    return datetime.strptime(texto, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _iso(d: datetime) -> str:
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _local(texto: str, zona) -> str:
    if not texto or not zona:
        return ""
    d = _utc(texto) + timedelta(minutes=_minutos(zona["desfase"]))
    return f"{d.strftime('%Y-%m-%d %H:%M:%S')} {zona['etiqueta']}"


def dataset_id(ds: dict, shas: list) -> str:
    """El id declarado; si no, DS- y los 12 primeros hex del SHA-256 de los sha256 ordenados (inmutable)."""
    if ds.get("id"):
        return ds["id"]
    if shas:
        base = "\n".join(sorted(shas))
    else:
        base = "\n".join(["sin-datos", ds["sitio"], ds.get("punto", ""), *sorted(ds.get("archivos", []))])
    return "DS-" + hashlib.sha256(base.encode("utf-8")).hexdigest()[:12].upper()


def _bytes(path) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _archivos(pares: list) -> list:
    return [{"archivo": Path(p).name, "sha256": sha, "bytes": _bytes(p), "_ruta": str(p)} for p, sha in pares]


def _fila(ds: dict, cfg: dict, archivos: list, punto_c1, avisos: list) -> dict:
    """Fila de un dataset. `archivos`: [{archivo, sha256, bytes, _ruta}] (vacio = sin datos); `punto_c1`: el punto de
    cobertura_captura o None (modo diagrama)."""
    con = bool(archivos)
    shas = [a["sha256"] for a in archivos]
    ident = dataset_id(ds, shas)
    f = {"dataset_id": ident, "sitio": ds["sitio"], "sensor": ds.get("sensor", ""), "punto": ds.get("punto", ""),
         "archivos": [a["archivo"] for a in archivos] if con else list(ds.get("archivos", [])),
         "punto_captura": ds.get("punto_captura", ""), "fuentes_espejadas": ds.get("fuentes_espejadas", []),
         "no_ve": ds.get("no_ve", []), "perdidas_declaradas": ds.get("perdidas_declaradas", ""),
         "procesado_por": cfg.get("procesado_por", ""), "version": __version__,
         "estado": CON_DATOS if con else SIN_DATOS, "inicio_utc": "", "fin_utc": "", "origen_ventana": "",
         "duracion_s": None, "huecos": "", "perdida_tcp_pct": "", "perdidas_pcapng": SIN_DATO,
         "archivos_n": len(archivos),
         "archivos_sha": [{k: a[k] for k in ("archivo", "sha256", "bytes")} for a in archivos]}
    ini = fin = None
    if punto_c1 is not None and punto_c1["m"]["inicio"] is not None:
        m = punto_c1["m"]
        ini = datetime.fromtimestamp(m["inicio"], timezone.utc)
        fin = datetime.fromtimestamp(m["fin"], timezone.utc)
        f["origen_ventana"] = MEDIDA
        f["huecos"] = m["huecos"]
        f["perdida_tcp_pct"] = round(m["perdida_pct"], 2)
        if "inicio_utc" in ds and "fin_utc" in ds:
            dif = max(abs((_utc(ds["inicio_utc"]) - ini).total_seconds()),
                      abs((_utc(ds["fin_utc"]) - fin).total_seconds()))
            if dif > DIFERENCIA_VENTANA_S:
                f["origen_ventana"] = DISTINTA
                avisos.append(AVISO_DISTINTA.format(id=ident))
    elif con and "inicio_utc" in ds and "fin_utc" in ds:
        ini, fin = _utc(ds["inicio_utc"]), _utc(ds["fin_utc"])
        f["origen_ventana"] = DECLARADA
    if ini is not None:
        f["inicio_utc"], f["fin_utc"] = _iso(ini), _iso(fin)
        f["duracion_s"] = (fin - ini).total_seconds()
    if con:
        vals = [v for v in (perdidas_pcapng(a["_ruta"]) for a in archivos) if v is not None]
        if vals:
            f["perdidas_pcapng"] = sum(vals)
    return f


def _plan_resultado(cfg: dict, filas: list):
    plan = cfg.get("plan")
    if plan is None:
        return None
    dias = plan.get("dias_por_punto")
    cap: dict = {}
    for f in filas:
        if f["estado"] == CON_DATOS and f["punto"]:
            c = cap.setdefault((f["sitio"], f["punto"]), {"ids": [], "seg": 0.0})
            c["ids"].append(f["dataset_id"])
            c["seg"] += f["duracion_s"] or 0.0
    planeados = list(dict.fromkeys((p["sitio"], p["punto"]) for p in plan["puntos"]))
    claves = planeados + sorted(k for k in cap if k not in planeados)
    out = []
    for k in claves:
        c = cap.get(k)
        plan_k = k in planeados
        capd = (c["seg"] / 86400.0) if c else 0.0
        if not plan_k:
            estado = NO_PLANEADO
        elif not c:
            estado = PENDIENTE
        else:
            estado = COMPLETO if dias is not None and capd >= dias else PARCIAL
        out.append({"sitio": k[0], "punto": k[1], "planeado": SI if plan_k else NO, "capturado": SI if c else NO,
                    "dataset_id": list(dict.fromkeys(c["ids"])) if c else [],
                    "dias_planeados": dias if plan_k else None, "dias_capturados": capd if c else None,
                    "estado": estado})
    con_datos = {f["sitio"] for f in filas if f["estado"] == CON_DATOS}
    muestras = [{"nombre": m["nombre"], "capturados": len([s for s in m["sitios"] if s in con_datos]),
                 "total": m["total"], "planeados": len(m["sitios"]), "sitios": m["sitios"]}
                for m in plan["muestras"]]
    cuenta = {e: sum(1 for x in out if x["estado"] == e) for e in (COMPLETO, PARCIAL, PENDIENTE, NO_PLANEADO)}
    return {"dias_por_punto": dias, "filas": out, "muestras": muestras, "conteos": cuenta}


def construir(perfil, cobertura: dict, capturas: list, entradas: list) -> dict:
    """{} sin la clave de perfil. `capturas`: [(Path, sha256)] de la corrida de captura; `entradas`: [(Path, sha256)]
    de los archivos de exportes (modo diagrama); `cobertura`: cobertura_captura.construir (C1)."""
    cfg = (perfil or {}).get(CLAVE)
    if not cfg:
        return {}
    sha_ruta = {str(p): s for p, s in capturas}
    puntos = {p["punto"]: p for p in (cobertura or {}).get("puntos", ())}
    por_nombre: dict = {}
    for p, s in entradas:
        por_nombre.setdefault(Path(p).name, (p, s))
    avisos, filas, usados = [], [], set()
    zona = cfg.get("zona_presentacion")
    for ds in cfg["datasets"]:
        archivos, p1, falta = [], None, ""
        if capturas and "punto" in ds:
            p1 = puntos.get(ds["punto"])
            if p1 is None:
                falta = f"punto '{ds['punto']}' no esta en la captura"
            else:
                usados.add(ds["punto"])
                archivos = _archivos([(r, sha_ruta.get(r, "")) for r in p1["paths"]])
        elif entradas and "archivos" in ds:
            perdidos = [n for n in ds["archivos"] if n not in por_nombre]
            if perdidos:
                falta = "faltan archivos: " + ", ".join(perdidos)
            else:
                archivos = _archivos([por_nombre[n] for n in ds["archivos"]])
        else:
            falta = "el modo de la corrida no tiene el punto ni los archivos del dataset"
        f = _fila(ds, cfg, archivos, p1, avisos)
        if falta:
            avisos.append(AVISO_SIN_DATOS.format(id=f["dataset_id"], sitio=ds["sitio"], que=falta))
        f["inicio_local"], f["fin_local"] = _local(f["inicio_utc"], zona), _local(f["fin_utc"], zona)
        filas.append(f)
    ids = [f["dataset_id"] for f in filas]
    repetidos = sorted({i for i in ids if ids.count(i) > 1})
    if repetidos:
        avisos.append(AVISO_REPETIDO.format(ids=", ".join(repetidos)))
    sin = sorted(n for n in puntos if n not in usados)
    if sin:
        avisos.append(AVISO_SIN_DECLARAR.format(puntos=", ".join(sin)))
    con = sum(1 for f in filas if f["estado"] == CON_DATOS)
    return {"filas": filas, "avisos": avisos, "zona": zona, "plan": _plan_resultado(cfg, filas),
            "conteos": {"datasets": len(filas), "con_datos": con, "sin_datos": len(filas) - con,
                        "sitios": len({f["sitio"] for f in filas})}}


def hay(m: dict) -> bool:
    return bool(m and m.get("filas"))


def avisos(m: dict) -> list:
    return list(m.get("avisos", ())) if m else []


# --------------------------------------------------------------------------- #
# Salidas
# --------------------------------------------------------------------------- #


def _dias(f: dict) -> str:
    return "" if f["duracion_s"] is None else f"{f['duracion_s'] / 86400:.1f}"


def _sha_texto(f: dict) -> str:
    return ";".join(f"{a['archivo']}:{a['sha256']}" for a in f["archivos_sha"])


def _dato(f: dict, col: str):
    """Valor de una columna de la tabla principal (traducido donde corresponde)."""
    if col == "punto_o_archivos":
        return f["punto"] or ";".join(f["archivos"])
    if col in ("fuentes_espejadas", "no_ve"):
        return ";".join(f[col])
    if col == "dias":
        return _dias(f)
    if col == "perdida_tcp_pct":
        return "" if f[col] == "" else f"{f[col]:.2f}"
    if col == "perdidas_pcapng":
        return t(SIN_DATO) if f[col] == SIN_DATO else f[col]
    if col in ("origen_ventana", "estado"):
        return t(f[col]) if f[col] else ""
    if col == "sha256":
        return _sha_texto(f)
    return f[col]


def fila_tabla(f: dict, columnas=COLUMNAS) -> list:
    return [_dato(f, c) for c in columnas]


def _fila_plan(x: dict) -> list:
    def dias(v):
        return "" if v is None else f"{v:.1f}"
    return [x["sitio"], x["punto"], t(x["planeado"]), t(x["capturado"]), ";".join(x["dataset_id"]),
            dias(x["dias_planeados"]), dias(x["dias_capturados"]), t(x["estado"])]


def texto_muestra(mu: dict) -> str:
    return t("muestra {n}: capturados {a} de {m} (planeados {k})", n=mu["nombre"], a=mu["capturados"],
             m=mu["total"], k=mu["planeados"])


def tablas(m: dict) -> list:
    """[(archivo_csv, hoja, cabecera, filas)]; el CSV lleva los sha256 completos y la hoja los recorta si una celda
    pasaria del limite de Excel."""
    if not hay(m):
        return []
    filas = [fila_tabla(f) for f in m["filas"]]
    i = COLUMNAS.index("sha256")
    hoja = [[(c[:MAX_CELDA_XLSX] + "..." if k == i and len(c) > MAX_CELDA_XLSX else c) for k, c in enumerate(r)]
            for r in filas]
    out = [(ARCHIVO, None, COLUMNAS, filas), ("", HOJA, COLUMNAS, hoja)]
    if m["plan"] is not None:
        pf = [_fila_plan(x) for x in m["plan"]["filas"]]
        pf += [[texto_muestra(mu)] + [""] * (len(COL_PLAN) - 1) for mu in m["plan"]["muestras"]]
        out += [(ARCHIVO_PLAN, HOJA_PLAN, COL_PLAN, pf)]
    return out


def resumen_texto(m: dict) -> str:
    c = m["conteos"]
    return t("{n} datasets ({a} con datos, {b} sin datos en esta corrida) en {s} sitios. Detalle en {f}; los SHA-256 "
             "de cada archivo estan en {f} y en manifiesto_<dataset_id>.json.", n=c["datasets"], a=c["con_datos"],
             b=c["sin_datos"], s=c["sitios"], f=ARCHIVO)


def resumen_plan(m: dict) -> str:
    c = m["plan"]["conteos"]
    return t("Plan de captura: {a} puntos completos, {b} parciales, {c} pendientes, {d} no planeados. Detalle en {f}.",
             a=c[COMPLETO], b=c[PARCIAL], c=c[PENDIENTE], d=c[NO_PLANEADO], f=ARCHIVO_PLAN)


def seccion(m: dict) -> dict:
    """Datos de la seccion de los reportes (todo traducido); sin SHA-256 (van en el CSV y el JSON)."""
    mas = len(m["filas"]) - MAX_SECCION
    out = {"titulo": t(TITULO), "nota": t(NOTA), "resumen": resumen_texto(m), "cab": [t(c) for c in COL_SECCION],
           "filas": [fila_tabla(f, COL_SECCION) for f in m["filas"][:MAX_SECCION]],
           "mas": t("Se muestran {n} filas; {m} mas estan en {f}.", n=MAX_SECCION, m=mas, f=ARCHIVO)
           if mas > 0 else "", "plan": None}
    if m["plan"] is not None:
        p = m["plan"]
        masp = len(p["filas"]) - MAX_SECCION
        out["plan"] = {"titulo": t(TITULO_PLAN), "resumen": resumen_plan(m), "cab": [t(c) for c in COL_PLAN],
                       "filas": [_fila_plan(x) for x in p["filas"][:MAX_SECCION]],
                       "mas": t("Se muestran {n} filas; {m} mas estan en {f}.", n=MAX_SECCION, m=masp,
                                f=ARCHIVO_PLAN) if masp > 0 else "",
                       "muestras": [texto_muestra(mu) for mu in p["muestras"]]}
    return out


def _json_fila(f: dict) -> dict:
    return {"dataset_id": f["dataset_id"], "sitio": f["sitio"], "sensor": f["sensor"], "punto": f["punto"],
            "archivos": f["archivos_sha"], "punto_captura": f["punto_captura"],
            "fuentes_espejadas": f["fuentes_espejadas"], "no_ve": f["no_ve"], "inicio_utc": f["inicio_utc"],
            "fin_utc": f["fin_utc"], "origen_ventana": f["origen_ventana"], "inicio_local": f["inicio_local"],
            "fin_local": f["fin_local"], "dias": _dias(f), "huecos": f["huecos"],
            "perdida_tcp_pct": f["perdida_tcp_pct"], "perdidas_pcapng": f["perdidas_pcapng"],
            "perdidas_declaradas": f["perdidas_declaradas"], "archivos_n": f["archivos_n"],
            "procesado_por": f["procesado_por"], "version": f["version"], "estado": f["estado"]}


def filas_json(m: dict) -> list:
    """Una entrada por dataset, con la lista de archivos (nombre, sha256, bytes)."""
    return [_json_fila(f) for f in m["filas"]] if hay(m) else []


def para_json(m: dict) -> dict:
    if not hay(m):
        return {}
    out = {"conteos": m["conteos"], "zona_presentacion": m["zona"], "filas": filas_json(m), "nota": t(NOTA)}
    if m["plan"] is not None:
        p = m["plan"]
        out["plan"] = {"dias_por_punto": p["dias_por_punto"], "conteos": p["conteos"], "muestras": p["muestras"],
                       "filas": [{**x, "dias_planeados": x["dias_planeados"],
                                  "dias_capturados": None if x["dias_capturados"] is None
                                  else round(x["dias_capturados"], 1)} for x in p["filas"]]}
    return out


def nota_no_ve(m: dict) -> list:
    """Notas para la seccion de flujos o matriz de comunicaciones: un punto que no ve segmentos."""
    if not hay(m):
        return []
    out = []
    for f in m["filas"]:
        if f["no_ve"] and f["estado"] == CON_DATOS:
            nombre = f["punto"] or f["punto_captura"] or f["dataset_id"]
            out.append(t("Ausencia de un flujo no es inexistencia: el punto {p} no ve {s}.", p=nombre,
                         s=", ".join(f["no_ve"])))
    return out
