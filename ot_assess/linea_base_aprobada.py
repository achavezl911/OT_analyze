"""LB1 (D82): linea base aprobada de un sitio y desviaciones de cada corrida nueva.

El equipo revisa una corrida, la aprueba como referencia (`aprobar`) y la carpeta resultante queda inmutable: lleva
los hash SHA-256 de lo copiado (`verificar`). Una corrida nueva se compara contra ella con el motor de E4
(comparar.py: identidad de activos, conductos y escritores) y con la linea base de trafico de L1. Las desviaciones
ordenan la revision; no son un veredicto. Nada aqui dice "cumple" ni "no cumple". La herramienta trabaja por lotes:
no vigila ni alerta en tiempo real.
"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from . import __version__, json_entrada
from . import comparar as _cmp
from . import entrega as _en
from .i18n import t

ARCHIVO = "linea_base_aprobada.json"
SUMAS = "linea_base_aprobada.sha256"
A_DESV, H_DESV = "desviaciones_linea_base.csv", "Desviaciones linea base"
FORMATO = 1
OBLIGATORIOS = ("resultado.json", "inventario.csv", "inventario_normalizado.csv", "comunicaciones.csv",
                "control.csv", "hallazgos.csv")
OPCIONALES = ("linea_base_trafico.json", "periodicidad.csv", "firewall_contraste.csv")
FACTOR_VOLUMEN = 3.0
MAX_TOP = 10
ESTADOS_REVISION = ("esperado", "no esperado", "por investigar")

TITULO = "Desviaciones respecto de la linea base aprobada"
NOTA = ("Compara esta corrida con la linea base que el equipo reviso y aprobo para el sitio. Una desviacion es un "
        "cambio respecto de esa referencia, no un incidente ni un incumplimiento: puede ser un cambio autorizado "
        "o una falla de la captura. Las columnas de revision estan vacias a proposito: las llena el analista que "
        "revisa cada desviacion.")

T_ESCRITOR = "escritor nuevo"
T_CONDUCTO = "conducto nuevo"
T_ACTIVO = "activo nuevo no aprobado"
T_NO_VISTO = "activo aprobado no visto"
T_CAMBIO = "cambio de firmware, modelo o MAC"
T_VOLUMEN = "volumen sobre la linea base"
T_PERIODO = "cambio de periodicidad"
T_SIN_TRAFICO = "conducto aprobado sin trafico"
T_HALLAZGO = "hallazgo nuevo"
TIPOS = (T_ESCRITOR, T_CONDUCTO, T_ACTIVO, T_CAMBIO, T_VOLUMEN, T_PERIODO, T_SIN_TRAFICO, T_NO_VISTO, T_HALLAZGO)

COLUMNAS = ["tipo", "atencion", "zona", "origen", "destino", "puerto", "detalle", "valor_aprobado", "valor_actual",
            "estado_revision", "revisado_por", "fecha", "comentario"]
_ORDEN_ATENCION = {"alta": 0, "media": 1, "baja": 2}
_CTRL = re.compile(r"(?:Nivel|Level)\s*[012]\b")      # el CSV de una corrida en ingles dice "Level"
_CAMPO_CTRL = re.compile(r"(?:Nivel|Level)\s*[01]\b|controlador|controller|PLC|RTU|IED", re.IGNORECASE)
_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class ErrorLineaBase(Exception):
    pass


# ---------------------------------------------------------------- aprobar y verificar
def _hash(p: Path) -> str:
    with open(p, "rb") as fh:
        return _en.sha256_flujo(fh)[0]


def _leer_json(p: Path) -> dict:
    try:
        d = json_entrada.cargar(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return d if isinstance(d, dict) else {}


def aprobar(corrida, out, sitio: str, aprobado_por: str, revisado_por: str = "", nota: str = "",
            fecha: str = "") -> dict:
    """Copia lo necesario de `corrida` a `out` y escribe linea_base_aprobada.json con el manifiesto SHA-256.

    No copia capturas, cache ni mapas de anonimizacion: solo los archivos nombrados en OBLIGATORIOS y OPCIONALES."""
    corrida, out = Path(corrida).expanduser(), Path(out).expanduser()
    if not corrida.is_dir():
        raise ErrorLineaBase(f"CORRIDA espera una carpeta existente: '{corrida}'")
    sitio, aprobado_por, revisado_por = sitio.strip(), aprobado_por.strip(), revisado_por.strip()
    if not sitio:
        raise ErrorLineaBase("--sitio no puede estar vacio")
    if not aprobado_por:
        raise ErrorLineaBase("--aprobado-por no puede estar vacio")
    if revisado_por and revisado_por.casefold() == aprobado_por.casefold():
        raise ErrorLineaBase("--aprobado-por y --revisado-por deben ser personas distintas (control de calidad "
                             "por dos personas)")
    if out.resolve() == corrida.resolve():
        raise ErrorLineaBase("-o debe ser otra carpeta distinta de la corrida")
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise ErrorLineaBase(f"'{out}' ya existe y no esta vacia: una linea base aprobada no se sobrescribe; "
                             "para cambiarla se aprueba otra en otra carpeta")
    faltan = [n for n in OBLIGATORIOS if not (corrida / n).is_file()]
    if faltan:
        raise ErrorLineaBase("la corrida no tiene " + ", ".join(faltan) + " (no es la salida de un analisis)")
    res = _leer_json(corrida / "resultado.json")
    base = _leer_json(corrida / "linea_base_trafico.json")
    meta = base.get("meta") or {}
    perfil = res.get("perfil") or {}
    avisos = []
    if not base:
        avisos.append("la corrida no tiene linea_base_trafico.json: no se comparara el volumen ni la periodicidad")
    out.mkdir(parents=True, exist_ok=True)
    copiados = [n for n in (*OBLIGATORIOS, *OPCIONALES) if (corrida / n).is_file()]
    for n in copiados:
        shutil.copyfile(corrida / n, out / n)
    manifiesto = {n: _hash(out / n) for n in copiados}
    datos = {
        "formato": FORMATO, "sitio": sitio, "version_herramienta": __version__,
        "version_corrida": str((res.get("entorno") or {}).get("ot_assess") or ""),
        "ventana": meta.get("ventana") or {}, "puntos_de_captura": meta.get("puntos_de_captura") or [],
        "perfil": {k: perfil[k] for k in ("cliente", "sitio", "pais", "sector") if perfil.get(k)},
        "aprobado_por": aprobado_por, "revisado_por": revisado_por, "fecha_aprobacion": fecha or _en.ahora_utc(),
        "nota": nota.strip(), "manifiesto": manifiesto,
    }
    (out / ARCHIVO).write_text(json.dumps(datos, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    sumas = [(n, h) for n, h in manifiesto.items()] + [(ARCHIVO, _hash(out / ARCHIVO))]
    (out / SUMAS).write_text(_en.lineas_sha256(sumas), encoding="utf-8")
    return {"carpeta": str(out), "archivos": copiados, "avisos": avisos, "datos": datos}


def verificar(carpeta) -> list:
    """Lista de errores (vacia si la linea base esta intacta). Cada error nombra el archivo."""
    carpeta = Path(carpeta).expanduser()
    if not carpeta.is_dir():
        return [f"{carpeta}: no es una carpeta"]
    datos = _leer_json(carpeta / ARCHIVO)
    if not datos or datos.get("formato") != FORMATO or not isinstance(datos.get("manifiesto"), dict):
        return [f"{ARCHIVO}: falta o no es una linea base aprobada valida"]
    if not (carpeta / SUMAS).is_file():
        return [f"{SUMAS}: falta"]
    try:
        sumas = _en._leer_sumas((carpeta / SUMAS).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, _en.ErrorEntrega) as e:
        return [f"{SUMAS}: ilegible ({e})"]
    esperado = dict(datos["manifiesto"])
    esperado[ARCHIVO] = sumas.get(ARCHIVO, "")
    errores = []
    if sumas != esperado:
        errores.append(f"{SUMAS}: no coincide con el manifiesto de {ARCHIVO}")
    reales = _en._hashes_carpeta(carpeta)
    for n, h in sorted(sumas.items()):
        if n not in reales:
            errores.append(f"{n}: falta")
        elif reales[n] != h:
            errores.append(f"{n}: cambio (el hash SHA-256 ya no coincide)")
    for n in sorted(set(reales) - set(sumas) - {SUMAS}):
        errores.append(f"{n}: archivo que no estaba en la linea base aprobada")
    return errores


# ---------------------------------------------------------------- datos de la corrida actual
def _dicts(cab: list, filas: list) -> list:
    return [dict(zip(cab, f)) for f in filas]


def _si_no(v):
    return "si" if str(v).strip().lower() in ("si", "yes") else str(v)


def actual_de(tablas: list, hallazgos: list, linea_base: dict) -> dict:
    """Arma la corrida actual en memoria desde csvout.tablas(res); `hallazgos`: hallazgos ya generados."""
    por = {a: _dicts(c, f) for a, _h, c, f in tablas}
    for fila in por.get("comunicaciones.csv", ()):
        fila["cruza_zona"] = _si_no(fila.get("cruza_zona", ""))
    return {"inventario": por.get("inventario.csv", []), "normalizado": por.get("inventario_normalizado.csv", []),
            "comunicaciones": por.get("comunicaciones.csv", []), "control": por.get("control.csv", []),
            "hallazgos": [{"titulo": f["titulo"], "severidad": f["severidad"], "categoria": f.get("categoria", "")}
                          for f in hallazgos],
            "linea_base": linea_base or {}}


# ---------------------------------------------------------------- desviaciones
def _d(tipo, atencion, zona="", origen="", destino="", puerto="", detalle="", aprobado="", actual="",
       activos=(), alta_regla=False, controlador=False) -> dict:
    return {"tipo": tipo, "atencion": atencion, "zona": zona, "origen": origen, "destino": destino,
            "puerto": str(puerto), "detalle": detalle, "valor_aprobado": aprobado, "valor_actual": actual,
            "activos": sorted({a for a in activos if _IP.match(a or "")}), "alta_regla": alta_regla,
            "controlador": controlador}


def _zona_activo(x: dict) -> str:
    return _cmp._g(x, "zona_asignada") or _cmp._g(x, "zona_purdue")


def _por_nombre(inv: list) -> dict:
    out: dict = {}
    for x in inv:
        for k in (_cmp._g(x, "equipo"), *_cmp._partir(_cmp._g(x, "ips"))):
            if k:
                out.setdefault(k, x)
    return out


def _desv_activos(a: list, d: list, avisos: list) -> list:
    filas, _c, _m = _cmp._activos(a, d, avisos)
    idx_d, idx_a = _por_nombre(d), _por_nombre(a)
    out = []
    for estado, att, razon, equipo, ips, mac, _cambios in filas:
        if estado == "nuevo":
            x = idx_d.get(equipo) or {}
            out.append(_d(T_ACTIVO, att, _zona_activo(x), equipo, "", "", t(razon or "activo nuevo"), "",
                          ips or mac, _cmp._partir(ips)))
        elif estado == "desaparecido":
            x = idx_a.get(equipo) or {}
            out.append(_d(T_NO_VISTO, att, _zona_activo(x), equipo, "", "", t(razon), ips or mac, "",
                          _cmp._partir(ips)))
    return out


def _clave_cond(f: dict) -> tuple:
    return (_cmp._g(f, "origen_ip"), _cmp._g(f, "destino_ip"), _cmp._g(f, "puerto"), _cmp._g(f, "l4").lower())


def _desv_conductos(a: list, d: list) -> list:
    idx_a, idx_d = {}, {}
    for f in a:
        idx_a.setdefault(_clave_cond(f), f)
    for f in d:
        idx_d.setdefault(_clave_cond(f), f)
    out = []
    for fila in _cmp._conductos(a, d, float("inf")):
        estado, att, razon, o, de, srv, l4, pu = fila[:8]
        serv = f"{srv} {l4}/{pu}".strip()
        if estado == "nuevo":
            x = idx_d.get((o, de, pu, l4.lower())) or {}
            zd, zo = _cmp._g(x, "destino_zona"), _cmp._g(x, "origen_zona")
            alta = bool(_CTRL.search(zd)) or "internet" in zo.lower()
            out.append(_d(T_CONDUCTO, att, zd, o, de, pu, t("{serv}: {razon}", serv=serv, razon=t(razon)), "", serv,
                          (o, de), alta_regla=alta))
        elif estado == "ya_no_se_ve":
            x = idx_a.get((o, de, pu, l4.lower())) or {}
            out.append(_d(T_SIN_TRAFICO, att, _cmp._g(x, "destino_zona"), o, de, pu, serv, serv, "", (o, de)))
    return out


def _desv_escritores(a: list, d: list, inv_d: list) -> list:
    idx = _por_nombre(inv_d)
    out = []
    for estado, att, razon, o, de, proto, nuevas, ops in _cmp._escritores(a, d):
        if estado == "ya_no_se_ve":
            continue
        x = idx.get(de) or {}
        out.append(_d(T_ESCRITOR, att, _zona_activo(x), o, de, "", t("{serv}: {razon}", serv=proto, razon=t(razon)), "",
                      nuevas or ops, (o, de), controlador=True))
    return out


def _desv_hallazgos(a: list, d: list) -> list:
    out = []
    for estado, att, razon, _sa, sev, cat, tit in _cmp._hallazgos(a, d):
        if estado == "nuevo":
            out.append(_d(T_HALLAZGO, att, "", "", "", "", t(tit), "", f"{t(sev)} / {t(cat)}".strip(" /")))
    return out


def _norm(v: str) -> str:
    return " ".join((v or "").lower().split())


def _desv_identidad(a: list, d: list) -> list:
    """Firmware, modelo o MAC distinto en una misma IP (inventario normalizado). Solo cuenta si la linea base ya
    tenia el dato: un dato nuevo no es un cambio."""
    por_ip: dict = {}
    for x in d:
        for ip in _cmp._partir(_cmp._g(x, "ips")):
            por_ip.setdefault(ip, x)
    out, vistos = [], set()
    for x in a:
        for ip in sorted(_cmp._partir(_cmp._g(x, "ips"))):
            y = por_ip.get(ip)
            if y is None or ip in vistos:
                continue
            vistos.add(ip)
            cambios, antes, ahora = [], [], []
            for campo, etq in (("firmware", "firmware"), ("modelo", "modelo")):
                va, vd = _cmp._g(x, campo), _cmp._g(y, campo)
                if va and vd and _norm(va) != _norm(vd):
                    cambios.append(t("{c}: {a} -> {b}", c=t(etq), a=va, b=vd))
                    antes.append(t("{c} {v}", c=t(etq), v=va))
                    ahora.append(t("{c} {v}", c=t(etq), v=vd))
            ma, md = _cmp._partir(_cmp._g(x, "mac").lower()), _cmp._partir(_cmp._g(y, "mac").lower())
            if ma and md and not ma & md:
                va, vd = ";".join(sorted(ma)), ";".join(sorted(md))
                cambios.append(t("{c}: {a} -> {b}", c=t("MAC"), a=va, b=vd))
                antes.append(t("{c} {v}", c=t("MAC"), v=va))
                ahora.append(t("{c} {v}", c=t("MAC"), v=vd))
            if not cambios:
                continue
            ctrl = bool(_CAMPO_CTRL.search(_cmp._g(y, "nivel_purdue") + " " + _cmp._g(y, "rol")))
            out.append(_d(T_CAMBIO, "alta" if ctrl else "media", _cmp._g(y, "zona"), _cmp._g(y, "nombre") or ip,
                          ip, "", "; ".join(cambios), "; ".join(antes), "; ".join(ahora), (ip,), controlador=ctrl))
    return out


def _filas_trafico(lb: dict) -> dict:
    return {(f["origen_ip"], f["destino_ip"], str(f["puerto"]), (f.get("l4") or "").lower()): f
            for f in (lb or {}).get("conductos", ())}


def _ident_lb(f: dict) -> dict:
    return {"src": f["origen_ip"], "dst": f["destino_ip"], "port": str(f["puerto"]),
            "l4": (f.get("l4") or "").lower(), "bidir": bool(f.get("bidireccional"))}


def _desv_trafico(a: dict, d: dict, comunic_d: list) -> list:
    pares, _nuevos = _cmp._emparejar(_filas_trafico(a), _filas_trafico(d), _ident_lb)
    idx = {_clave_cond(f): f for f in reversed(comunic_d)}
    out = []
    for x, ys in pares:
        if not ys:
            continue
        y = ys[0]
        o, de, pu, l4 = x["origen_ip"], x["destino_ip"], str(x["puerto"]), x.get("l4") or ""
        serv = f"{x.get('servicio') or ''} {l4}/{pu}".strip()
        zona = _cmp._g(idx.get((o, de, pu, l4.lower())) or {}, "destino_zona")
        pa, pc = x.get("bytes_min_p95"), y.get("bytes_min_p95")
        if x.get("serie_por_minuto") and y.get("serie_por_minuto") and pa and pc is not None \
                and pc > FACTOR_VOLUMEN * pa:
            out.append(_d(T_VOLUMEN, "baja", zona, o, de, pu,
                          t("{serv}: p95 de bytes por minuto x{f}", serv=serv, f=f"{pc / pa:.1f}"),
                          t("{n} bytes/min (p95)", n=pa), t("{n} bytes/min (p95)", n=pc), (o, de)))
        if x.get("periodicidad") == "periodico" and y.get("periodicidad") == "irregular":
            out.append(_d(T_PERIODO, "baja", zona, o, de, pu,
                          t("{serv}: periodico -> irregular", serv=serv), t("periodico"), t("irregular"), (o, de)))
    return out


def _orden(d: dict) -> tuple:
    return (_ORDEN_ATENCION.get(d["atencion"], 9), TIPOS.index(d["tipo"]))


def _csv_aprobado(carpeta: Path, nombre: str, columnas: tuple, avisos: list):
    filas = _cmp.leer_csv(carpeta, nombre)
    if filas and not all(c in filas[0] for c in columnas):
        avisos.append(t("{n} de la linea base no tiene las columnas esperadas ({c}, ...): se aprobo en otro idioma "
                        "o con otra version; esa comparacion se omite.", n=nombre, c=columnas[0]))
        return None
    return filas


def evaluar(carpeta, actual: dict, sitio_perfil: str = "") -> dict:
    """Compara la corrida actual con la linea base aprobada de `carpeta`. Con manifiesto alterado no compara."""
    carpeta = Path(carpeta).expanduser()
    errores = verificar(carpeta)
    datos = _leer_json(carpeta / ARCHIVO)
    rep = {"carpeta": carpeta.name, "sitio": datos.get("sitio", ""), "aprobado_por": datos.get("aprobado_por", ""),
           "revisado_por": datos.get("revisado_por", ""), "fecha_aprobacion": datos.get("fecha_aprobacion", ""),
           "nota": datos.get("nota", ""), "ventana": datos.get("ventana") or {}, "avisos": [], "desviaciones": []}
    if errores:
        rep["estado"] = "manifiesto alterado"
        rep["avisos"] = [t("La linea base aprobada no pasa la verificacion; no se compara: {e}", e="; ".join(errores))]
        rep["resumen"] = resumen(rep)
        return rep
    avisos = rep["avisos"]
    if datos.get("sitio") and sitio_perfil and _norm(datos["sitio"]) != _norm(sitio_perfil):
        avisos.append(t("El sitio de la linea base ({a}) no coincide con el del perfil ({b}): se compara igual.",
                        a=datos["sitio"], b=sitio_perfil))
    if datos.get("version_corrida") and datos["version_corrida"] != __version__:
        avisos.append(t("La linea base se genero con la version {a} y esta corrida es {b}: parte de las "
                        "desviaciones pueden venir de las reglas.", a=datos["version_corrida"], b=__version__))
    rep["estado"] = "comparada"
    des = rep["desviaciones"]
    a = _csv_aprobado(carpeta, "inventario.csv", ("equipo", "ips"), avisos)
    if a is not None and actual["inventario"]:
        varios: list = []
        des += _desv_activos(a, actual["inventario"], varios)
        if varios:
            avisos.append(t("{n} activos de la linea base coinciden con varios activos de la corrida actual (se "
                            "compara con el primero).", n=len(varios)))
    a = _csv_aprobado(carpeta, "comunicaciones.csv", ("origen_ip", "destino_ip", "puerto"), avisos)
    if a is not None:
        des += _desv_conductos(a, actual["comunicaciones"])
    a = _csv_aprobado(carpeta, "control.csv", ("origen", "destino", "protocolo", "operacion"), avisos)
    if a is not None:
        des += _desv_escritores(a, actual["control"], actual["inventario"])
    a = _csv_aprobado(carpeta, "hallazgos.csv", ("titulo", "severidad"), avisos)
    if a is not None:
        des += _desv_hallazgos(a, actual["hallazgos"])
    a = _csv_aprobado(carpeta, "inventario_normalizado.csv", ("ips", "mac", "firmware"), avisos)
    if a is not None:
        des += _desv_identidad(a, actual["normalizado"])
    base = _leer_json(carpeta / "linea_base_trafico.json")
    if base and actual["linea_base"]:
        des += _desv_trafico(base, actual["linea_base"], actual["comunicaciones"])
    elif not base:
        avisos.append(t("La linea base aprobada no tiene linea_base_trafico.json: no se compara el volumen ni la "
                        "periodicidad."))
    des.sort(key=_orden)
    rep["resumen"] = resumen(rep)
    return rep


def evaluar_corrida(res, carpeta, hallazgos: list, sitio_perfil: str = "") -> dict:
    """Para los CLI de analisis: arma la corrida actual desde `res` (a medio construir) y la compara."""
    from .report.csvout import tablas as _tablas
    actual = actual_de(_tablas(res), hallazgos, (res.salud_red or {}).get("linea_base"))
    return evaluar(carpeta, actual, sitio_perfil)


def imprimir(rep: dict) -> None:
    for adv in rep["avisos"]:
        print(f"[!] {adv}")
    if rep["estado"] == "comparada":
        r = rep["resumen"]
        print(f"    linea base aprobada ({rep['sitio'] or rep['carpeta']}): {r['total']} desviaciones, "
              f"{r['atencion_alta']} de atencion alta")


def resumen(rep: dict) -> dict:
    por_tipo: dict = {}
    for x in rep["desviaciones"]:
        por_tipo[x["tipo"]] = por_tipo.get(x["tipo"], 0) + 1
    return {"total": len(rep["desviaciones"]), "por_tipo": {k: por_tipo[k] for k in TIPOS if k in por_tipo},
            "atencion_alta": sum(1 for x in rep["desviaciones"] if x["atencion"] == "alta")}


# ---------------------------------------------------------------- salidas
def hay(rep: dict) -> bool:
    return bool(rep and rep.get("estado"))


def filas_tabla(rep: dict) -> list:
    return [[t(x["tipo"]), t(x["atencion"]), x["zona"], x["origen"], x["destino"], x["puerto"], x["detalle"],
             x["valor_aprobado"], x["valor_actual"], "", "", "", ""] for x in rep["desviaciones"]]


def tablas(rep: dict) -> list:
    if not hay(rep) or rep["estado"] != "comparada":
        return []
    return [(A_DESV, H_DESV, COLUMNAS, filas_tabla(rep))]


def _quien(rep: dict) -> str:
    return t("Sitio {s}; aprobada el {f} por {a}{r}.", s=rep["sitio"] or "-", f=rep["fecha_aprobacion"] or "-",
             a=rep["aprobado_por"] or "-", r=(t(" y revisada por {x}", x=rep["revisado_por"])
                                               if rep["revisado_por"] else ""))


def seccion(rep: dict) -> dict:
    """Para HTML, Markdown y Word: titulo, nota, resumen y tablas (titulo, cabecera, filas)."""
    res = rep["resumen"]
    if rep["estado"] != "comparada":
        resumen_txt = " ".join(t(x) for x in rep["avisos"])
        return {"titulo": t(TITULO), "nota": t(NOTA), "resumen": resumen_txt, "tablas": []}
    texto = _quien(rep) + " " + t("{n} desviaciones, {a} de atencion alta. Detalle en {f}.", n=res["total"],
                                   a=res["atencion_alta"], f=A_DESV)
    if rep["avisos"]:
        texto += " " + " ".join(rep["avisos"])
    tablas_ = []
    if res["por_tipo"]:
        tablas_.append((t("Desviaciones por tipo"), [t("tipo"), t("cantidad")],
                        [[t(k), n] for k, n in res["por_tipo"].items()]))
        top = [[t(x["tipo"]), t(x["atencion"]), x["zona"], x["origen"], x["destino"], x["detalle"]]
               for x in rep["desviaciones"][:MAX_TOP]]
        tablas_.append((t("Desviaciones de mayor atencion"),
                        [t(c) for c in ("tipo", "atencion", "zona", "origen", "destino", "detalle")], top))
    return {"titulo": t(TITULO), "nota": t(NOTA), "resumen": texto, "tablas": tablas_}


def para_json(rep: dict) -> dict:
    if not hay(rep):
        return {}
    res = rep["resumen"]
    return {"estado": rep["estado"], "carpeta": rep["carpeta"], "sitio": rep["sitio"],
            "fecha_aprobacion": rep["fecha_aprobacion"], "aprobado_por": rep["aprobado_por"],
            "revisado_por": rep["revisado_por"], "desviaciones": res["total"], "por_tipo": res["por_tipo"],
            "atencion_alta": res["atencion_alta"], "avisos": rep["avisos"]}
