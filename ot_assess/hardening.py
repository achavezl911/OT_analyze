"""Linea base de hardening por tipo de equipo (T1b, D86): lista de verificacion y evidencia de la corrida.

Por tipo de equipo (controlador, estacion, servidor, red, seguridad, otro) hay una lista propia de puntos de
configuracion, redactada con palabras propias y alineada a ISA/IEC 62443-4-2 (CR, EDR/HDR/NDR) y 3-3 (SR); los
mapeos estan sin revisar. Por cada activo del inventario, cada punto queda "revisar: evidencia en contra" si la
corrida ya muestra un hallazgo o un servicio que lo contradice, o "verificar en sitio" si no hay evidencia (lo
que no significa que este bien). No lee configuraciones de equipos y nunca concluye cumplimiento ni "endurecido".
Solo lee el modelo ya calculado. Datos en data/hardening.json.
"""
from __future__ import annotations

import collections
import json
import re
from functools import lru_cache
from pathlib import Path

from .i18n import t
from .roles import mostrar as mostrar_rol
from .zonas import mostrar_zona

RUTA = Path(__file__).parent / "data" / "hardening.json"
TITULO = "Linea base de hardening por tipo de equipo"
HOJA_BASE = "Hardening por tipo"
HOJA_ACTIVOS = "Hardening por activo"
ARCHIVO_BASE = "hardening_baseline.csv"
ARCHIVO_ACTIVOS = "hardening_activos.csv"
NOTA = ("Lista de verificacion propia por tipo de equipo, con puntos redactados con palabras propias y alineada a "
        "ISA/IEC 62443-4-2 (CR y EDR/HDR/NDR) y 3-3 (SR); los mapeos estan sin revisar. El tipo de cada activo se "
        "infiere del rol (capturas) o del tipo que da la plataforma. 'Revisar: evidencia en contra' significa que "
        "la corrida ya muestra un hallazgo o un servicio que contradice el punto; 'Verificar en sitio' significa "
        "que la corrida no tiene evidencia y no indica que el punto este bien. La herramienta no lee la "
        "configuracion de los equipos y no concluye cumplimiento ni equipo endurecido. La lista para la visita "
        "esta en hardening_baseline.csv.")
ESTADO_REVISAR = "revisar: evidencia en contra"
ESTADO_VERIFICAR = "verificar en sitio"
MAX_TOP = 15
COL_BASE = ["tipo", "id", "punto", "referencia_42", "referencia_33", "resultado_visita", "evidencia_presentada",
            "verificado_por", "fecha", "comentario"]
COL_ACTIVOS = ["activo", "ip", "zona", "rol", "tipo", "id_punto", "punto", "estado", "evidencia", "ids_hallazgo",
              "base_tipo"]
CAB_TIPOS = ["Tipo de equipo", "Activos", "Puntos", "Activos con evidencia en contra",
             "Puntos por verificar en sitio"]
CAB_TOP = ["ID", "Punto", "Tipo de equipo", "Activos en contra"]
_IPV4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?!\d)")


@lru_cache(maxsize=1)
def cargar() -> dict:
    d = json.loads(RUTA.read_text(encoding="utf-8"))
    for clave, info in d["tipos"].items():       # los ID salen de la posicion: HB-CTL-01, HB-CTL-02...
        for i, p in enumerate(d["puntos"][clave], 1):
            p["id"] = f"HB-{info['prefijo']}-{i:02d}"
            p["tipo"] = clave
    return d


def _norm(texto: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(texto).lower()).strip("_")


def tipo_de(activo: dict) -> str:
    """Clave del tipo de equipo de un activo; sin rol conocido, 'otro'."""
    from .importers.perfiles import clasificar_tipo
    d = cargar()
    rol = str(activo.get("role") or "")
    if rol in d["roles"]:
        return d["roles"][rol]
    for pref, tipo in d["prefijos_rol"].items():
        if rol.startswith(pref):
            return tipo
    if not rol:
        return d["tipos_internos"].get(str(activo.get("tipo", "")).lower(), "otro")
    plat = d["tipos_plataforma"].get(_norm(rol))
    if plat:
        return plat
    tipo = d["tipos_internos"].get(clasificar_tipo(rol)[0], "otro")
    if tipo == "otro":
        tipo = d["tipos_internos"].get(str(activo.get("tipo", "")).lower(), "otro")
    return tipo


def _puertos_servidos(activo: dict) -> set:
    out = set()
    for p in activo.get("ports_served") or ():
        try:
            out.add(int(p[0] if isinstance(p, tuple) else str(p).split("/")[0]))
        except ValueError:
            pass
    return out


def tipos_por_hallazgo(hallazgos) -> dict:
    """{ip: tipo} de las IP en `activos` de un hallazgo que identifica al equipo (p. ej. la configuracion del switch
    habla de las IP de gestion del propio switch)."""
    reglas = cargar()["tipo_por_hallazgo"]
    out: dict = {}
    for f in hallazgos:
        for r in reglas:
            if r["fragmento"] in f.get("titulo", ""):
                for ip in f.get("activos") or ():
                    out.setdefault(ip, r["tipo"])
    return out


def tipo_y_base(activo: dict, por_hallazgo: dict | None = None) -> tuple:
    """(clave de tipo, base): 'rol' (rol o tipo de plataforma), 'hallazgo' (rol vacio o Indeterminado y la IP es la
    de un equipo identificado por un hallazgo, p. ej. el switch), 'servicios' (por los puertos que sirve) o 'sin rol'
    (otro)."""
    d = cargar()
    rol = str(activo.get("role") or "")
    if rol and rol != "Indeterminado":
        return tipo_de(activo), "rol"
    if not rol:
        interno = d["tipos_internos"].get(str(activo.get("tipo", "")).lower(), "otro")
        if interno != "otro":
            return interno, "rol"
    for ip in sorted(activo.get("ips") or ()):
        if ip in (por_hallazgo or {}):
            return por_hallazgo[ip], "hallazgo"
    servidos = _puertos_servidos(activo)
    for r in d["tipo_por_servicio"]:
        if servidos & set(r["puertos"]):
            return r["tipo"], "servicios"
    return "otro", "sin rol"


def _valor(fila: dict, campo: str) -> str:
    return str((fila["campos"].get(campo) or {}).get("valor") or "")


def _conjunto(fila: dict, campo: str) -> set:
    return {x for x in _valor(fila, campo).split(";") if x}


def _activos_de_inventario(filas: list) -> dict:
    """Una entidad por fila del inventario normalizado, con la forma de `assets`."""
    return {f["id"]: {"mac": "", "ips": _conjunto(f, "ips"), "role": _valor(f, "rol"), "nombre": _valor(f, "nombre"),
                      "zona_asignada": _valor(f, "zona"), "ports_served": _conjunto(f, "servicios"),
                      "protocolos": _conjunto(f, "protocolos")}
            for f in filas}


def _servicios(activo: dict, d: dict) -> list:
    """[(nombre, detalle)] de los servicios en claro que el activo sirve segun el inventario."""
    cfg = d["servicios"]
    out = {}
    for p in activo.get("ports_served") or ():
        clave = f"{p[0]}/{p[1]}" if isinstance(p, tuple) else str(p)
        if clave in cfg["puertos"]:
            out[cfg["puertos"][clave]] = clave
    for pr in activo.get("protocolos") or ():
        for tok in re.split(r"[^a-z0-9]+", str(pr).lower()):
            if tok in cfg["protocolos"]:
                out.setdefault(cfg["protocolos"][tok], "")
    return sorted(out.items())


def _linea_con_ip(evidencia: str, ip: str, patron: str) -> bool:
    ip_rx = re.compile(r"(?<![\d.])" + re.escape(ip) + r"(?!\d)")
    return any(ip_rx.search(ln) and re.search(patron, ln) for ln in (evidencia or "").splitlines())


def _ips_hallazgo(f: dict, por_ip: dict) -> list:
    """Como R1: las IP de `activos` del hallazgo o, si no trae, las de su evidencia."""
    return sorted({ip for ip in (f.get("activos") or _IPV4.findall(f.get("evidencia") or "")) if ip in por_ip})


def _evidencia(assets: dict, hallazgos, d: dict) -> dict:
    """{(clave de activo, tema): {'hallazgos': {titulo: {ids}}, 'servicios': [(nombre, detalle)]}}"""
    from .riesgo import id_hallazgo
    por_ip: dict = collections.defaultdict(list)
    for k, a in assets.items():
        for ip in a["ips"]:
            por_ip[ip].append(k)
    ev: dict = {}

    def celda(k, tema):
        return ev.setdefault((k, tema), {"hallazgos": {}, "servicios": []})
    for f in hallazgos:
        reglas = [r for r in d["titulos"] if r["fragmento"] in f["titulo"]]
        if not reglas:
            continue
        hid = f.get("id") or id_hallazgo(f["titulo"])
        for ip in _ips_hallazgo(f, por_ip):
            for r in reglas:
                if r.get("evidencia") and not _linea_con_ip(f.get("evidencia", ""), ip, r["evidencia"]):
                    continue
                for k in por_ip[ip]:
                    for tema in r["temas"]:
                        celda(k, tema)["hallazgos"].setdefault(f["titulo"], set()).add(hid)
    for k, a in assets.items():
        sv = _servicios(a, d)
        if sv:
            celda(k, d["servicios"]["tema"])["servicios"] = sv
    return ev


def _nombre(a: dict) -> str:
    return a.get("nombre") or next(iter(sorted(a.get("hostnames") or ())), "") or \
        next(iter(sorted(a["ips"])), "") or a.get("mac", "")


def construir(assets: dict, hallazgos, inventario=None) -> dict:
    """{'tipos', 'filas', 'top', 'totales'}; vacio sin activos. Las filas llevan los valores en espanol.
    Con `inventario` (inventario normalizado) cada fila es un activo (una por IP detras de un enrutador)."""
    if inventario and inventario.get("filas"):
        assets = _activos_de_inventario(inventario["filas"])
    if not assets:
        return {}
    d = cargar()
    hallazgos = list(hallazgos)
    por_hallazgo = tipos_por_hallazgo(hallazgos)
    ev = _evidencia(assets, hallazgos, d)
    por_tipo = {c: {"activos": 0, "en_contra": 0, "verificar": 0, "contra": 0} for c in d["tipos"]}
    contra_punto: dict = collections.defaultdict(set)
    filas = []
    orden = sorted(assets, key=lambda k: (sorted(assets[k]["ips"]), assets[k].get("mac", ""), str(k)))
    for k in orden:
        a = assets[k]
        clave, base = tipo_y_base(a, por_hallazgo)
        resumen = por_tipo[clave]
        resumen["activos"] += 1
        con_ev = False
        for p in d["puntos"][clave]:
            e = ev.get((k, p["tema"]))
            if not e:
                resumen["verificar"] += 1
                continue
            con_ev = True
            resumen["contra"] += 1
            contra_punto[p["id"]].add(k)
            ids = sorted({i for v in e["hallazgos"].values() for i in v})
            filas.append({"activo": _nombre(a), "ips": sorted(a["ips"]), "zona": a.get("zona_asignada") or "",
                          "origen_zona": a.get("origen_zona") or "", "rol": a.get("role") or "", "tipo": clave,
                          "base_tipo": base,
                          "id_punto": p["id"], "tema": p["tema"], "estado": ESTADO_REVISAR,
                          "hallazgos": sorted(e["hallazgos"]), "servicios": list(e["servicios"]),
                          "ids_hallazgo": ids})
        resumen["en_contra"] += con_ev
    tipos = [{"clave": c, "activos": r["activos"], "puntos": len(d["puntos"][c]), "en_contra": r["en_contra"],
              "pares_contra": r["contra"], "pares_verificar": r["verificar"]}
             for c, r in por_tipo.items()]
    por_id = {p["id"]: p for ps in d["puntos"].values() for p in ps}
    top = sorted(((pid, len(ks)) for pid, ks in contra_punto.items()), key=lambda x: (-x[1], x[0]))[:MAX_TOP]
    return {"tipos": tipos, "filas": filas,
            "top": [{"id_punto": pid, "tipo": por_id[pid]["tipo"], "activos": n} for pid, n in top],
            "totales": {"activos": len(assets), "contra": sum(x["pares_contra"] for x in tipos),
                        "verificar": sum(x["pares_verificar"] for x in tipos)}}


# --------------------------------------------------------------------------- #
# Salidas
# --------------------------------------------------------------------------- #


def hay(h: dict) -> bool:
    return bool(h) and bool(h.get("tipos")) and any(x["activos"] for x in h["tipos"])


def _punto(pid: str) -> dict:
    return next(p for ps in cargar()["puntos"].values() for p in ps if p["id"] == pid)


def _nombre_tipo(clave: str) -> str:
    return t(cargar()["tipos"][clave]["nombre"])


def filas_base(h: dict) -> list:
    """Lista de verificacion de la visita: solo los tipos que tienen activos; las 5 ultimas columnas, vacias."""
    d = cargar()
    presentes = {x["clave"] for x in h["tipos"] if x["activos"]}
    return [[_nombre_tipo(c), p["id"], t(p["texto"]), "; ".join(p["cr"]), "; ".join(p["sr"]), "", "", "", "", ""]
            for c in d["tipos"] if c in presentes for p in d["puntos"][c]]


def _evidencia_texto(f: dict) -> str:
    piezas = [t("hallazgo: {x}", x=t(x)) for x in f["hallazgos"]]
    piezas += [t("sirve {s} ({d}) segun el inventario", s=s, d=det) if det
               else t("sirve {s} segun el inventario de la plataforma", s=s) for s, det in f["servicios"]]
    return " | ".join(piezas)


def filas_activos(h: dict) -> list:
    out = []
    for f in h["filas"]:
        zona = mostrar_zona(f["zona"], f["origen_zona"]) if f["zona"] else ""
        out.append([f["activo"], ";".join(f["ips"]), zona, mostrar_rol(f["rol"]), _nombre_tipo(f["tipo"]),
                    f["id_punto"], t(_punto(f["id_punto"])["texto"]), t(f["estado"]), _evidencia_texto(f),
                    ";".join(f["ids_hallazgo"]), f["base_tipo"]])
    return out


def tablas(h: dict) -> list:
    """[(archivo, hoja, cabecera, filas)] para el CSV y el XLSX."""
    if not hay(h):
        return []
    return [(ARCHIVO_BASE, HOJA_BASE, COL_BASE, filas_base(h)),
            (ARCHIVO_ACTIVOS, HOJA_ACTIVOS, COL_ACTIVOS, filas_activos(h))]


def resumen_texto(h: dict) -> str:
    x = h["totales"]
    return t("{a} activos, {c} combinaciones activo-punto con evidencia en contra (revisar) y {v} por verificar "
             "en sitio. Los que hay que revisar estan en hardening_activos.csv; la lista de la visita, en "
             "hardening_baseline.csv.", a=x["activos"], c=x["contra"], v=x["verificar"])


def seccion(h: dict) -> dict:
    """Datos de la seccion de los reportes (todo traducido)."""
    tipos = [[_nombre_tipo(x["clave"]), x["activos"], x["puntos"], x["en_contra"], x["pares_verificar"]]
             for x in h["tipos"] if x["activos"]]
    top = [[x["id_punto"], t(_punto(x["id_punto"])["texto"]), _nombre_tipo(x["tipo"]), x["activos"]]
           for x in h["top"]]
    return {"titulo": t(TITULO), "nota": t(NOTA), "resumen": resumen_texto(h),
            "cab_tipos": [t(c) for c in CAB_TIPOS], "tipos": tipos,
            "titulo_top": t("Puntos con mas activos con evidencia en contra"),
            "cab_top": [t(c) for c in CAB_TOP], "top": top,
            "sin_top": t("Ningun punto tiene evidencia en contra en esta corrida; todos quedan por verificar en sitio.")}


def para_json(h: dict) -> dict:
    if not hay(h):
        return {}
    return {"nota": t(NOTA), "totales": h["totales"],
            "tipos": [dict(x, tipo=_nombre_tipo(x["clave"])) for x in h["tipos"]],
            "filas": [dict(zip(COL_ACTIVOS, fila), estado_clave=f["estado"], ids_hallazgo=f["ids_hallazgo"])
                      for fila, f in zip(filas_activos(h), h["filas"])],
            "top": h["top"]}
