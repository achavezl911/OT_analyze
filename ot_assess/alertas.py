"""E2a: alertas y eventos de un IDS o plataforma OT (CSV generico) asociados a conductos y activos.

Funciones puras salvo cargar(). La fecha se guarda como texto (no se parsea). El numero de fila en los
mensajes es el N-esimo registro despues del encabezado. Los totales de resumen() cuentan eventos
(suman 'conteo'), no filas.
"""
from __future__ import annotations

import re
import unicodedata
from pathlib import Path

from .i18n import t
from .importers.lector import leer_csv

MAX_FILAS = 500000

_ALIAS = {
    "fecha": "fecha", "timestamp": "fecha", "time": "fecha", "hora": "fecha",
    "origen": "origen", "src": "origen", "src_ip": "origen", "source": "origen", "source_ip": "origen",
    "destino": "destino", "dst": "destino", "dst_ip": "destino", "destination": "destino",
    "destination_ip": "destino",
    "puerto": "puerto", "port": "puerto", "dst_port": "puerto", "dport": "puerto",
    "protocolo": "protocolo", "protocol": "protocolo", "proto": "protocolo",
    "firma": "firma", "regla": "firma", "alerta": "firma", "signature": "firma", "rule": "firma",
    "name": "firma", "titulo": "firma",
    "severidad": "severidad", "severity": "severidad", "criticidad": "severidad",
    "prioridad": "prioridad", "priority": "prioridad",
    "categoria": "categoria", "category": "categoria",
    "conteo": "conteo", "count": "conteo", "ocurrencias": "conteo",
}
_SEVERIDAD = {
    "critical": "Alta", "critica": "Alta", "high": "Alta", "alta": "Alta",
    "medium": "Media", "media": "Media", "moderate": "Media", "warning": "Media",
    "low": "Baja", "baja": "Baja", "info": "Baja", "informativa": "Baja",
}
_ORDEN_SEV = ("Alta", "Media", "Baja")
_ENTERO = re.compile(r"^\d+$")


def _norm(s) -> str:
    s = unicodedata.normalize("NFD", str(s or ""))
    return "".join(c for c in s if not unicodedata.combining(c)).strip().lower()


def _sev_de_prioridad(p: str):
    if not _ENTERO.match(p) or int(p) < 1:
        return None
    return {1: "Alta", 2: "Media"}.get(int(p), "Baja")


def alertas_de_filas(filas: list, nombre: str) -> list:
    """Convierte los registros de leer_csv en alertas normalizadas. 'nombre' es el archivo, sin ruta."""
    if not filas:
        raise SystemExit(f"[!] '{nombre}': sin filas o sin encabezado")
    if len(filas) > MAX_FILAS:
        raise SystemExit(f"[!] '{nombre}': mas de {MAX_FILAS} filas")
    mapa = {}
    for h in dict.fromkeys(h for f in filas for h in f):    # union de claves: filas cortas omiten celdas
        campo = _ALIAS.get(_norm(h).replace(" ", "_"))
        if campo:
            mapa[h] = campo
    campos = set(mapa.values())
    if "firma" not in campos:
        raise SystemExit(f"[!] '{nombre}': falta la columna requerida 'firma'")
    if not campos & {"origen", "destino"}:
        raise SystemExit(f"[!] '{nombre}': falta la columna origen o destino")
    if not campos & {"severidad", "prioridad"}:
        raise SystemExit(f"[!] '{nombre}': falta la columna severidad o prioridad")
    out = []
    for n, fila in enumerate(filas, 1):
        v: dict = {}
        for h, campo in mapa.items():           # ante columnas repetidas gana la primera con valor
            val = (fila.get(h) or "").strip()
            if val and not v.get(campo):
                v[campo] = val
        if not v.get("firma"):
            raise SystemExit(f"[!] '{nombre}': fila {n}: firma vacia")
        if not (v.get("origen") or v.get("destino")):
            raise SystemExit(f"[!] '{nombre}': fila {n}: sin origen ni destino")
        sev = _SEVERIDAD.get(_norm(v.get("severidad"))) or _sev_de_prioridad(v.get("prioridad", ""))
        if sev is None:
            raise SystemExit(f"[!] '{nombre}': fila {n}: no se pudo determinar la severidad "
                             f"('{v.get('severidad', '')}', prioridad '{v.get('prioridad', '')}')")
        conteo = 1
        if v.get("conteo"):
            if not _ENTERO.match(v["conteo"]) or int(v["conteo"]) < 1:
                raise SystemExit(f"[!] '{nombre}': fila {n}: conteo invalido '{v['conteo']}'")
            conteo = int(v["conteo"])
        puerto = None
        if v.get("puerto"):
            if not _ENTERO.match(v["puerto"]) or int(v["puerto"]) > 65535:
                raise SystemExit(f"[!] '{nombre}': fila {n}: puerto invalido '{v['puerto']}'")
            puerto = int(v["puerto"])
        out.append({
            "fecha": v.get("fecha", ""), "origen": v.get("origen", ""), "destino": v.get("destino", ""),
            "puerto": puerto, "protocolo": v.get("protocolo", ""), "firma": v["firma"],
            "severidad": sev, "categoria": v.get("categoria", ""), "conteo": conteo,
        })
    return out


def cargar(path) -> list:
    p = Path(path)
    try:
        raw = p.read_bytes()
    except OSError as e:
        raise SystemExit(f"[!] No pude leer '{p.name}': {e}")
    return alertas_de_filas(leer_csv(raw), p.name)


def _puerto(x):
    s = str(x if x is not None else "").strip()
    return int(s) if _ENTERO.match(s) else None


def asociar(alertas: list, conductos: list, assets) -> list:
    """Asocia cada alerta a un conducto (par src/dst en cualquier sentido y, si trae puerto, el mismo
    puerto; sin puerto, el primer conducto del par) y a los activos por IP exacta.

    'assets' es {clave: activo} o una lista de activos (clave = su "mac"). Si varios activos comparten
    la IP, gana el de clave menor (determinista).
    """
    items = sorted(assets.items(), key=lambda kv: str(kv[0])) if isinstance(assets, dict) else \
        sorted(((a.get("mac", ""), a) for a in assets), key=lambda kv: str(kv[0]))
    por_ip: dict = {}
    for clave, a in items:
        for ip in a.get("ips") or ():
            por_ip.setdefault(str(ip).strip(), clave)
    ips_de = {str(k): {str(i).strip() for i in a.get("ips") or ()} for k, a in items}

    def ids(x):             # un extremo de conducto: su valor y, si es clave de activo, sus IPs
        x = str(x or "").strip()
        return {x} | ips_de.get(x, set())
    out = []
    for al in alertas:
        o, d, p = al["origen"].strip(), al["destino"].strip(), al["puerto"]
        idx = None
        if o and d:
            for i, c in enumerate(conductos):
                s, t = ids(c.get("src")), ids(c.get("dst"))
                if not ((o in s and d in t) or (o in t and d in s)):
                    continue
                if p is None or _puerto(c.get("port")) == p:
                    idx = i
                    break
        out.append({"alerta": al, "conducto": idx,
                    "activo_origen": por_ip.get(o), "activo_destino": por_ip.get(d)})
    return out


def resumen(asociadas: list) -> dict:
    """Totales por eventos: total, por severidad, sin conducto y las 10 firmas de mayor conteo."""
    por_sev = {s: 0 for s in _ORDEN_SEV}
    firmas: dict = {}
    sin = total = 0
    for a in asociadas:
        al = a["alerta"]
        total += al["conteo"]
        por_sev[al["severidad"]] += al["conteo"]
        firmas[al["firma"]] = firmas.get(al["firma"], 0) + al["conteo"]
        if a["conducto"] is None:
            sin += al["conteo"]
    top = sorted(firmas.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
    return {"total": total, "por_severidad": por_sev, "sin_conducto": sin, "firmas": top}


NOTA = "Datos del archivo importado; la herramienta no valida las firmas ni descarta falsos positivos."
TITULO = "Alertas de seguridad registradas por la plataforma (segun el archivo importado)"
COLUMNAS = ["fecha", "origen", "destino", "puerto", "protocolo", "firma", "severidad", "categoria",
            "conteo", "conducto_observado", "activo_origen", "activo_destino"]


def _pares(asociadas: list) -> list:
    """Los 10 pares origen -> destino con mas eventos: [(origen, destino, conteo)]."""
    pares: dict = {}
    for a in asociadas:
        al = a["alerta"]
        k = (al["origen"], al["destino"])
        pares[k] = pares.get(k, 0) + al["conteo"]
    return [(o, d, n) for (o, d), n in sorted(pares.items(), key=lambda kv: (-kv[1], kv[0]))[:10]]


def resumen_completo(asociadas: list, archivo: str) -> dict:
    """resumen() mas el nombre del archivo y los pares con mas alertas; es lo que van a las salidas."""
    r = resumen(asociadas)
    r["archivo"] = archivo
    r["pares"] = [list(p) for p in _pares(asociadas)]
    return r


def intro(r: dict) -> str:
    return t("{archivo}: {total} alertas, {sin} sin conducto observado. Detalle en alertas.csv.",
             archivo=r["archivo"], total=r["total"], sin=r["sin_conducto"])


def tablas_resumen(r: dict) -> list:
    """[(cabecera, filas)] de severidad y de firmas principales, para HTML, Word y Markdown."""
    return [([t("Severidad"), t("Alertas")], [[t(s), n] for s, n in r["por_severidad"].items()]),
            ([t("Firma principal"), t("Alertas")], [[f, n] for f, n in r["firmas"]])]


def _ips_asociadas(asociadas: list, assets) -> list:
    """IP de los activos asociados a las alertas ('assets' como en asociar)."""
    if not assets:
        return []
    if not isinstance(assets, dict):
        assets = {a.get("mac", ""): a for a in assets}
    claves = {k for x in asociadas for k in (x.get("activo_origen"), x.get("activo_destino")) if k is not None}
    return [str(ip) for k in claves for ip in (assets.get(k) or {}).get("ips") or ()]


def agregar_hallazgo(cap, asociadas: list, assets=None) -> None:
    """Un hallazgo en 'cap' si hay al menos una alerta."""
    from .rules.base import finding

    if not asociadas:
        return
    r = resumen(asociadas)
    sev = min((a["alerta"]["severidad"] for a in asociadas), key=_ORDEN_SEV.index)
    ev = t("Total {total} alertas ({sevs}). Firmas principales: {firmas}. Pares con mas alertas: "
           "{pares}. Alertas sin conducto observado: {sin}", total=r["total"],
           sevs=", ".join(f"{t(s)} {n}" for s, n in r["por_severidad"].items()),
           firmas="; ".join(f"{f} ({n})" for f, n in r["firmas"]),
           pares="; ".join(f"{o or '?'} -> {d or '?'} ({n})" for o, d, n in _pares(asociadas)),
           sin=r["sin_conducto"])
    finding(cap, sev, TITULO, ev,
            "Las alertas de un sensor son evidencia directa de actividad potencialmente adversa en "
            "conductos concretos; las que no tienen trafico observado senalan huecos de visibilidad.",
            "Investigar las alertas de mayor severidad con el equipo de operacion, descartar falsos "
            "positivos y ajustar firmas y segmentacion segun lo confirmado.", "Deteccion",
            activos=_ips_asociadas(asociadas, assets))


def filas_tabla(asociadas: list, assets) -> list:
    """Filas de alertas.csv en el orden del archivo importado."""
    mapa = assets if isinstance(assets, dict) else {a.get("mac", ""): a for a in assets}

    def nom(k):
        a = mapa.get(k) if k is not None else None
        return (a.get("nombre") or "") if a else ""
    out = []
    for x in asociadas:
        al = x["alerta"]
        out.append([al["fecha"], al["origen"], al["destino"], "" if al["puerto"] is None else al["puerto"],
                    al["protocolo"], al["firma"], t(al["severidad"]), al["categoria"], al["conteo"],
                    t("si") if x["conducto"] is not None else t("no"),
                    nom(x["activo_origen"]), nom(x["activo_destino"])])
    return out
