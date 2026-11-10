"""T8 (D68): herramientas de acceso remoto de terceros (soporte de proveedores, RMM) vistas en la red.

Evidencia tecnica, no un veredicto: un nombre o un puerto del catalogo indica que alguien intenta usar la
herramienta; no prueba que haya una sesion ni que sea no autorizada. El catalogo vive en
data/acceso_remoto.json (estado 'verificado' o 'sin verificar' por herramienta). Los puertos 80 y 443 nunca
son indicador por si solos. Funciones puras sobre el modelo ya calculado: sin tshark y sin reglas.
Las piezas comunes con T9 viven en indicadores.py (se reexportan aqui con los mismos nombres).
"""
from __future__ import annotations

import json
from pathlib import Path

from .i18n import t
from .indicadores import (  # noqa: F401
    _METODO_SNI,
    A_IT,
    A_OT,
    D_DESCARTADO,
    D_INDETERMINADO,
    D_INTERNET,
    D_INTERNO,
    M_DNS,
    M_EXPORT,
    M_HTTP,
    M_PUERTO,
    M_SNI,
    MAX_DESTINOS,
    PUERTOS_SERVIDOR_MAX,
    SIN_VERIFICAR,
    VERIFICADO,
    _Acum,
    _destino,
    _limpio,
    _mapas_captura,
    _pares_captura,
    _publica,
    ayudas_exportacion,
    coincide_dominio,
    destinos_de_muchos_puertos,
    es_ot,
    orden_ip,
    puertos_por_destino,
)
from .periodicidad import iso

ARCHIVO = "acceso_remoto.csv"
COLUMNAS = ["activo", "ip", "herramienta", "estado_indicador", "metodo", "indicador", "destino", "destino_ip",
            "ambito", "conductos", "bytes", "primera", "ultima", "fuente", "nota"]
DATOS = Path(__file__).resolve().parent / "data" / "acceso_remoto.json"

SOLO_NO = (80, 443)           # nunca son indicador por si solos


def _cargar() -> list:
    return json.loads(DATOS.read_text(encoding="utf-8"))["herramientas"]


CATALOGO = _cargar()


# --------------------------------------------------------------------------- #
# Catalogo
# --------------------------------------------------------------------------- #


def herramienta_de_nombre(nombre: str):
    """Entrada del catalogo cuyo dominio cubre el nombre, o None."""
    for e in CATALOGO:
        if any(coincide_dominio(nombre, d) for d in e["dominios"]):
            return e
    return None


def herramienta_de_puerto(puerto, l4: str = ""):
    """Entrada del catalogo que usa ese puerto (con transporte si se conoce), o None. 80 y 443 nunca."""
    try:
        p = int(puerto)
    except (TypeError, ValueError):
        return None
    if p in SOLO_NO:
        return None
    l4 = str(l4 or "").lower()
    for e in CATALOGO:
        if any(x["puerto"] == p and (not l4 or x["l4"] == l4) for x in e["puertos"]):
            return e
    return None


def puertos_verificados() -> set:
    """Puertos de herramientas con estado 'verificado' (los que se suman a 'acceso remoto' en cruces y rutas)."""
    return {x["puerto"] for e in CATALOGO if e["estado"] == VERIFICADO for x in e["puertos"]}


# --------------------------------------------------------------------------- #
# Capturas
# --------------------------------------------------------------------------- #


def de_captura(cap, muchos=None) -> list:
    """Indicadores de una captura: consultas DNS, SNI/Host y conductos por puerto del catalogo.

    `muchos`: destinos de muchos puertos de toda la entrada; si falta, se calcula con esta captura sola."""
    nivel_de, nombre_de = _mapas_captura(cap)
    if muchos is None:
        muchos = destinos_de_muchos_puertos(puertos_por_destino(_pares_captura(cap)))
    ac = _Acum(cap.name, nivel_de, nombre_de, muchos)
    flows = list(getattr(cap, "flows", {}).values())
    por_par: dict = {}
    for f in flows:
        por_par.setdefault((f["src"], f["dst"]), []).append(f)

    def par(src, dst):
        fs = por_par.get((src, dst), [])
        return ({(f["dst"], f["dport"], f["l4"]) for f in fs}, sum(f["bytes"] for f in fs))

    resueltos: dict = {}
    for e in cap.dns_eventos:
        if e["resp"] and e["rcode"] in ("", "NOERROR"):
            for _dueno, tipo, valor, _ttl in e["respuestas"]:
                if tipo in ("A", "AAAA") and valor:
                    resueltos.setdefault((e["dst"], e["nombre"]), set()).add(valor)
    for e in cap.dns_eventos:
        h = None if e["resp"] else herramienta_de_nombre(e["nombre"])
        if h is None or not e["src"]:
            continue
        ips = resueltos.get((e["src"], e["nombre"]), set())
        cond = set()
        for ip in ips:
            cond |= par(e["src"], ip)[0]
        ac.sumar(e["src"], h, M_DNS, e["nombre"], ips, cond, 0, iso(e["t"]) if e["t"] else "",
                 iso(e["t"]) if e["t"] else "")
    for n in cap.nombres_servidor:
        h = herramienta_de_nombre(n["nombre"])
        if h is None or not n.get("src"):
            continue
        cond, nb = par(n["src"], n["ip"])
        ac.sumar(n["src"], h, _METODO_SNI.get(n["fuente"], M_HTTP), n["nombre"], [n["ip"]], cond, nb,
                 iso(n["t"]) if n.get("t") else "", iso(n["t"]) if n.get("t") else "")
    for f in flows:
        h = herramienta_de_puerto(f["dport"], f["l4"])
        if h is None:
            continue
        ac.sumar(f["src"], h, M_PUERTO, f"{f['l4']}/{f['dport']}", [f["dst"]], [(f["dst"], f["dport"], f["l4"])],
                 f["bytes"], iso(f["first"]) if f["first"] else "", iso(f["last"]) if f["last"] else "")
    return ac.lista()


# --------------------------------------------------------------------------- #
# Exportaciones de plataformas (camino diagrama)
# --------------------------------------------------------------------------- #


def de_exportacion(fuente: str, dominios: list, conductos: list, assets: dict) -> list:
    """Indicadores de una exportacion. `dominios`: [{cliente, servidor, dominio, bytes, fecha}] con ids de activo."""
    ip_de, nivel_de, nombre_de, externo = ayudas_exportacion(assets)
    muchos = destinos_de_muchos_puertos(puertos_por_destino((ip_de(c["dst"]), c.get("port")) for c in conductos))
    ac = _Acum(fuente, nivel_de, nombre_de, muchos)
    for d in dominios:
        h = herramienta_de_nombre(d["dominio"])
        if h is None:
            continue
        srv = ip_de(d["servidor"])
        ac.sumar(ip_de(d["cliente"]), h, M_EXPORT, _limpio(d["dominio"]), [srv], [(srv, "", "")],
                 d.get("bytes", 0), d.get("fecha", ""), d.get("fecha", ""), externo(d["servidor"]))
    for c in conductos:
        h = herramienta_de_puerto(c.get("port"), c.get("l4"))
        if h is None:
            continue
        srv = ip_de(c["dst"])
        ind = f"{c['l4']}/{c['port']}" if c.get("l4") else str(c["port"])
        ac.sumar(ip_de(c["src"]), h, M_PUERTO, ind, [srv], [(srv, c["port"], c.get("l4", ""))],
                 c.get("bytes", 0), c.get("primera", ""), c.get("ultima", ""), externo(c["dst"]))
    return ac.lista()


# --------------------------------------------------------------------------- #
# Salidas
# --------------------------------------------------------------------------- #


def indicadores(res) -> list:
    """Indicadores de todas las capturas del analisis mas los de la exportacion (res.acceso_remoto)."""
    out = []
    caps = [c for c in getattr(res, "caps", ()) if not getattr(c, "error", "")]
    muchos = destinos_de_muchos_puertos(puertos_por_destino(p for c in caps for p in _pares_captura(c)))
    for cap in caps:
        out += de_captura(cap, muchos)
    return out + list(getattr(res, "acceso_remoto", None) or [])


def hay(res) -> bool:
    return bool(indicadores(res))


def fila(x: dict) -> list:
    return [x["activo"], x["ip"], x["herramienta"], t(x["estado"]), t(x["metodo"]), x["indicador"], t(x["destino"]),
            x["destino_ip"], t(x["ambito"]), x["conductos"], x["bytes"], x["primera"], x["ultima"], x["fuente"],
            x.get("nota", "")]


def filas(res) -> list:
    return [fila(x) for x in indicadores(res)]
