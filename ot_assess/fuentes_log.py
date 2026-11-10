"""G1a (D87): inventario de fuentes de log y arquitectura de registro observada.

Parte de los conductos (capturas y plataformas): un conducto hacia un puerto o aplicacion de registro (Syslog, traps
SNMP, NetFlow, reenvio de eventos de Windows, agentes de SIEM) es un envio observado; el origen es el emisor y el
destino el colector. Por activo del inventario normalizado dice si envia, si es colector o si no se vio envio, y
cuando el tipo de equipo (T1b) suele enviar lo marca "verificar". La ausencia en la captura no prueba que no envie.
No lee la configuracion de registro de los equipos, no genera hallazgos y nunca concluye cumplimiento.
Solo lee el modelo ya calculado. Datos en data/fuentes_log.json.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from . import conductos_zcr as _zc
from . import hardening as _hd
from .firewalls import cruces as _cr
from .i18n import t
from .zonas import mostrar_zona

RUTA = Path(__file__).parent / "data" / "fuentes_log.json"
TITULO = "Fuentes de log (arquitectura de registro observada)"
HOJA_FUENTES = "Fuentes de log"
HOJA_COLECTORES = "Colectores de log"
ARCHIVO_FUENTES = "fuentes_log.csv"
ARCHIVO_COLECTORES = "colectores_log.csv"
COL_FUENTES = ["activo", "ip", "zona", "tipo", "expectativa", "fuente_esperada", "estado", "protocolos",
               "colectores", "cifrado", "estado_revision", "revisado_por", "fecha", "comentario"]
COL_COLECTORES = ["colector", "ip", "zona", "protocolos", "emisores", "zonas_emisoras", "cifrado"]
CAB_TIPOS = ["Tipo de equipo", "Activos", "Envian registros", "Sin envio observado"]
CAB_COLECTORES = ["Colector", "IP", "Zona", "Protocolos", "Emisores", "Zonas emisoras", "Cifrado"]
MAX_COLECTORES = 20

E_ENVIA = "envia (observado)"
E_COLECTOR = "colector"
E_VERIFICAR = "sin envio observado: verificar"
E_OPCIONAL = "sin envio observado (opcional para el tipo)"
ORDEN_ESTADO = [E_VERIFICAR, E_ENVIA, E_COLECTOR, E_OPCIONAL]
EXP_ESPERADA = "esperada"
EXP_OPCIONAL = "opcional"

NOTA = ("Inventario de fuentes de registro segun los conductos observados: un conducto hacia un puerto o una "
        "aplicacion de registro (tabla en data/fuentes_log.json) cuenta como envio; el origen es el emisor y el "
        "destino, el colector, y las respuestas no cuentan. 'Sin envio observado: verificar' es un equipo que por su "
        "tipo suele enviar registros y no se vio que lo haga; la ausencia en la captura no prueba que no envie "
        "(ventana de captura, cobertura del SPAN, envio por otra interfaz). Para confirmarlo use las preguntas de "
        "servicios esperados (esperados_no_observados.csv y preguntas_cliente.csv). La columna cifrado solo informa "
        "si el protocolo va en claro; no es un hallazgo. La herramienta no lee la configuracion de registro de los "
        "equipos y no concluye cumplimiento.")
TEXTO_VACIO = "No se observo envio de registros en la corrida."


@lru_cache(maxsize=1)
def cargar() -> dict:
    return json.loads(RUTA.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _indices() -> tuple:
    d = cargar()
    por_clave = {p["clave"]: p for p in d["protocolos"]}
    por_puerto = {}
    for p in d["protocolos"]:
        for pt in p["puertos"]:
            por_puerto[pt] = p["clave"]
    return por_clave, por_puerto


def _protocolo_puerto(puerto, l4: str):
    return _indices()[1].get(f"{puerto}/{l4}") if puerto is not None else None


def _protocolo_app(app: str):
    app = (app or "").lower()
    if not app:
        return None
    for p in cargar()["protocolos"]:
        if any(a in app for a in p["apps"]):
            return p["clave"]
    return None


def _nombre_protocolo(clave: str) -> str:
    return t(_indices()[0][clave]["nombre"])


def _cifrado_texto(valores) -> str:
    """'no', 'si' o 'depende de la configuracion' por protocolo, sin repetir, en ese orden."""
    cifra = {_indices()[0][c]["cifrado"] for c in valores}
    return "; ".join(t(x) for x, v in (("no", False), ("si", True), ("depende de la configuracion", None))
                     if v in cifra)


def _envios(conductos: list, ip_de, firewall) -> list:
    """[(emisor, colector, clave de protocolo)] sin repetir; las respuestas no cuentan."""
    fw = firewall or {}
    res_fw = fw.get("resultados") or []
    con_fw = "hostname" in fw and len(res_fw) == len(conductos)
    vistos, por_app = [], []
    pares_puerto = set()
    for i, c in enumerate(conductos):
        r = res_fw[i] if con_fw else {}
        if r.get("resultado") == "respuesta":
            continue
        s, d = str(ip_de(c.get("src"))), str(ip_de(c.get("dst")))
        if r.get("sentido") == "invertido":
            s, d = d, s
        l4 = str(c.get("l4") or "").strip().lower()
        puerto = _cr._puerto(c)
        clave = _protocolo_puerto(puerto, l4)
        if clave:
            vistos.append((s, d, clave))
            pares_puerto.add((s, d))
            continue
        servicio = str(c.get("servicio") or "")
        clave = _protocolo_app("" if servicio == "-" else servicio)
        if clave:
            por_app.append((s, d, clave))
    for s, d, clave in por_app:
        if (d, s) in pares_puerto:       # el puerto de servidor va en sentido contrario: es la respuesta
            continue
        vistos.append((s, d, clave))
    return sorted(set(vistos))


def construir(assets: dict, conductos: list, hallazgos=(), inventario=None, firewall=None) -> dict:
    """{'filas', 'colectores', 'tipos', 'totales'}; vacio sin activos. Con `inventario` (inventario normalizado)
    cada fila es un activo (una por IP detras de un enrutador); sin el, `assets`."""
    if inventario and inventario.get("filas"):
        activos = _hd._activos_de_inventario(inventario["filas"])
    else:
        activos = assets
    if not activos:
        return {}
    d = cargar()
    por_hallazgo = _hd.tipos_por_hallazgo(list(hallazgos))
    envios = _envios(conductos or [], _zc._ip_de(assets), firewall)
    clave_de_ip: dict = {}
    for k, a in activos.items():
        for ip in a["ips"]:
            clave_de_ip.setdefault(ip, k)

    def nombre(ip):
        k = clave_de_ip.get(ip)
        return _hd._nombre(activos[k]) if k is not None else ip

    def zona(ip):
        k = clave_de_ip.get(ip)
        a = activos.get(k) if k is not None else None
        if not a or not a.get("zona_asignada"):
            return ""
        return mostrar_zona(a["zona_asignada"], a.get("origen_zona") or "")

    envia: dict = {}          # clave de activo -> {protocolo: {IP de colector}}
    recibe: dict = {}         # IP de colector -> {protocolo: {IP de emisor}}
    for s, c, clave in envios:
        if s in clave_de_ip:
            envia.setdefault(clave_de_ip[s], {}).setdefault(clave, set()).add(c)
        recibe.setdefault(c, {}).setdefault(clave, set()).add(s)
    filas = []
    for k, a in activos.items():
        tipo, _base = _hd.tipo_y_base(a, por_hallazgo)
        exp = d["tipos"][tipo]
        mio = envia.get(k, {})
        recibido: dict = {}
        for ip in a["ips"]:
            for clave, ems in recibe.get(ip, {}).items():
                recibido.setdefault(clave, set()).update(ems)
        emisores = sorted({e for ems in recibido.values() for e in ems})
        if emisores:
            estado = E_COLECTOR
        elif mio:
            estado = E_ENVIA
        else:
            estado = E_VERIFICAR if exp["expectativa"] == EXP_ESPERADA else E_OPCIONAL
        filas.append({"activo": _hd._nombre(a), "ips": sorted(a["ips"]), "zona_clave": a.get("zona_asignada") or "",
                      "origen_zona": a.get("origen_zona") or "", "tipo": tipo, "expectativa": exp["expectativa"],
                      "fuente_esperada": exp["fuente_esperada"], "estado": estado,
                      "protocolos": sorted(mio), "recibe": sorted(recibido),
                      "colectores": sorted({nombre(c) for cs in mio.values() for c in cs}),
                      "emisores": emisores, "zona": zona(min(a["ips"])) if a["ips"] else ""})
    filas.sort(key=lambda f: (ORDEN_ESTADO.index(f["estado"]), f["zona"], _cr._orden_ip(f["ips"][0] if f["ips"] else "")))
    colectores = []
    for ip, protos in recibe.items():
        ems = sorted({e for v in protos.values() for e in v})
        colectores.append({"colector": nombre(ip), "ip": ip, "zona": zona(ip), "protocolos": sorted(protos),
                           "emisores": len(ems),
                           "zonas_emisoras": sorted({zona(e) for e in ems if zona(e)})})
    colectores.sort(key=lambda x: (-x["emisores"], _cr._orden_ip(x["ip"])))
    tipos = []
    for clave in d["tipos"]:
        fs = [f for f in filas if f["tipo"] == clave]
        envian = sum(1 for f in fs if f["protocolos"])
        tipos.append({"clave": clave, "activos": len(fs), "envian": envian, "sin_envio": len(fs) - envian,
                      "verificar": sum(1 for f in fs if f["estado"] == E_VERIFICAR)})
    return {"filas": filas, "colectores": colectores, "tipos": tipos,
            "totales": {"activos": len(filas), "envios": len(envios),
                        "envian": sum(1 for f in filas if f["protocolos"]),
                        "colectores": sum(1 for f in filas if f["estado"] == E_COLECTOR),
                        "verificar": sum(1 for f in filas if f["estado"] == E_VERIFICAR),
                        "opcional": sum(1 for f in filas if f["estado"] == E_OPCIONAL)}}


# --------------------------------------------------------------------------- #
# Salidas
# --------------------------------------------------------------------------- #


def hay(f: dict) -> bool:
    return bool(f) and bool(f.get("filas"))


def _nombre_tipo(clave: str) -> str:
    return _hd._nombre_tipo(clave)


def _protocolos_texto(f: dict) -> str:
    env = "; ".join(_nombre_protocolo(c) for c in f["protocolos"])
    if f["estado"] != E_COLECTOR:
        return env
    rec = t("recibe: {p}", p="; ".join(_nombre_protocolo(c) for c in f["recibe"]))
    return rec + (" | " + t("envia: {p}", p=env) if env else "")


def filas_fuentes(f: dict) -> list:
    out = []
    for x in f["filas"]:
        usados = x["protocolos"] if x["protocolos"] else x["recibe"]
        out.append([x["activo"], ";".join(x["ips"]), x["zona"], _nombre_tipo(x["tipo"]), t(x["expectativa"]),
                    t(x["fuente_esperada"]), t(x["estado"]), _protocolos_texto(x), "; ".join(x["colectores"]),
                    _cifrado_texto(usados), "", "", "", ""])
    return out


def filas_colectores(f: dict) -> list:
    return [[x["colector"], x["ip"], x["zona"], "; ".join(_nombre_protocolo(c) for c in x["protocolos"]),
             x["emisores"], "; ".join(x["zonas_emisoras"]), _cifrado_texto(x["protocolos"])]
            for x in f["colectores"]]


def tablas(f: dict) -> list:
    """[(archivo, hoja, cabecera, filas)]; el de colectores solo si hubo envios."""
    if not hay(f):
        return []
    out = [(ARCHIVO_FUENTES, HOJA_FUENTES, COL_FUENTES, filas_fuentes(f))]
    if f["colectores"]:
        out.append((ARCHIVO_COLECTORES, HOJA_COLECTORES, COL_COLECTORES, filas_colectores(f)))
    return out


def resumen_texto(f: dict) -> str:
    x = f["totales"]
    return t("{a} activos: {e} envian registros, {c} son colectores, {v} sin envio observado por verificar y {o} "
             "sin envio observado (opcional para el tipo). Detalle en fuentes_log.csv.",
             a=x["activos"], e=x["envian"], c=x["colectores"], v=x["verificar"], o=x["opcional"])


def seccion(f: dict) -> dict:
    """Datos de la seccion de los reportes (todo traducido)."""
    tipos = [[_nombre_tipo(x["clave"]), x["activos"], x["envian"], x["sin_envio"]] for x in f["tipos"] if x["activos"]]
    cols = filas_colectores(f)[:MAX_COLECTORES]
    mas = len(f["colectores"]) - len(cols)
    return {"titulo": t(TITULO), "nota": t(NOTA), "resumen": resumen_texto(f),
            "cab_tipos": [t(c) for c in CAB_TIPOS], "tipos": tipos,
            "cab_colectores": [t(c) for c in CAB_COLECTORES], "colectores": cols,
            "mas": t("Se muestran {n} colectores; {m} mas estan en colectores_log.csv.", n=len(cols), m=mas)
            if mas > 0 else "",
            "vacio": "" if f["colectores"] else t(TEXTO_VACIO)}


def para_json(f: dict) -> dict:
    if not hay(f):
        return {}
    return {"nota": t(NOTA), "totales": f["totales"],
            "tipos": [dict(x, tipo=_nombre_tipo(x["clave"])) for x in f["tipos"]],
            "filas": [dict(zip(COL_FUENTES[:10], fila), estado_clave=x["estado"], protocolos_clave=x["protocolos"],
                           recibe=x["recibe"], emisores=x["emisores"])
                      for fila, x in zip(filas_fuentes(f), f["filas"])],
            "colectores": [dict(zip(COL_COLECTORES, fila), protocolos_clave=x["protocolos"])
                           for fila, x in zip(filas_colectores(f), f["colectores"])]}
